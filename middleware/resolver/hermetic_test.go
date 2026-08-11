package resolver

import (
	"crypto"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
)

// A signed DNS namespace served from loopback, so that resolution — including
// DNSSEC validation from a trust anchor down to an answer — can be tested
// without reaching the internet.
//
// Three things about it are forced rather than chosen:
//
//   - The root must delegate, not answer. If the root replies authoritatively
//     for a name, the resolver has no zone cut to descend through, never
//     establishes a signer, and returns the data unvalidated. Only a referral
//     makes validation happen at all.
//   - Each zone needs its own socket. The root and the child are asked the
//     same question — one to delegate it, the other to answer it — and a
//     single socket could not tell those apart.
//   - A child's address is seeded into the delegation cache rather than
//     carried as glue. Glue is an A/AAAA record, so its address always means
//     port 53, which a test cannot bind. The DS still travels in the referral
//     and is still validated against the parent, so seeding supplies the
//     address only — never the trust.

type hermeticKey struct {
	key  *dns.DNSKEY
	priv crypto.PrivateKey
}

func newHermeticKey(tb testing.TB, zone string) hermeticKey {
	tb.Helper()

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		tb.Fatalf("generate %s DNSKEY: %v", zone, err)
	}
	return hermeticKey{key: key, priv: priv}
}

func (k hermeticKey) sign(tb testing.TB, rrset []dns.RR) *dns.RRSIG {
	tb.Helper()

	hdr := rrset[0].Header()
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: hdr.Class, Ttl: hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   k.key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)), //nolint:gosec // fixture names have few labels
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(now.Add(6 * time.Hour).Unix()),  //nolint:gosec // RFC 4034 serial time
		Inception:   uint32(now.Add(-6 * time.Hour).Unix()), //nolint:gosec // RFC 4034 serial time
		KeyTag:      k.key.KeyTag(),
		SignerName:  k.key.Header().Name,
	}
	signer, ok := k.priv.(crypto.Signer)
	if !ok {
		tb.Fatalf("generated key %T is not a crypto.Signer", k.priv)
	}
	if err := sig.Sign(signer, rrset); err != nil {
		tb.Fatalf("sign %s %s: %v", hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}
	return sig
}

type hermeticRRSetKey struct {
	name  string
	qtype uint16
}

// hermeticServer is one authoritative socket: the root, or one zone.
type hermeticServer struct {
	mu       sync.Mutex
	label    string
	records  map[hermeticRRSetKey][]dns.RR
	names    map[string]bool     // every name this server holds any type for
	children map[string][]dns.RR // referral records, by delegated zone
	queries  map[hermeticRRSetKey]int
	// silent drops queries instead of answering, which is what a dead
	// authority looks like from the resolver's side.
	silent bool

	addr string
	stop func()
}

func startHermeticServer(tb testing.TB, label string) *hermeticServer {
	tb.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen udp: %v", err)
	}

	s := &hermeticServer{
		label:    label,
		records:  make(map[hermeticRRSetKey][]dns.RR),
		names:    make(map[string]bool),
		children: make(map[string][]dns.RR),
		queries:  make(map[hermeticRRSetKey]int),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) != 1 {
			return
		}
		q := r.Question[0]

		s.mu.Lock()
		if s.silent {
			s.mu.Unlock()
			return
		}
		s.queries[hermeticRRSetKey{q.Name, q.Qtype}]++
		rrs, known := s.records[hermeticRRSetKey{q.Name, q.Qtype}]
		nameExists := s.names[q.Name]
		var referral []dns.RR
		for zone, records := range s.children {
			if q.Name != zone && dns.IsSubDomain(zone, q.Name) {
				referral = records
				break
			}
		}
		s.mu.Unlock()

		reply := new(dns.Msg)
		reply.SetReply(r)
		switch {
		case known:
			reply.Authoritative = true
			reply.Answer = append(reply.Answer, rrs...)
		case referral != nil:
			reply.Authoritative = false
			reply.Ns = append(reply.Ns, referral...)
		case nameExists:
			// The name is there, this type is not: NODATA, not NXDOMAIN.
			reply.Authoritative = true
		default:
			reply.Authoritative = true
			reply.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(reply)
	})

	server := &dns.Server{Net: "udp", PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	time.Sleep(10 * time.Millisecond)

	s.addr = pc.LocalAddr().String()
	s.stop = func() { _ = server.Shutdown() }
	tb.Cleanup(s.stop)
	return s
}

func (s *hermeticServer) serve(name string, qtype uint16, rrs ...dns.RR) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[hermeticRRSetKey{dns.Fqdn(name), qtype}] = rrs
	s.names[dns.Fqdn(name)] = true
}

// silence makes the server stop answering, so the resolver sees an authority
// that is reachable but never replies.
func (s *hermeticServer) silence() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.silent = true
}

func (s *hermeticServer) asked(name string, qtype uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[hermeticRRSetKey{dns.Fqdn(name), qtype}]
}

// hermeticZone is one delegated zone within the namespace.
type hermeticZone struct {
	tb     testing.TB
	name   string
	key    hermeticKey
	server *hermeticServer
	signed bool
	// ds is exactly what the parent published, so the delegation seeding
	// cannot hand the resolver a different — and in a broken-chain fixture,
	// a working — trust path than the referral does.
	ds []dns.RR
}

// Serve publishes an RRset and, in a signed zone, its signature.
func (z *hermeticZone) Serve(rrs ...dns.RR) {
	z.tb.Helper()
	if len(rrs) == 0 {
		z.tb.Fatal("Serve needs at least one record")
	}
	hdr := rrs[0].Header()
	set := rrs
	if z.signed {
		set = append(append([]dns.RR{}, rrs...), z.key.sign(z.tb, rrs))
	}
	z.server.serve(hdr.Name, hdr.Rrtype, set...)
}

// ServeUnsigned publishes an RRset without its signature. In a signed zone
// that is a bogus answer, which a validating resolver must refuse — the case
// a live "missing signatures" probe used to cover.
func (z *hermeticZone) ServeUnsigned(rrs ...dns.RR) {
	z.tb.Helper()
	if len(rrs) == 0 {
		z.tb.Fatal("ServeUnsigned needs at least one record")
	}
	hdr := rrs[0].Header()
	z.server.serve(hdr.Name, hdr.Rrtype, rrs...)
}

func (z *hermeticZone) asked(name string, qtype uint16) int {
	return z.server.asked(name, qtype)
}

// Silence stops the zone answering anything further.
func (z *hermeticZone) Silence() { z.server.silence() }

// hermeticNet is the namespace: a signed root plus the zones it delegates to.
type hermeticNet struct {
	tb      testing.TB
	rootKey hermeticKey
	root    *hermeticServer
	zones   []*hermeticZone
}

func newHermeticNet(tb testing.TB) *hermeticNet {
	tb.Helper()

	n := &hermeticNet{
		tb:      tb,
		rootKey: newHermeticKey(tb, "."),
		root:    startHermeticServer(tb, "root"),
	}

	n.root.serve(".", dns.TypeDNSKEY,
		n.rootKey.key, n.rootKey.sign(tb, []dns.RR{n.rootKey.key}))

	// Answered without addresses on purpose: priming keeps the configured
	// root server when it finds no A/AAAA, which is what this fixture wants.
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns.root.",
	}
	n.root.serve(".", dns.TypeNS, ns, n.rootKey.sign(tb, []dns.RR{ns}))

	return n
}

// Delegate creates a signed child zone: the root publishes and signs its DS,
// so an answer from it validates all the way to the anchor.
func (n *hermeticNet) Delegate(zone string) *hermeticZone {
	return n.delegate(zone, true, true, false)
}

// DelegateInsecure creates a child zone with no DS at the cut. The resolver
// must accept its unsigned answers rather than demand signatures.
func (n *hermeticNet) DelegateInsecure(zone string) *hermeticZone {
	return n.delegate(zone, false, false, false)
}

// DelegateWrongDS creates a signed child whose DS at the parent describes a
// key the child does not hold. The chain is broken at the cut rather than at
// the answer, which a validator must also refuse.
func (n *hermeticNet) DelegateWrongDS(zone string) *hermeticZone {
	return n.delegate(zone, true, true, true)
}

func (n *hermeticNet) delegate(zone string, signed, publishDS, wrongDS bool) *hermeticZone {
	n.tb.Helper()
	zone = dns.Fqdn(zone)

	z := &hermeticZone{
		tb:     n.tb,
		name:   zone,
		key:    newHermeticKey(n.tb, zone),
		server: startHermeticServer(n.tb, zone),
		signed: signed,
	}

	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns." + zone,
	}
	referral := []dns.RR{ns}

	if publishDS {
		dsKey := z.key
		if wrongDS {
			dsKey = newHermeticKey(n.tb, zone)
		}
		ds := dsKey.key.ToDS(dns.SHA256)
		dsSig := n.rootKey.sign(n.tb, []dns.RR{ds})
		n.root.serve(zone, dns.TypeDS, ds, dsSig)
		referral = append(referral, ds, dsSig)
		z.ds = []dns.RR{ds}
	}
	if signed {
		z.Serve(z.key.key)
	}

	n.root.mu.Lock()
	n.root.children[zone] = referral
	n.root.mu.Unlock()

	n.zones = append(n.zones, z)
	return z
}

// Config returns a resolver configuration anchored on this namespace's root.
func (n *hermeticNet) Config() *config.Config {
	cfg := makeTestConfig()
	cfg.RootServers = []string{n.root.addr}
	cfg.Root6Servers = nil
	cfg.IPv6Access = false
	cfg.DNSSEC = "on"
	cfg.RootKeys = []string{n.rootKey.key.String()}
	return cfg
}

// Resolver returns the resolver behind Handler, for tests that care about
// the error a resolution failed with rather than the response it produced.
func (n *hermeticNet) Resolver() *Resolver {
	return n.Handler().resolver
}

// Handler returns a resolver wired to this namespace, with each zone's
// address seeded into the delegation cache.
func (n *hermeticNet) Handler() *DNSHandler {
	return n.handlerWithConfig(n.Config())
}

// handlerWithConfig is Handler for a caller that adjusted the configuration
// first — qname minimisation, for one.
func (n *hermeticNet) handlerWithConfig(cfg *config.Config) *DNSHandler {
	n.tb.Helper()

	handler := New(cfg)
	for _, z := range n.zones {
		servers := &authority.Servers{
			Zone: z.name,
			List: []*authority.Server{authority.NewServer(z.server.addr, authority.IPv4)},
		}
		// The delegation key carries the request's CD bit, so both spellings
		// are seeded — a test that disables checking still finds the zone.
		question := dns.Question{Name: z.name, Qtype: dns.TypeNS, Qclass: dns.ClassINET}
		handler.resolver.delegations.Set(cache.Key(question, false), z.ds, servers, time.Hour)
		handler.resolver.delegations.Set(cache.Key(question, true), z.ds, servers, time.Hour)
	}
	return handler
}
