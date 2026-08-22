package resolver

import (
	"context"
	"crypto"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
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
//   - Glue is remapped rather than seeded. A glue address always means port
//     53, which a test cannot bind, so zones advertise TEST-NET-1 addresses
//     and the resolver is told to dial the loopback socket serving each one.
//     Seeding the delegation cache instead would hand the resolver a child
//     it already knows, and the referral — with the DS inside it — would
//     never be processed or checked against the parent.
//   - Denials carry proof. A signed zone answers NODATA and NXDOMAIN with a
//     signed SOA and an NSEC, because a validator cannot tell a denial from
//     a stripped answer without one, and correctly refuses.

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

// nextInZone names something that sorts after everything else the fixture
// publishes under owner, and still lies inside it. An NSEC whose interval
// leaves its own zone is discarded before it is ever examined, since it says
// nothing about that zone's contents — and the root is its own suffix, so
// the obvious spelling would produce a doubled dot.
func nextInZone(owner string) string {
	if owner == "." {
		return "zz-last."
	}
	return "zz-last." + dns.Fqdn(owner)
}

// emptyNonTerminals lists the names strictly between the root and zone.
// They hold no records of their own, but they exist: a query for one is
// NODATA, never a denial of the whole subtree below it.
func emptyNonTerminals(zone string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(zone))
	ents := make([]string, 0, len(labels))
	for i := 1; i < len(labels); i++ {
		ents = append(ents, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return ents
}

// hermeticReferral is what a parent hands back for a name below a zone cut:
// the child's nameserver, its address as glue, and — when the child is
// signed — the DS that makes it verifiable.
type hermeticReferral struct {
	zone  string
	ns    []dns.RR
	extra []dns.RR
}

// hermeticServer is one authoritative socket: the root, or one zone.
type hermeticServer struct {
	mu       sync.Mutex
	label    string
	records  map[hermeticRRSetKey][]dns.RR
	names    map[string]bool              // every name this server holds any type for
	children map[string]*hermeticReferral // referral, by delegated zone
	// proofs are the authority-section records a negative answer carries:
	// the zone's SOA and an NSEC denying the queried type. Without them a
	// validating resolver cannot tell "does not exist" from "was stripped",
	// and must refuse — so a signed zone has to supply them.
	proofs   map[hermeticRRSetKey][]dns.RR
	soaProof []dns.RR
	// nxProof is the NSEC a denial carries. One record spanning the whole
	// zone covers every absent name in these fixtures, and the wildcard
	// with them, which is all a denial needs to be verifiable here.
	nxProof []dns.RR
	// nodataProof is the NSEC for a name that exists without the queried
	// type. It lists exactly the types the name does hold, so it is rebuilt
	// whenever one is published.
	nodataProof map[string][]dns.RR
	key         *hermeticKey
	tb          testing.TB
	// zoneName, and the NSEC3 parameters when the zone uses hashed denial,
	// are needed to name a proof record: an NSEC3's owner is the hash of
	// the name it speaks for, placed under the zone.
	zoneName   string
	nsec3      bool
	nsec3Salt  string
	nsec3Iters uint16
	// nsec3Flags carries the Opt-Out bit. A span marked Opt-Out may hide an
	// unsigned delegation, so a denial resting on one proves less than it
	// appears to (RFC 5155 §6).
	nsec3Flags uint8
	queries    map[hermeticRRSetKey]int
	// silent drops queries instead of answering, which is what a dead
	// authority looks like from the resolver's side.
	silent bool
	// beforeReply, when set, runs before this server answers. It lets a
	// test hold one server's reply until something else has happened —
	// the only way to observe whether two servers were asked at once.
	beforeReply func(dns.Question)

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
		label:       label,
		records:     make(map[hermeticRRSetKey][]dns.RR),
		names:       make(map[string]bool),
		children:    make(map[string]*hermeticReferral),
		proofs:      make(map[hermeticRRSetKey][]dns.RR),
		nodataProof: make(map[string][]dns.RR),
		queries:     make(map[hermeticRRSetKey]int),
		tb:          tb,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) != 1 {
			return
		}
		q := r.Question[0]

		s.mu.Lock()
		// Count first: a silent server still received the query, and
		// whether it did is exactly what tells a fan-out from one server
		// answering on its own.
		s.queries[hermeticRRSetKey{q.Name, q.Qtype}]++
		if s.silent {
			s.mu.Unlock()
			return
		}
		rrs, known := s.records[hermeticRRSetKey{q.Name, q.Qtype}]
		nameExists := s.names[q.Name]
		proof := s.proofs[hermeticRRSetKey{q.Name, q.Qtype}]
		soaProof := s.soaProof
		nxProof := s.nxProof
		nodataProof := s.nodataProof[q.Name]
		// The zone cut itself is below the cut too: a query for the child's
		// apex belongs to the child, not the parent. Only the records the
		// parent genuinely holds there — the DS — are answered here, and the
		// switch below reaches those first.
		var referral *hermeticReferral
		for zone, delegation := range s.children {
			if dns.IsSubDomain(zone, q.Name) {
				referral = delegation
				break
			}
		}
		beforeReply := s.beforeReply
		s.mu.Unlock()

		if beforeReply != nil {
			beforeReply(q)
		}

		reply := new(dns.Msg)
		reply.SetReply(r)
		switch {
		case known:
			reply.Authoritative = true
			reply.Answer = append(reply.Answer, rrs...)
		case proof != nil:
			// A fact the parent holds about the cut — that there is no DS
			// here, say. It has to be answered rather than referred, or the
			// denial the child cannot make for itself never gets made.
			reply.Authoritative = true
			reply.Ns = append(reply.Ns, soaProof...)
			reply.Ns = append(reply.Ns, proof...)
		case referral != nil:
			// A referral names the child's servers and carries their
			// addresses as glue, which is how the resolver reaches them —
			// and carries the DS, which is what makes the next zone
			// verifiable. Both have to travel on the wire for the
			// delegation to be processed and validated at all.
			reply.Authoritative = false
			reply.Ns = append(reply.Ns, referral.ns...)
			reply.Extra = append(reply.Extra, referral.extra...)
		case nameExists:
			// NODATA: the name is there, this type is not, and the NSEC
			// listing what the name does hold is what proves it.
			reply.Authoritative = true
			reply.Ns = append(reply.Ns, soaProof...)
			reply.Ns = append(reply.Ns, nodataProof...)
		default:
			// A denial from a signed zone has to be provable, or a validator
			// cannot tell it from an answer someone removed.
			reply.Authoritative = true
			reply.Rcode = dns.RcodeNameError
			reply.Ns = append(reply.Ns, soaProof...)
			reply.Ns = append(reply.Ns, nxProof...)
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
	name = dns.Fqdn(name)
	s.records[hermeticRRSetKey{name, qtype}] = rrs
	s.names[name] = true
	s.rebuildNODATAProofLocked(name)
}

// rebuildNODATAProofLocked recomputes the NSEC for one name from the types it
// now holds. A NODATA answer must show which types exist at the name, so the
// proof cannot be written once — it changes as the zone is populated.
func (s *hermeticServer) rebuildNODATAProofLocked(name string) {
	if s.key == nil {
		return
	}

	present := []uint16{}
	for key := range s.records {
		if key.name == name {
			present = append(present, key.qtype)
		}
	}
	if s.nsec3 {
		s.rebuildNSEC3RingLocked()
		return
	}

	present = append(present, dns.TypeRRSIG, dns.TypeNSEC)
	slices.Sort(present)
	present = slices.Compact(present)

	next := nextInZone(name)
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600,
		},
		NextDomain: next,
		TypeBitMap: present,
	}
	s.nodataProof[name] = []dns.RR{nsec, s.key.sign(s.tb, []dns.RR{nsec})}
}

// rebuildNSEC3RingLocked recomputes the zone's whole NSEC3 chain: one record
// per name it holds, owners ordered by hash, each naming the next and the
// last wrapping round to the first.
//
// The chain is what makes a denial provable. RFC 5155 §8.4 asks for three
// things to refuse a name: a record matching the closest encloser, one
// covering the next closer, and one covering the wildcard at the closest
// encloser. A ring over the zone's real names supplies all three, because
// every hash that is not an owner falls inside exactly one interval.
func (s *hermeticServer) rebuildNSEC3RingLocked() {
	if s.key == nil || !s.nsec3 {
		return
	}

	type ringEntry struct {
		hash string
		name string
	}
	entries := make([]ringEntry, 0, len(s.names))
	for name := range s.names {
		entries = append(entries, ringEntry{
			hash: dns.HashName(name, dns.SHA1, s.nsec3Iters, s.nsec3Salt),
			name: name,
		})
	}
	if len(entries) == 0 {
		return
	}
	slices.SortFunc(entries, func(a, b ringEntry) int {
		return strings.Compare(a.hash, b.hash)
	})

	all := make([]dns.RR, 0, len(entries)*2)
	s.nodataProof = make(map[string][]dns.RR, len(entries))
	for i, entry := range entries {
		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   entry.hash + "." + s.zoneName,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Hash:       dns.SHA1,
			Flags:      s.nsec3Flags,
			Iterations: s.nsec3Iters,
			SaltLength: uint8(len(s.nsec3Salt) / 2), //nolint:gosec // fixture salt is two octets
			Salt:       s.nsec3Salt,
			HashLength: 20,
			NextDomain: entries[(i+1)%len(entries)].hash,
			TypeBitMap: s.typesAtLocked(entry.name),
		}
		set := []dns.RR{nsec3, s.key.sign(s.tb, []dns.RR{nsec3})}

		// The record whose owner is this name's hash is what proves NODATA
		// at it; the ring as a whole is what proves a denial.
		s.nodataProof[entry.name] = set
		all = append(all, set...)
	}
	s.nxProof = all
}

// typesAtLocked lists the types the zone holds at one name, in the ascending
// order a bitmap is read in. RRSIG is always there because the zone is
// signed; NSEC3 is not, since those records live at hashed owners of their
// own and this bitmap describes the original name.
func (s *hermeticServer) typesAtLocked(name string) []uint16 {
	present := []uint16{dns.TypeRRSIG}
	for key := range s.records {
		if key.name == name {
			present = append(present, key.qtype)
		}
	}
	slices.Sort(present)
	return slices.Compact(present)
}

// silence makes the server stop answering, so the resolver sees an authority
// that is reachable but never replies.
func (s *hermeticServer) proveAbsent(name string, qtype uint16, rrs ...dns.RR) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofs[hermeticRRSetKey{dns.Fqdn(name), qtype}] = rrs
}

func (s *hermeticServer) setSOAProof(rrs []dns.RR) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.soaProof = rrs
}

func (s *hermeticServer) setNXProof(rrs []dns.RR) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nxProof = rrs
}

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

// hermeticAuthority is one address a zone is reachable at.
type hermeticAuthority struct {
	server *hermeticServer
	glue   net.IP
}

// hermeticZone is one delegated zone within the namespace.
type hermeticZone struct {
	tb     testing.TB
	name   string
	key    hermeticKey
	server *hermeticServer
	signed bool
	// glue is the address the parent advertises for this zone. It is a
	// TEST-NET-1 literal, remapped to the zone's loopback socket when the
	// resolver dials — glue cannot name a port, so the address the
	// delegation carries can never be the one a test binds.
	glue net.IP
	// glue6 is the same nameserver's IPv6 address. Advertising both is what
	// sends the resolver down its AAAA paths — looking a nameserver's v6
	// address up, caching it, choosing between families — which a v4-only
	// fixture leaves untouched. Both are remapped to the same socket.
	glue6 net.IP
	// extra are further nameservers the parent advertises for this zone,
	// so a lookup has more than one address to choose between.
	extra []hermeticAuthority
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

// ServeEmptyNonTerminals publishes the interior labels of a name the way a
// real zone holds them: they exist and carry no records. delegate() does this
// for the labels above a cut; a deep name needs it below one too.
//
// Without them a minimized query for an interior label draws a signed
// NXDOMAIN, and RFC 8020 ends the resolution there — so a fixture missing them
// can only be resolved with validation switched off, which quietly tests
// something else.
func (z *hermeticZone) ServeEmptyNonTerminals(name string) {
	z.tb.Helper()
	name = dns.Fqdn(name)

	z.server.mu.Lock()
	defer z.server.mu.Unlock()
	for n := dns.CountLabel(z.name) + 1; n < dns.CountLabel(name); n++ {
		idx, end := dns.PrevLabel(name, n)
		if end {
			break
		}
		ent := name[idx:]
		z.server.names[ent] = true
		z.server.rebuildNODATAProofLocked(ent)
	}
}

func (z *hermeticZone) asked(name string, qtype uint16) int {
	return z.server.asked(name, qtype)
}

// Silence stops the zone answering anything further.
func (z *hermeticZone) Silence() { z.server.silence() }

// WithholdDenialCoverage keeps only the record that matches the zone apex in
// what a denial carries, dropping the ones whose intervals cover anything
// else. The result looks like a proof and proves nothing: a validator that
// accepts it would accept a denial for a name that exists.
func (z *hermeticZone) WithholdDenialCoverage() {
	z.tb.Helper()

	z.server.mu.Lock()
	defer z.server.mu.Unlock()

	if z.server.nsec3 {
		// The record matching the apex covers a narrow slice of the hash
		// ring, so keeping only it already withholds coverage of anything
		// else.
		apex := z.server.nodataProof[z.name]
		if len(apex) == 0 {
			z.tb.Fatalf("%s has no proof at its apex to keep", z.name)
		}
		z.server.nxProof = apex
		return
	}

	// An NSEC's interval is over names, and the apex record spans the whole
	// zone — keeping it would still cover everything. This one stops just
	// after the apex, so it covers almost nothing and certainly not the
	// names these tests ask about.
	narrow := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name: z.name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600,
		},
		NextDomain: "aaa." + z.name,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	z.server.nxProof = []dns.RR{narrow, z.key.sign(z.tb, []dns.RR{narrow})}
}

// silentAsked reports how many times the zone's silent nameservers were
// asked for one name. A silent server counts the query before dropping it,
// so this is how a test can tell that a second server was contacted.
func (z *hermeticZone) silentAsked(name string, qtype uint16) int {
	total := 0
	for _, extra := range z.extra {
		total += extra.server.asked(name, qtype)
	}
	return total
}

// HoldUntil makes the zone's primary nameserver wait for cond before it
// answers, up to a bound. A test uses it to keep the fast server quiet
// until a slower path has been observed.
func (z *hermeticZone) HoldUntil(cond func() bool, limit time.Duration) {
	z.server.mu.Lock()
	defer z.server.mu.Unlock()
	z.server.beforeReply = func(dns.Question) {
		deadline := time.Now().Add(limit)
		for !cond() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
}

// AddSilentAuthority gives the zone a second nameserver that never replies.
// A zone served by one address cannot exercise the resolver's parallel
// server path at all: there is nothing to race, and an answer carrying two
// records proves only that one server sent two records.
func (z *hermeticZone) AddSilentAuthority(n *hermeticNet) {
	z.tb.Helper()

	server := startHermeticServer(z.tb, z.name+"-silent")
	server.silence()
	glue := net.IPv4(192, 0, 2, byte(100+len(z.extra))) //nolint:gosec // a fixture never has 155 nameservers

	z.extra = append(z.extra, hermeticAuthority{server: server, glue: glue})

	nsName := "ns-silent." + z.name
	n.root.mu.Lock()
	referral := n.root.children[z.name]
	referral.ns = append(referral.ns, &dns.NS{
		Hdr: dns.RR_Header{Name: z.name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  nsName,
	})
	referral.extra = append(referral.extra, &dns.A{
		Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   glue,
	})
	n.root.mu.Unlock()
}

// signedSOA publishes a zone's SOA — signed when the zone is — and makes it
// the record every negative answer from that server carries.
func signedSOA(tb testing.TB, server *hermeticServer, zone string, key *hermeticKey) {
	tb.Helper()

	// The root is its own suffix, so the usual "ns."+zone would spell "ns..".
	nsName, mbox := "ns."+zone, "hostmaster."+zone
	if zone == "." {
		nsName, mbox = "ns.", "hostmaster."
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600,
		},
		Ns: nsName, Mbox: mbox,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
	}
	set := []dns.RR{soa}
	if key != nil {
		set = append(set, key.sign(tb, []dns.RR{soa}))
	}
	if key != nil {
		server.mu.Lock()
		server.key = key
		server.zoneName = zone
		server.mu.Unlock()
	}
	server.serve(zone, dns.TypeSOA, set...)
	server.setSOAProof(set)

	if key == nil {
		return
	}
	// One NSEC from the apex to a name past everything in the zone. Absent
	// names and the wildcard both sort inside that span, so this proves any
	// denial these fixtures produce.
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name: zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600,
		},
		// The next name has to be inside the zone: a validator drops an NSEC
		// whose interval escapes it, since such a record proves nothing about
		// this zone's contents. "zz-last"+zone would name a sibling.
		NextDomain: nextInZone(zone),
		// An NSEC bitmap is read in ascending type order, and the packer
		// rejects any other arrangement.
		TypeBitMap: []uint16{
			dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY,
		},
	}
	server.setNXProof([]dns.RR{nsec, key.sign(tb, []dns.RR{nsec})})
}

// denyType registers the signed NSEC saying that owner holds present but not
// the type a query will ask for.
func denyType(
	tb testing.TB, server *hermeticServer, key hermeticKey,
	owner, next string, absent uint16, present ...uint16,
) {
	tb.Helper()

	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600,
		},
		NextDomain: dns.Fqdn(next),
		TypeBitMap: append(append([]uint16{}, present...), dns.TypeRRSIG, dns.TypeNSEC),
	}
	server.proveAbsent(owner, absent, nsec, key.sign(tb, []dns.RR{nsec}))
}

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
	signedSOA(tb, n.root, ".", &n.rootKey)

	return n
}

// Delegate creates a signed child zone: the root publishes and signs its DS,
// so an answer from it validates all the way to the anchor.
func (n *hermeticNet) Delegate(zone string) *hermeticZone {
	return n.delegate(zone, true, true, false)
}

// DelegateVia is Delegate for a zone whose nameserver is named in some
// other zone. The parent then has no glue to offer — an address record for
// a name it is not authoritative for would be ignored — so the resolver has
// to look the nameserver up before it can reach the child at all. That is
// also the only way the address can later be refreshed: a nameserver named
// inside its own zone can only be found through the very servers that have
// stopped working.
func (n *hermeticNet) DelegateVia(zone, nsHost string) *hermeticZone {
	n.tb.Helper()

	z := n.delegate(zone, true, true, false)

	zone = dns.Fqdn(zone)
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  dns.Fqdn(nsHost),
	}

	n.root.mu.Lock()
	referral := n.root.children[zone]
	// Replace the in-zone nameserver and its glue outright: leaving them
	// would give the resolver a working address and the lookup would never
	// happen.
	referral.ns = append([]dns.RR{ns}, referral.ns[1:]...)
	referral.extra = nil
	n.root.mu.Unlock()

	return z
}

// DelegateNSEC3 is Delegate for a zone that denies with hashed names. The
// two denial families take different paths through the resolver, so a
// fixture that only ever produces NSEC leaves the NSEC3 one unexercised.
func (n *hermeticNet) DelegateNSEC3(zone string) *hermeticZone {
	return n.delegateNSEC3(zone, 0)
}

// DelegateNSEC3OptOut is DelegateNSEC3 with the Opt-Out bit set on every
// record. Such a span may hide an unsigned delegation, so what it denies is
// not fully established and a validator must not present the answer as
// authenticated.
func (n *hermeticNet) DelegateNSEC3OptOut(zone string) *hermeticZone {
	return n.delegateNSEC3(zone, 1)
}

func (n *hermeticNet) delegateNSEC3(zone string, flags uint8) *hermeticZone {
	n.tb.Helper()

	z := n.delegate(zone, true, true, false)
	z.server.mu.Lock()
	z.server.nsec3 = true
	z.server.nsec3Salt = "aabb"
	z.server.nsec3Iters = 0
	z.server.nsec3Flags = flags
	z.server.mu.Unlock()

	// The apex proof was built as NSEC when the zone was created; rebuild
	// everything published so far in the hashed form.
	z.server.mu.Lock()
	names := make([]string, 0, len(z.server.names))
	for name := range z.server.names {
		names = append(names, name)
	}
	for _, name := range names {
		z.server.rebuildNODATAProofLocked(name)
	}
	// The NSEC records built when the zone was created describe a chain this
	// zone no longer has; the ring replaces both the per-name proofs and the
	// denial set.
	z.server.rebuildNSEC3RingLocked()
	z.server.mu.Unlock()

	return z
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

	z.glue = net.IPv4(192, 0, 2, byte(10+len(n.zones))) //nolint:gosec // a fixture never has 245 zones
	nsName := "ns." + zone
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  nsName,
	}
	z.glue6 = net.ParseIP("2001:db8::" + strconv.Itoa(10+len(n.zones)))
	glue := &dns.A{
		Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   z.glue,
	}
	glue6 := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: nsName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
		AAAA: z.glue6,
	}
	referral := &hermeticReferral{
		zone: zone, ns: []dns.RR{ns}, extra: []dns.RR{glue, glue6},
	}

	if publishDS {
		dsKey := z.key
		if wrongDS {
			dsKey = newHermeticKey(n.tb, zone)
		}
		ds := dsKey.key.ToDS(dns.SHA256)
		dsSig := n.rootKey.sign(n.tb, []dns.RR{ds})
		n.root.serve(zone, dns.TypeDS, ds, dsSig)
		referral.ns = append(referral.ns, ds, dsSig)
		z.ds = []dns.RR{ds}
	}
	if signed {
		z.Serve(z.key.key)
		signedSOA(n.tb, z.server, zone, &z.key)
	} else {
		signedSOA(n.tb, z.server, zone, nil)
	}
	if !publishDS {
		// The parent must say, in a way that can be verified, that this cut
		// carries no DS. Absent that proof a validator cannot distinguish an
		// unsigned child from a stripped one, and must refuse — so an
		// insecure delegation is only insecure if the denial is signed.
		denyType(n.tb, n.root, n.rootKey, zone, "zz-"+zone, dns.TypeDS, dns.TypeNS)
	}

	n.root.mu.Lock()
	n.root.children[zone] = referral
	// Every label between the root and the cut exists as an empty
	// non-terminal. Denying it outright would be wrong — and the resolver
	// only gets past it through its broken-parent fallback, so a fixture
	// that does so quietly tests the fallback instead of the descent.
	for _, ent := range emptyNonTerminals(zone) {
		n.root.names[ent] = true
		n.root.rebuildNODATAProofLocked(ent)
	}
	n.root.mu.Unlock()

	n.zones = append(n.zones, z)
	return z
}

// workDir gives this namespace a directory of its own.
//
// Each namespace generates its own root key, and the resolver persists trust
// anchors under the working directory: sharing one directory means every run
// reloads and rewrites the random keys of every run before it, which makes
// state depend on test order and two test processes write the same file.
//
// It is not TempDir, whose cleanup fails the test if anything appears in the
// directory while it is being removed — and the resolver's trust-anchor
// upkeep runs in the background, so something does.
func (n *hermeticNet) workDir() string {
	n.tb.Helper()

	dir, err := os.MkdirTemp("", "sdns-hermetic-")
	if err != nil {
		n.tb.Fatalf("temp dir: %v", err)
	}
	n.tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Config returns a resolver configuration anchored on this namespace's root.
func (n *hermeticNet) Config() *config.Config {
	cfg := makeTestConfig()
	cfg.Directory = n.workDir()
	cfg.RootServers = []string{n.root.addr}
	cfg.Root6Servers = nil
	// Zones advertise both families, so the resolver exercises its AAAA
	// paths; every address is remapped to the same loopback socket, so no
	// IPv6 packet is actually sent.
	cfg.IPv6Access = true
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

	// Remap each zone's advertised glue to the socket actually serving it,
	// and leave everything else alone. Seeding the delegation cache instead
	// would be simpler and would also be a lie: the resolver would find the
	// child already known, so the referral would never be processed and the
	// DS in it never validated against the parent — the very links these
	// tests exist to cover.
	byGlue := make(map[string]string, len(n.zones))
	for _, z := range n.zones {
		byGlue[net.JoinHostPort(z.glue.String(), "53")] = z.server.addr
		byGlue[net.JoinHostPort(z.glue6.String(), "53")] = z.server.addr
		for _, extra := range z.extra {
			byGlue[net.JoinHostPort(extra.glue.String(), "53")] = extra.server.addr
		}
	}
	mapper := func(addr string) string {
		if target, ok := byGlue[addr]; ok {
			return target
		}
		return addr
	}
	handler.resolver.resolveTarget.Store(&mapper)

	// A resolver asks itself things: where a nameserver lives, most of all.
	// Without somewhere to send those sub-queries it cannot look a
	// nameserver up, so every path that refreshes addresses is unreachable
	// and a delegation whose glue has gone stale can never recover.
	var queryer middleware.Queryer = hermeticQueryer{handler: handler}
	handler.resolver.queryer.Store(&queryer)

	return handler
}

// hermeticQueryer answers a resolver's internal sub-queries from the same
// namespace the resolver itself is pointed at.
type hermeticQueryer struct {
	handler *DNSHandler
}

func (q hermeticQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := q.handler.handle(ctx, req)
	if resp == nil {
		return nil, middleware.ErrNoResponse
	}
	return resp, nil
}
