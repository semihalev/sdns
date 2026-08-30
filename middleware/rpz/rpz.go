// Package rpz is the Response Policy Zones middleware: the chain seat of
// the internal/rpz engine. It matches client queries against the loaded
// policy zones ahead of the cache, so policy applies to every client
// query — cache hits included — and a reload takes effect immediately.
// Semantics and invariants: RPZ-DESIGN.md.
package rpz

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

const name = "rpz"

// localDataTTL is the TTL of the synthetic CNAME a `policy = "cname"`
// override serves. Feed-supplied local data keeps the TTLs the operator's
// zone file wrote; only this record has no file to take one from. Short,
// so a lifted policy stops echoing from downstream caches quickly.
const localDataTTL = 300

// RPZ is the middleware. The compiled policy store swaps atomically on
// reload; everything else is set at construction and read-only after.
type RPZ struct {
	enforce bool
	store   atomic.Pointer[rpz.Store]

	// queryer resolves a Local Data CNAME's target through the internal
	// sub-pipeline, the same seam dns64 uses. Nil when no wiring exists
	// (a cache-less pipeline): the CNAME is then served unchased and the
	// client follows it.
	queryer middleware.Queryer

	// reloadMu serializes reloads; zones is the config list the watcher
	// re-reads files from, index-aligned with the store's zones.
	reloadMu sync.Mutex
	zones    []config.RPZZone
}

// New builds the middleware from the config. A zone file that fails to
// load is an empty placeholder — it filters nothing, keeps its index for
// the reload watcher, and says so loudly — rather than a refused startup:
// the config gate (`sdns -t`) is where a broken feed is a hard failure.
func New(cfg *config.Config) *RPZ {
	r := &RPZ{enforce: cfg.RPZ.Mode == "enforce"}
	if !cfg.RPZ.Enabled || len(cfg.RPZ.Zones) == 0 {
		r.store.Store(&rpz.Store{})
		return r
	}

	r.zones = cfg.RPZ.Zones
	zones := make([]*rpz.Zone, 0, len(cfg.RPZ.Zones))
	for _, zc := range cfg.RPZ.Zones {
		zones = append(zones, loadZone(zc))
	}
	r.store.Store(&rpz.Store{Zones: zones})
	r.watch()

	return r
}

func loadZone(zc config.RPZZone) *rpz.Zone {
	policy, _ := rpz.ParseOverride(zc.Policy)
	target := ""
	if zc.Cname != "" {
		target = dns.CanonicalName(zc.Cname)
	}
	z, err := rpz.LoadZoneFile(zc.Name, zc.File, policy, target)
	if err != nil {
		zlog.Error("RPZ zone failed to load and will filter nothing", "zone", zc.Name, "file", zc.File, "error", err.Error())
		reloadErrors.WithLabelValues(zc.Name).Inc()
		return &rpz.Zone{Name: zc.Name, Policy: policy, CNAMETarget: target}
	}
	publishZoneMetrics(z)
	zlog.Info("RPZ zone loaded", "zone", zc.Name, "rules", z.Rules, "skipped", len(z.Skipped))
	return z
}

// Name implements the Handler interface.
func (r *RPZ) Name() string { return name }

// ClientOnly keeps policy off internal sub-queries: rewriting the
// resolver's own probes would corrupt resolution itself.
func (r *RPZ) ClientOnly() bool { return true }

// SetQueryer wires the internal sub-pipeline used to chase a Local Data
// CNAME's target (middleware.Setup, QueryerSetter).
func (r *RPZ) SetQueryer(q middleware.Queryer) { r.queryer = q }

// ServeDNS implements the Handler interface.
func (r *RPZ) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	s := r.store.Load()
	if s.Empty() {
		ch.Next(ctx)
		return
	}

	req, w := ch.Request, ch.Writer

	// Policy is recursive-service policy for external clients (design
	// §5.4). The RD gate is load-bearing, not decoration: the cache sits
	// ahead of the resolver's own RD=0 refusal, so without it an RD=0
	// probe would be policy-checked here and answered from the cache
	// below. INET only — the CHAOS/NONE worlds name nothing RPZ covers.
	if w.Internal() || !req.RD() || req.Qclass() != dns.ClassINET {
		ch.Next(ctx)
		return
	}

	// The query key, in canonical-labels form, built on the stack. The
	// wire-born path reads the name bytes straight out of the packet; the
	// decoded path re-packs the question name first, in its own function
	// so its packing buffer cannot leak an allocation onto this one.
	var keyBuf [dnsname.MaxPresentationLength]byte
	var offs [dnsname.MaxLabels]int
	var canon []byte
	var n int
	var ok bool
	if req.Undecoded() {
		canon, n, ok = dnsname.AppendCanonicalLabels(keyBuf[:0], req.WireName(), offs[:])
	} else {
		canon, n, ok = decodedKey(req.Msg(), keyBuf[:0], offs[:])
	}
	if !ok {
		ch.Next(ctx)
		return
	}

	winner, observed := s.MatchQNAME(canon, offs[:], n)
	if winner.Zone == nil && observed == nil {
		// The steady state: no rule anywhere named this query. Nothing
		// above this line allocated.
		ch.Next(ctx)
		return
	}

	// Winner-bounded counting (design §5.5): the disabled zones met on
	// the way to the winner are counted as what they would have done.
	for _, m := range observed {
		countMatch(m, outcomeObserved)
		if debugLogEnabled() {
			zlog.Debug("RPZ match observed", "zone", m.Zone.Name, "action", m.Effective().String())
		}
	}
	if winner.Zone == nil {
		ch.Next(ctx)
		return
	}

	if !r.enforce {
		countMatch(winner, outcomeObserved)
		if debugLogEnabled() {
			zlog.Debug("RPZ match in shadow", "zone", winner.Zone.Name, "action", winner.Effective().String())
		}
		ch.Next(ctx)
		return
	}

	countMatch(winner, outcomeEnforced)
	r.act(ctx, ch, winner)
}

// decodedKey builds the canonical-labels key for a decoded request by
// packing the question name back to wire form. The decoded path is the
// slow lane already; keeping the packing buffer here, behind a call, is
// what keeps it out of the wire path's frame — inlined, its escape would
// cost every query an allocation.
//
//go:noinline
func decodedKey(msg *dns.Msg, dst []byte, offs []int) ([]byte, int, bool) {
	if msg == nil || len(msg.Question) != 1 {
		return nil, 0, false
	}
	var wireBuf [256]byte
	off, err := dns.PackDomainName(msg.Question[0].Name, wireBuf[:], 0, nil, false)
	if err != nil {
		return nil, 0, false
	}
	return dnsname.AppendCanonicalLabels(dst, wireBuf[:off], offs)
}

// act carries out the winning action in enforce mode.
func (r *RPZ) act(ctx context.Context, ch *middleware.Chain, winner rpz.ZoneMatch) {
	w := ch.Writer
	action := winner.Effective()

	switch action {
	case rpz.ActionPassthru:
		// Acting, by not acting: the match exempts the name from RPZ.
		ch.Next(ctx)
		return
	case rpz.ActionDrop:
		// No reply at all — the accesslist mechanism: the job releases
		// without a write.
		ch.Cancel()
		return
	case rpz.ActionTCPOnly:
		if w.Proto() != "udp" {
			// Any non-UDP transport already gives the trigger the
			// spoofing resistance it asks for.
			ch.Next(ctx)
			return
		}
	}

	// Everything from here synthesizes a reply, which needs the message.
	ctx, msg := ch.Materialize(ctx)
	if msg == nil {
		return
	}
	_ = ctx
	do := ch.Request.DO()

	switch action {
	case rpz.ActionTCPOnly:
		// TC=1 and nothing else: RFC 2181 §9 tells the client to ignore
		// a truncated response's records and retry over TCP, so the
		// policy SOA/EDE stamp would decorate a body nobody may read.
		m := new(dns.Msg)
		m.SetReply(msg)
		m.RecursionAvailable = true
		m.Truncated = true
		_ = w.WriteMsg(m)
		ch.Cancel()
	case rpz.ActionNXDOMAIN:
		m := dnsutil.SetRcode(msg, dns.RcodeNameError, do)
		stamp(m, winner)
		_ = w.WriteMsg(m)
		ch.Cancel()
	case rpz.ActionNODATA:
		m := dnsutil.SetRcode(msg, dns.RcodeSuccess, do)
		stamp(m, winner)
		_ = w.WriteMsg(m)
		ch.Cancel()
	case rpz.ActionLocalData:
		r.serveLocalData(ctx, ch, msg, winner, do)
	}
}

// serveLocalData synthesizes the rule's records as if the policy zone were
// authoritative for the client's qname: every answer owner is the qname,
// only RDATA and TTL come from the rule (design §5.2 — an address-encoded
// or wildcard trigger owner must never leak into a response).
func (r *RPZ) serveLocalData(ctx context.Context, ch *middleware.Chain, msg *dns.Msg, winner rpz.ZoneMatch, do bool) {
	q := msg.Question[0]
	m := dnsutil.SetRcode(msg, dns.RcodeSuccess, do)
	m.Authoritative = true

	records := winner.Rule.Local
	if winner.Zone.Policy == rpz.OverrideCNAME {
		// The zone-wide walled-garden override replaces whatever the
		// rule said with one CNAME to the configured target.
		records = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: localDataTTL},
			Target: winner.Zone.CNAMETarget,
		}}
	}

	var cname *dns.CNAME
	for _, rr := range records {
		if q.Qtype == dns.TypeANY || rr.Header().Rrtype == q.Qtype {
			cp := dns.Copy(rr)
			cp.Header().Name = q.Name
			m.Answer = append(m.Answer, cp)
			continue
		}
		if c, ok := rr.(*dns.CNAME); ok && cname == nil {
			cname = c
		}
	}

	// No RRset of the requested type: a CNAME answers for every type
	// (draft §3.6), and a recursive answering RD=1 chases it.
	if len(m.Answer) == 0 && cname != nil {
		if cp := expandCNAME(cname, q.Name); cp != nil {
			m.Answer = append(m.Answer, cp)
			r.chase(ctx, m, cp.Target, q.Qtype)
		}
	}

	stamp(m, winner)
	_ = ch.Writer.WriteMsg(m)
	ch.Cancel()
}

// expandCNAME copies the rule's CNAME onto the qname, expanding a
// wildcarded target by prepending the qname (draft §3.6: EVIL.EXAMPLE.ORG
// through `CNAME *.EXAMPLE.COM` becomes EVIL.EXAMPLE.ORG.EXAMPLE.COM).
// nil when the expansion is not a legal name — the caller then serves
// NODATA, the nearest lawful answer.
func expandCNAME(cname *dns.CNAME, qname string) *dns.CNAME {
	cp := dns.Copy(cname).(*dns.CNAME)
	cp.Hdr.Name = qname
	if strings.HasPrefix(cp.Target, "*.") {
		cp.Target = qname + cp.Target[2:]
		if _, ok := dns.IsDomainName(cp.Target); !ok {
			return nil
		}
	}
	return cp
}

// chase resolves the CNAME target through the internal sub-pipeline and
// appends the real answer, so the client gets the full chain the way any
// recursive would serve it. The chased records are the resolver's own
// answer for the target — policy synthesized only the link. DNSSEC
// records are dropped on the way: the assembled answer cannot validate
// and must not pretend to (design C2).
func (r *RPZ) chase(ctx context.Context, m *dns.Msg, target string, qtype uint16) {
	if r.queryer == nil || qtype == dns.TypeCNAME {
		return
	}
	sub := new(dns.Msg)
	sub.SetQuestion(target, qtype)
	sub.RecursionDesired = true
	resp, err := r.queryer.Query(ctx, sub)
	if err != nil || resp == nil {
		// The link alone is still a correct partial answer; the client
		// retries the target itself.
		return
	}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		m.Answer = append(m.Answer, rr)
	}
	m.Rcode = resp.Rcode
}

// stamp marks a rewritten answer the way the draft requires: the policy
// zone's SOA in the additional section names the source, EDE 17 says
// "Filtered" in modern terms, and AD is clear — the rewrite is not the
// signed truth and must never claim to be (design C2).
func stamp(m *dns.Msg, winner rpz.ZoneMatch) {
	m.AuthenticatedData = false
	if soa := winner.Zone.SOA; soa != nil {
		// A value copy: the stored record is shared across queries and
		// a downstream TTL rewrite must not reach it.
		cp := *soa
		m.Extra = append([]dns.RR{&cp}, m.Extra...)
	}
	dnsutil.SetEDE(m, dns.ExtendedErrorCodeFiltered, "rpz: filtered by zone "+winner.Zone.Name)
}

// debugLogEnabled mirrors the resolver's guard: zlog drops disabled
// records only after arguments are boxed, so per-match call sites check
// first.
func debugLogEnabled() bool {
	return zlog.Default().GetLevel() <= zlog.LevelDebug
}
