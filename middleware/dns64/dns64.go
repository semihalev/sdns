// Package dns64 implements RFC 6147 DNS64. When an IPv6-only client
// queries AAAA for a name that has no usable AAAA records but does
// have A records, DNS64 synthesises AAAA records by embedding the
// IPv4 addresses inside a configured Pref64::/n IPv6 prefix (RFC
// 6052). The client receives addresses in a NAT64-routable subnet
// and can reach the IPv4-only service through a paired NAT64
// gateway.
//
// Internal sub-queries skip DNS64 entirely (ClientOnly() == true):
// the resolver's own NS / glue chase and our secondary A-record
// lookup must not loop back through us, and the synthesis is a
// client-facing concern.
//
// Implementation notes:
//
//   - Chain placement is between kubernetes and cache. The cache
//     stores the original AAAA response (NODATA, NXDOMAIN, or AAAA
//     RRset) — synthesis runs per client query against that
//     cached response. The secondary A lookup is itself cached, so
//     repeat synthesis costs an O(few-µs) memcpy plus a cache hit;
//     this preserves per-client correctness when client_networks
//     restricts synthesis.
//   - RCODE handling follows RFC 6147 §5.1.2 / §5.1.3 / §5.5.
//     NOERROR with no usable AAAA triggers synthesis. NXDOMAIN
//     passes through unchanged — the name doesn't exist, so it
//     has no A either. SERVFAIL carrying a DNSSEC-failure
//     Extended DNS Error (Unsupported DNSKEY Algorithm /
//     DS Digest Type / NSEC3 Iterations Value, Indeterminate,
//     Bogus, Signature Expired/Not Yet Valid, DNSKEY/RRSIGs/NSEC
//     Missing, No Zone Key Bit Set) also passes through — DNS64
//     must never paper over a validation failure. Any other
//     nonzero RCODE (plain SERVFAIL, REFUSED, etc.) is treated
//     as "no answer" and attempts synthesis; if the A query is
//     itself empty or errors, that response (rcode + Authority)
//     becomes the basis for the client reply per §5.1.6.
//   - AAAA records in the upstream response are filtered against
//     exclude_aaaa_networks (RFC 6147 §5.1.4) before deciding
//     pass-through vs synthesis. The default ::ffff:0:0/96 keeps
//     IPv4-mapped IPv6 from leaking through.
//   - Per RFC 6147 §5.5 a NODATA proven by AD=1 from the resolver
//     is downgraded: the synthesised reply clears AD and attaches
//     EDE 4 ("Forged Answer"). A client that set CD=1 is asking to
//     validate itself, so synthesis is skipped.
//   - The well-known prefix 64:ff9b::/96 enforces the RFC 6147
//     §5.1.4 "do not translate" set on the IPv4 side at synthesis
//     time. Operator-chosen prefixes do not.
//   - Multiple prefixes synthesise in parallel per RFC 6147 §5.2:
//     every (A, prefix) pair produces a synthesised AAAA so the
//     client gets every reachable Pref64 path.
//   - PTR translation per RFC 6147 §5.3.1: ip6.arpa queries whose
//     embedded IPv4 falls inside a configured Pref64 are answered
//     with a CNAME redirect to in-addr.arpa, optionally with the
//     resolved PTR records appended.
package dns64

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

const name = "dns64"

// noSOATTLCeiling is the cap RFC 6147 §5.1.7 mandates when the
// upstream AAAA response carries no SOA — i.e. there's no
// negative-cache TTL to take the minimum against. A synthesised
// AAAA may still use a lower TTL via the A record's own TTL.
const noSOATTLCeiling uint32 = 600

// errQueryerNotWired guards the (impossible in production) case of
// reaching the synthesis path before middleware.Setup ran. Shaped
// like the cache middleware's equivalent for grep-ability.
var errQueryerNotWired = errors.New("dns64: queryer not wired")

// DNS64 is the middleware handler. The receiver may legitimately be
// nil — New returns a typed-nil pointer when the middleware is
// disabled in config. Methods invoked on the typed-nil are no-ops
// where it makes sense; ServeDNS in particular is never called on
// a typed-nil because Registry.Build skips disabled handlers.
type DNS64 struct {
	cfg     *compiled
	queryer middleware.Queryer
	pool    sync.Pool
}

// New constructs a DNS64 handler. Returns a typed-nil pointer when
// DNS64 is disabled or has no usable configuration; the registry
// detects that via isNilHandler and skips the middleware entirely.
func New(cfg *config.Config) *DNS64 {
	c := compileConfig(cfg)
	if c == nil {
		return nil
	}
	d := &DNS64{cfg: c}
	d.pool.New = func() any { return &responseWriter{} }
	prefixStrs := make([]string, len(c.prefixes))
	for i, p := range c.prefixes {
		prefixStrs[i] = p.net.String()
	}
	zlog.Info("DNS64 enabled",
		"prefixes", prefixStrs,
		"client_networks", len(c.clientNetworks),
		"exclude_zones", len(c.excludeZones),
		"exclude_a_networks", len(c.excludeAv4),
		"exclude_aaaa_networks", len(c.excludeAAAA),
	)
	return d
}

// Name returns the registered middleware name.
func (d *DNS64) Name() string { return name }

// ClientOnly excludes DNS64 from the internal sub-pipeline. Internal
// sub-queries (resolver NS chase, our own secondary A lookup, cache
// CNAME chase) must not re-enter DNS64 — that would cause infinite
// synthesis loops and leak synthesised AAAAs into delegation logic.
func (d *DNS64) ClientOnly() bool { return true }

// SetQueryer wires the internal-sub-pipeline Queryer used for the
// secondary A-record lookup. Auto-wired by middleware.Setup.
func (d *DNS64) SetQueryer(q middleware.Queryer) { d.queryer = q }

// ServeDNS gates synthesis behind cheap fast-path checks before
// committing to a writer wrap. The wrap (and consequently the
// secondary A lookup) only happens for client AAAA-class-IN
// queries that match the configured client networks and aren't on
// an excluded zone. PTR queries inside ip6.arpa are intercepted
// here too, when their address falls under one of the configured
// Pref64 ranges (RFC 6147 §5.3.1).
func (d *DNS64) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) != 1 {
		ch.Next(ctx)
		return
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		ch.Next(ctx)
		return
	}
	if w.Internal() {
		Passthrough.WithLabelValues("internal").Inc()
		ch.Next(ctx)
		return
	}
	if !req.RecursionDesired {
		// RD=0 clients are asking for a non-recursive response.
		// DNS64 inherently issues a recursive secondary lookup
		// (A for AAAA synthesis, in-addr.arpa PTR for ip6.arpa),
		// so opting out preserves the client's policy. Without
		// this gate, the cache rejects RD=0 with SERVFAIL and
		// DNS64 would interpret that SERVFAIL as "no AAAA",
		// firing a recursive A query that bypasses the
		// non-recursion intent.
		Passthrough.WithLabelValues("no_rd").Inc()
		ch.Next(ctx)
		return
	}
	if req.CheckingDisabled {
		// RFC 6147 §5.5 — a CD=1 client has opted to validate
		// itself; do not synthesise. Symmetric for PTR: the
		// CNAME we'd synthesise points at an unsigned name we
		// fabricated, so respect the bit.
		Passthrough.WithLabelValues("cd_bit").Inc()
		ch.Next(ctx)
		return
	}
	if !d.cfg.clientEligible(w.RemoteIP()) {
		Passthrough.WithLabelValues("client_excluded").Inc()
		ch.Next(ctx)
		return
	}
	qname := strings.ToLower(dns.CanonicalName(q.Name))

	// PTR translation per RFC 6147 §5.3.1. If the qname falls in
	// ip6.arpa under a configured Pref64 we synthesise a CNAME to
	// the corresponding in-addr.arpa name and short-circuit the
	// chain. Anything else (qname not under a configured Pref64,
	// malformed encoding, exclusion under the well-known prefix)
	// falls through to normal recursion so the resolver can answer
	// real ip6.arpa zones.
	if q.Qtype == dns.TypePTR && strings.HasSuffix(qname, ".ip6.arpa.") {
		if d.handlePTR(ctx, ch, qname) {
			return
		}
		ch.Next(ctx)
		return
	}

	if q.Qtype != dns.TypeAAAA {
		ch.Next(ctx)
		return
	}
	if d.cfg.zoneExcluded(qname) {
		Passthrough.WithLabelValues("zone_excluded").Inc()
		ch.Next(ctx)
		return
	}

	rw := d.pool.Get().(*responseWriter)
	rw.ResponseWriter = w
	rw.d = d
	rw.ctx = ctx
	rw.qname = qname
	rw.req = req
	ch.Writer = rw
	defer func() {
		ch.Writer = w
		rw.reset()
		d.pool.Put(rw)
	}()

	ch.Next(ctx)
}

// ptrSynthTTL is the TTL applied to a synthesised CNAME redirect.
// Short enough to recover quickly if the operator re-points
// prefixes; long enough to amortise the chase cost across a
// session of reverse lookups.
const ptrSynthTTL uint32 = 600

// handlePTR translates an ip6.arpa PTR query whose embedded IPv4
// falls under one of the configured Pref64 prefixes. On match it
// writes a CNAME pointing at the corresponding in-addr.arpa name
// (plus, if the chase succeeds, the resolved PTR records) and
// short-circuits the chain. Returns true iff it answered; false
// means "not a translation, let the normal chain handle it".
func (d *DNS64) handlePTR(ctx context.Context, ch *middleware.Chain, qname string) bool {
	addr, ok := parseIP6ArpaName(qname)
	if !ok {
		return false
	}
	var v4 net.IP
	for _, p := range d.cfg.prefixes {
		if !p.net.Contains(addr) {
			continue
		}
		ext, ok := extractIPv4(p.net, addr)
		if !ok {
			continue
		}
		// Apply the same RFC 6147 §5.1.4 IPv4 exclusion that
		// AAAA synthesis does — refuse to translate ip6.arpa
		// names whose corresponding IPv4 address is in the
		// "do not translate" set under the well-known prefix.
		if d.cfg.shouldExcludeAOnPrefix(ext, p) {
			continue
		}
		v4 = ext
		break
	}
	if v4 == nil {
		return false
	}

	target := inAddrArpa(v4)
	cname := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   ch.Request.Question[0].Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    ptrSynthTTL,
		},
		Target: target,
	}
	answers := []dns.RR{cname}

	// Best-effort chase the in-addr.arpa PTR through the internal
	// sub-pipeline so the client gets a complete answer. Failures
	// drop us back to "CNAME only" — RFC-compliant; the client can
	// follow the CNAME themselves.
	if d.queryer != nil {
		sub := new(dns.Msg)
		sub.SetQuestion(target, dns.TypePTR)
		sub.RecursionDesired = true
		if resp, err := d.queryer.Query(ctx, sub); err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			for _, rr := range resp.Answer {
				if rr.Header().Rrtype == dns.TypePTR {
					answers = append(answers, rr)
				}
			}
		}
	}

	out := new(dns.Msg)
	out.SetReply(ch.Request)
	out.RecursionAvailable = true
	out.Rcode = dns.RcodeSuccess
	out.Answer = answers
	if len(ch.Request.Extra) > 0 {
		out.Extra = make([]dns.RR, len(ch.Request.Extra))
		copy(out.Extra, ch.Request.Extra)
	}

	PTRTranslated.Inc()
	_ = ch.Writer.WriteMsg(out)
	ch.Cancel()
	return true
}

// responseWriter intercepts the downstream chain's WriteMsg. It
// passes through every response that doesn't qualify for DNS64
// synthesis and rewrites the rest.
type responseWriter struct {
	middleware.ResponseWriter
	d     *DNS64
	ctx   context.Context //nolint:containedctx // mirrors cache.ResponseWriter; the wrapper is per-request
	req   *dns.Msg
	qname string
}

func (w *responseWriter) reset() {
	w.ResponseWriter = nil
	w.d = nil
	w.ctx = nil
	w.req = nil
	w.qname = ""
}

// WriteMsg observes the downstream reply and, when the client is
// missing a usable AAAA, replaces it with a synthesised answer
// derived from a secondary A lookup. RFC 6147 dispatch:
//
//   - Truncated / malformed → pass through unchanged.
//   - NXDOMAIN → pass through (§5.1.2: the name doesn't exist, so
//     it has no A either; synthesis would be misleading).
//   - SERVFAIL with a DNSSEC-failure Extended DNS Error → pass
//     through (§5.5: DNS64 must never mask a validation failure).
//   - NOERROR with at least one AAAA RR that survives the
//     exclude_aaaa_networks filter → pass through (§5.1.4 / §5.1.6).
//   - NOERROR with no usable AAAA (post-filter), or any other
//     nonzero RCODE (plain SERVFAIL, REFUSED, etc.; §5.1.3 treats
//     these as "no answer") → secondary A lookup; replace the
//     response with synthesised AAAAs plus any CNAME / DNAME chain
//     from the A response.
//
// Note: AAAA records that are filtered out (e.g. ::ffff:0:0/96
// IPv4-mapped) are stripped from the response even on the
// pass-through path, so the client never sees a non-routable
// address that the upstream put there in error.
func (w *responseWriter) WriteMsg(m *dns.Msg) error {
	if m == nil || m.Truncated || len(m.Question) == 0 {
		return w.ResponseWriter.WriteMsg(m)
	}
	if m.Rcode == dns.RcodeNameError {
		Passthrough.WithLabelValues("nxdomain").Inc()
		return w.ResponseWriter.WriteMsg(m)
	}
	// RFC 6147 §5.5: a validating DNS64 must not paper over a
	// resolver-side DNSSEC failure. The recursive resolver
	// returns SERVFAIL with one of the DNSSEC Extended DNS Error
	// codes (Bogus, Signature Expired/Not Yet Valid, DNSKEY /
	// RRSIG / NSEC missing, etc.) on validation failure; in that
	// case synthesis would mask the failure and let the client
	// reach a target whose AAAA the upstream said was bogus.
	// Pass the SERVFAIL through so the client sees the validation
	// failure verbatim.
	if isDNSSECFailure(m) {
		Passthrough.WithLabelValues("dnssec_fail").Inc()
		return w.ResponseWriter.WriteMsg(m)
	}

	// Filter the upstream Answer section against the AAAA
	// exclude list. If anything survives, the response is
	// "non-empty" per §5.1.4 and we forward the (possibly
	// modified) version. If nothing survives — every AAAA was
	// excluded, or there were none to begin with — fall through
	// to the synthesis path.
	if m.Rcode == dns.RcodeSuccess {
		filtered, hadAAAA, kept, stripped := w.filterUpstreamAAAA(m)
		if hadAAAA && kept > 0 {
			Passthrough.WithLabelValues("aaaa_present").Inc()
			if stripped > 0 {
				// We modified the RRset, so any AD bit the
				// validator set no longer covers what the client
				// is about to see. Clear it; if the upstream had
				// vouched for the response, advertise the reason
				// via EDE 4 so a curious client can see why.
				filtered.AuthenticatedData = false
				if m.AuthenticatedData {
					util.SetEDE(filtered, dns.ExtendedErrorCodeForgedAnswer, "DNS64 filtered IPv4-mapped AAAA")
				}
			}
			return w.ResponseWriter.WriteMsg(filtered)
		}
		m = filtered
	}

	synth := w.synthesise(m)
	if synth == nil {
		// A lookup failed or yielded nothing usable; preserve the
		// original (already AAAA-filtered) answer rather than
		// papering over it. Reason has already been counted.
		return w.ResponseWriter.WriteMsg(m)
	}
	Synthesised.Inc()
	return w.ResponseWriter.WriteMsg(synth)
}

// filterUpstreamAAAA inspects m and, if any AAAA records fall in
// the configured exclude_aaaa_networks set, returns a copy with
// those records dropped from Answer. Returns:
//
//   - the (possibly mutated) message;
//   - hadAAAA: did Answer carry any AAAA at all (regardless of
//     survival);
//   - kept: count of AAAA records retained after filtering;
//   - stripped: count of AAAA records actually dropped.
//
// The dns.Msg.Copy is only made when stripped > 0 — a response
// with non-AAAA records (CNAME, RRSIG, etc.) is otherwise
// returned as-is to keep the common pass-through path
// allocation-free.
func (w *responseWriter) filterUpstreamAAAA(m *dns.Msg) (*dns.Msg, bool, int, int) {
	hadAAAA := false
	kept := 0
	stripped := 0
	for _, rr := range m.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			hadAAAA = true
			if w.d.cfg.shouldExcludeAAAA(aaaa.AAAA) {
				stripped++
				continue
			}
			kept++
		}
	}
	if stripped == 0 {
		return m, hadAAAA, kept, 0
	}
	out := m.Copy()
	answer := out.Answer[:0]
	for _, rr := range out.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			if w.d.cfg.shouldExcludeAAAA(aaaa.AAAA) {
				continue
			}
		}
		answer = append(answer, rr)
	}
	out.Answer = answer
	return out, hadAAAA, kept, stripped
}

// synthesise issues the secondary A-record lookup and builds the
// replacement message. Returns nil only when the queryer itself
// failed to deliver an A response — caller then falls back to the
// original. When the A response simply has no usable records
// (empty answer, NXDOMAIN, SERVFAIL), RFC 6147 §5.1.6 says the
// A response is the basis for the client reply, so we return a
// non-nil empty/error response addressed to the AAAA question.
func (w *responseWriter) synthesise(orig *dns.Msg) *dns.Msg {
	if w.d.queryer == nil {
		ALookupFailures.WithLabelValues("queryer_error").Inc()
		return nil
	}

	aReq := new(dns.Msg)
	aReq.SetQuestion(w.req.Question[0].Name, dns.TypeA)
	aReq.RecursionDesired = true
	// Inherit CD from the client request so the A lookup honours
	// the same validation policy. CD=1 was already filtered out at
	// ServeDNS — this preserves whatever bit was set on the AAAA
	// query's path through DO/AD.
	aReq.CheckingDisabled = w.req.CheckingDisabled

	aResp, err := w.d.queryer.Query(w.ctx, aReq)
	if err != nil {
		ALookupFailures.WithLabelValues(classifyQueryErr(err)).Inc()
		return nil
	}
	if aResp == nil {
		ALookupFailures.WithLabelValues("nil_response").Inc()
		return nil
	}
	if aResp.Rcode != dns.RcodeSuccess {
		switch aResp.Rcode {
		case dns.RcodeServerFailure:
			ALookupFailures.WithLabelValues("servfail").Inc()
		case dns.RcodeNameError:
			ALookupFailures.WithLabelValues("nxdomain").Inc()
		default:
			ALookupFailures.WithLabelValues("other_rcode").Inc()
		}
		return w.buildAResponseAsBasis(orig, aResp)
	}

	chain, addresses := splitChainAndA(aResp)
	if len(addresses) == 0 {
		// NOERROR with no A records — RFC 6147 §5.1.6 still
		// applies: the empty A response is the basis for the
		// client reply.
		ALookupFailures.WithLabelValues("no_a").Inc()
		return w.buildAResponseAsBasis(orig, aResp)
	}

	// RFC 6147 §5.1.7: synthesised TTL = min(A TTL, negative-cache
	// TTL of the original AAAA response). When no SOA is present
	// the upper bound is 600 seconds. The lower bound is whatever
	// the A records carry — short-lived A records intentionally
	// keep DNS64 answers short-lived too.
	ttl := noSOATTLCeiling
	if negTTL := negativeAAAATTL(orig); negTTL > 0 {
		ttl = negTTL
	}
	for _, a := range addresses {
		if a.Hdr.Ttl < ttl {
			ttl = a.Hdr.Ttl
		}
	}

	answers := make([]dns.RR, 0, len(chain)+len(addresses)*len(w.d.cfg.prefixes))
	for _, c := range chain {
		cp := dns.Copy(c)
		if cp.Header().Ttl > ttl {
			cp.Header().Ttl = ttl
		}
		answers = append(answers, cp)
	}
	// Synthesised AAAAs adopt the A record's owner — that's the
	// terminal name after any CNAME / DNAME chain has been
	// resolved by the upstream, and matches what the client
	// expects in the Answer section. RFC 6147 §5.2 lets multiple
	// configured prefixes coexist; we synthesise one AAAA per
	// (A, prefix) pair so the client gets every configured path.
	for _, p := range w.d.cfg.prefixes {
		for _, a := range addresses {
			v4 := a.A.To4()
			if v4 == nil {
				continue
			}
			if w.d.cfg.shouldExcludeAOnPrefix(v4, p) {
				continue
			}
			rr := synthesizeAAAA(a.Hdr.Name, a, p.net, ttl)
			if rr != nil {
				answers = append(answers, rr)
			}
		}
	}
	// All (A, prefix) pairs were excluded (e.g. only the well-known
	// prefix is configured and every A is in private space). RFC
	// 6147 §5.1.4 — we treat the response as if no A records
	// existed. Fall back to the original NODATA.
	if !hasAAAAInList(answers) {
		Passthrough.WithLabelValues("a_excluded").Inc()
		return nil
	}

	out := new(dns.Msg)
	out.SetReply(w.req)
	out.RecursionAvailable = orig.RecursionAvailable
	out.Rcode = dns.RcodeSuccess
	out.Answer = answers

	// RFC 6147 §5.4 + §5.3.2: Authority and Additional sections
	// come from the final A response unmodified. §5.3.2 explicitly
	// forbids the DNS64 from rewriting any RR type other than the
	// AAAA-from-A synthesis above and CNAME/RRSIG handling — A
	// records elsewhere in the message MUST pass through verbatim.
	// The client's OPT (carrying DO/UDP-size/cookie state) is
	// taken from the original AAAA reply so downstream writers
	// see a well-formed EDNS frame.
	out.Ns = copyExtraNoOPT(aResp.Ns)
	out.Extra = appendOPTFrom(orig, copyExtraNoOPT(aResp.Extra))

	// RFC 6147 §5.5: the synthesised AAAA RRset is not signed.
	// Whatever AD we received from the validator on either the
	// AAAA or A response no longer holds end-to-end. Clear AD; if
	// the AAAA NODATA had been validated, attach EDE 4 so a
	// curious client sees the reason.
	out.AuthenticatedData = false
	if orig.AuthenticatedData {
		util.SetEDE(out, dns.ExtendedErrorCodeForgedAnswer, "DNS64 synthesis")
	}
	return out
}

// buildAResponseAsBasis implements RFC 6147 §5.1.6: when the
// secondary A query yielded no usable records (empty answer,
// NXDOMAIN, SERVFAIL, etc.), the A response — not the original
// AAAA reply — is the basis for what the client receives. We
// preserve the A response's RCODE and Authority/Additional
// sections but rewrite the question to AAAA so the client sees
// an answer addressed to its actual query. RFC 6147 §5.1.5
// requires any CNAME/DNAME chain that led the A query to its
// terminal name to remain in the Answer section so the client
// can see the rewriting trail (e.g. CNAME → NODATA where the A
// alias resolves but its target has no A record).
func (w *responseWriter) buildAResponseAsBasis(orig, aResp *dns.Msg) *dns.Msg {
	out := new(dns.Msg)
	out.SetReply(w.req)
	out.Rcode = aResp.Rcode
	out.RecursionAvailable = aResp.RecursionAvailable
	// CNAME/DNAME chain (if any) survives. A records would only
	// appear here if the A response actually had answers; in that
	// case we'd be on the synthesis path, not this one. splitChainAndA
	// drops everything else (including any stray AAAAs / RRSIGs)
	// to keep the response shape clean.
	chain, _ := splitChainAndA(aResp)
	if len(chain) > 0 {
		out.Answer = make([]dns.RR, len(chain))
		copy(out.Answer, chain)
	}
	// Authority (typically the SOA for negative caching) carries
	// forward unchanged per RFC 6147 §5.3.2.
	if len(aResp.Ns) > 0 {
		out.Ns = make([]dns.RR, len(aResp.Ns))
		copy(out.Ns, aResp.Ns)
	}
	out.Extra = appendOPTFrom(orig, copyExtraNoOPT(aResp.Extra))

	// AD on the A response was derived against an A question, not
	// the AAAA question we're answering. Clear it; if the original
	// AAAA reply had been validated, attach EDE 4 so the client
	// can see why we changed our mind.
	out.AuthenticatedData = false
	if orig.AuthenticatedData {
		util.SetEDE(out, dns.ExtendedErrorCodeForgedAnswer, "DNS64 used A response as basis")
	}
	return out
}

// copyExtraNoOPT returns a copy of rrs with any OPT records
// dropped. OPT is re-attached separately so the client's
// EDNS state is preserved exactly once.
func copyExtraNoOPT(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// appendOPTFrom prepends the OPT record (if any) from src onto
// the head of dst. Used to reattach the client's EDNS state to
// a synthesised response without losing other Extra records.
func appendOPTFrom(src *dns.Msg, dst []dns.RR) []dns.RR {
	for _, rr := range src.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			out := make([]dns.RR, 0, len(dst)+1)
			out = append(out, opt)
			out = append(out, dst...)
			return out
		}
	}
	return dst
}

func hasAAAAInList(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeAAAA {
			return true
		}
	}
	return false
}

// splitChainAndA pulls the CNAME / DNAME chain (in order) and A
// records out of resp.Answer. RFC 6147 §5.1.5 requires the chain
// to be carried into the synthesised response so the client can
// follow the rewriting trail. The resolver already orders Answer
// canonically, so iterating in slice order preserves the chain.
func splitChainAndA(resp *dns.Msg) ([]dns.RR, []*dns.A) {
	chain := make([]dns.RR, 0, len(resp.Answer))
	addrs := make([]*dns.A, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.CNAME, *dns.DNAME:
			chain = append(chain, v)
		case *dns.A:
			addrs = append(addrs, v)
		}
	}
	return chain, addrs
}

// isDNSSECFailure reports whether m looks like a recursive
// resolver's "validation failed / cannot validate" response:
// SERVFAIL with at least one DNSSEC-related Extended DNS Error
// attached. RFC 8914 covers two clusters of failure modes that
// DNS64 must surface to the client unchanged:
//
//   - codes 1, 2, 27: unsupported DNSKEY algorithm, unsupported
//     DS digest type, unsupported NSEC3 iterations — the
//     validator couldn't process the chain at all;
//   - codes 5-12: indeterminate, bogus, signature expired/not
//     yet valid, DNSKEY/RRSIG/NSEC missing, no zone key bit set
//     — the validator processed it and rejected.
//
// In either cluster, papering over the SERVFAIL with synthesised
// AAAAs would let a client reach a target whose AAAA the upstream
// said it could not vouch for. We require RcodeServerFailure as
// the gate so an EDE attached to a successful response (e.g. our
// own EDE 4 on synthesised answers) doesn't mistakenly bypass
// synthesis upstream.
func isDNSSECFailure(m *dns.Msg) bool {
	if m == nil || m.Rcode != dns.RcodeServerFailure {
		return false
	}
	opt := m.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		ede, ok := o.(*dns.EDNS0_EDE)
		if !ok {
			continue
		}
		switch ede.InfoCode {
		case dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm,
			dns.ExtendedErrorCodeUnsupportedDSDigestType,
			dns.ExtendedErrorCodeUnsupportedNSEC3IterValue,
			dns.ExtendedErrorCodeDNSSECIndeterminate,
			dns.ExtendedErrorCodeDNSBogus,
			dns.ExtendedErrorCodeSignatureExpired,
			dns.ExtendedErrorCodeSignatureNotYetValid,
			dns.ExtendedErrorCodeDNSKEYMissing,
			dns.ExtendedErrorCodeRRSIGsMissing,
			dns.ExtendedErrorCodeNoZoneKeyBitSet,
			dns.ExtendedErrorCodeNSECMissing:
			return true
		}
	}
	return false
}

// negativeAAAATTL returns the SOA-derived minimum negative TTL of
// the original AAAA response, or 0 if no SOA is present. RFC 2308
// — the negative TTL is min(SOA.MINIMUM, SOA.TTL).
func negativeAAAATTL(m *dns.Msg) uint32 {
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			ttl := soa.Hdr.Ttl
			if soa.Minttl > 0 && soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			return ttl
		}
	}
	return 0
}

// classifyQueryErr collapses queryer errors to a small label set so
// the metric cardinality stays bounded. Anything we don't recognise
// flows under "other".
func classifyQueryErr(err error) string {
	switch {
	case errors.Is(err, middleware.ErrNoResponse):
		return "no_response"
	case errors.Is(err, middleware.ErrMaxRecursion):
		return "max_recursion"
	case errors.Is(err, errQueryerNotWired):
		return "queryer_error"
	}
	return "other"
}
