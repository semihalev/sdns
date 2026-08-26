package cache

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

const staleAnswerTTL = 30 * time.Second

type staleAliasChaseKeyType struct{}

var staleAliasChaseKey = &staleAliasChaseKeyType{}

type staleEntryResponse struct {
	msg      *dns.Msg
	until    time.Time
	boundKey uint64
}

func withStaleAliasChase(ctx context.Context) context.Context {
	return context.WithValue(ctx, staleAliasChaseKey, true)
}

func isStaleAliasChase(ctx context.Context) bool {
	active, _ := ctx.Value(staleAliasChaseKey).(bool)
	return active
}

// staleResponse applies the single RFC 8767 policy used by both failure
// seams. Every applicable scoped key and then the shared key is checked for a
// fresh entry before any stale answer is returned. Among stale candidates the
// most-specific eligible and complete scope wins, so stale retention cannot
// let an expired narrow scope shadow a fresh wider answer or cross audiences.
func (c *Cache) staleResponse(
	ctx context.Context,
	req *dns.Msg,
	requestCD bool,
	clientScope netip.Prefix,
) (*dns.Msg, *CacheEntry) {
	if c == nil || !c.config.ServeStale || req == nil || len(req.Question) != 1 {
		return nil, nil
	}

	now := time.Now()
	q := req.Question[0]
	candidates := make([]*CacheEntry, 0, 4)
	if clientScope.IsValid() {
		for bits := clientScope.Bits(); bits >= 1; bits-- {
			scope, err := clientScope.Addr().Prefix(bits)
			if err != nil {
				continue
			}
			want := CacheKey{Question: q, CD: requestCD, Scope: scope}
			entry, ok := c.store.LookupByKeyVerified(want.Hash(), want)
			if !ok {
				continue
			}
			if entry.remaining(now) > 0 {
				return nil, nil
			}
			candidates = append(candidates, entry)
		}
	}

	want := CacheKey{Question: q, CD: requestCD}
	entry, ok := c.store.lookupRetainedPositiveVerified(want.Hash(), want)
	if ok {
		if entry.remaining(now) > 0 {
			return nil, nil
		}
		candidates = append(candidates, entry)
	}

	// Freshness was checked across every applicable scope before any alias
	// chase is attempted. Now try stale candidates in specificity order; an
	// incomplete narrow alias that cannot be completed must not suppress a
	// usable wider candidate.
	for _, candidateEntry := range candidates {
		// Each candidate is judged on the clock it is actually reached at,
		// not the one the walk started on. Completing an earlier candidate's
		// alias can spend real seconds on a failing sub-resolution, and the
		// delegation lease is an absolute instant: reusing the opening
		// timestamp would let a candidate whose lease ran out during that
		// chase pass the ceiling check and be served after it expired, which
		// is the revival the ceiling exists to prevent.
		candidate := c.staleResponseFromEntry(candidateEntry, req, requestCD, time.Now())
		if candidate.msg == nil {
			continue
		}
		resp := c.completeStaleAlias(ctx, candidate, req)
		if resp != nil {
			return resp, candidateEntry
		}
	}
	return nil, nil
}

// writeStaleResponse is the single commit point for a retained answer. A
// stale response is still a cache answer, so an external query pays the same
// entry-local rate-limit token as an ordinary hit. Internal alias chases are
// exempt: charging their target leg would either double-charge one client
// question or leave the outer response with only a partial alias chain.
//
// handled is true both when the response was written and when the limiter
// refused it. The latter is deliberately terminal and silent, matching the
// ordinary cache-hit path instead of falling back to the SERVFAIL that made
// the retained answer eligible.
func (c *Cache) writeStaleResponse(
	ctx context.Context,
	w middleware.ResponseWriter,
	req *dns.Msg,
	requestCD bool,
	clientScope netip.Prefix,
	internal bool,
) (handled bool, err error) {
	resp, entry := c.staleResponse(ctx, req, requestCD, clientScope)
	if resp == nil {
		return false, nil
	}

	if !internal && !isStaleAliasChase(ctx) {
		if limiter := entry.GetRateLimiter(); limiter != nil && !limiter.Allow() {
			return true, nil
		}
	}

	boundRequestToStaleLifetime(ctx, entry, time.Now())
	staleAnswers.Inc()
	return true, w.WriteMsg(resp)
}

func (c *Cache) staleResponseFromEntry(
	entry *CacheEntry,
	req *dns.Msg,
	requestCD bool,
	now time.Time,
) staleEntryResponse {
	if entry == nil {
		return staleEntryResponse{}
	}

	ttlRemaining, leaseRemaining := entry.remainingBounds(now)
	if ttlRemaining > 0 {
		return staleEntryResponse{}
	}
	// A zero cut is explicitly unbounded. A real delegation lease is a
	// non-negotiable security ceiling: never revive an answer after it.
	if !entry.cutUntil.IsZero() && leaseRemaining <= 0 {
		return staleEntryResponse{}
	}
	if maxStale := c.config.ServeStaleMaxTTL; maxStale > 0 && -ttlRemaining > maxStale {
		return staleEntryResponse{}
	}

	resp := entry.storedMsg()
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 || hasZeroTTLRecord(resp) {
		return staleEntryResponse{}
	}

	hardUntil := now.Add(staleAnswerTTL)
	hardKey := uint64(0)
	if !entry.cutUntil.IsZero() && entry.cutUntil.Before(hardUntil) {
		hardUntil, hardKey = entry.cutUntil, entry.cutKey
	}
	// DNS TTLs have one-second granularity. Rounding a positive sub-second
	// lease up would outlive the delegation; rounding down would emit TTL 0,
	// which RFC 8767 section 4 forbids. Decline the stale candidate instead.
	responseTTL := hardUntil.Sub(now)
	if responseTTL < time.Second {
		return staleEntryResponse{}
	}

	originalRcode := resp.Rcode
	originalExtra := resp.Extra
	resp.SetReply(req)
	resp.Rcode = originalRcode
	resp.Extra = originalExtra
	resp.Id = req.Id
	resp.Authoritative = false
	resp.CheckingDisabled = requestCD

	setStaleTTLs(resp.Answer, responseTTL)
	setStaleTTLs(resp.Ns, responseTTL)
	setStaleTTLs(resp.Extra, responseTTL)

	// AD is meaningful only while every retained signature is still inside
	// its validity period. CD=1 always clears it, as on an ordinary hit.
	if requestCD || (resp.AuthenticatedData && !allSignaturesCurrent(resp, now)) {
		resp.AuthenticatedData = false
	}

	// OPT is hop-by-hop and was stripped at admission. Rebuild only the
	// capabilities needed for this response, then identify it with EDE 3.
	if reqOPT := req.IsEdns0(); reqOPT != nil {
		resp.SetEdns0(reqOPT.UDPSize(), reqOPT.Do())
		dnsutil.SetEDE(resp, dns.ExtendedErrorCodeStaleAnswer, "Stale Answer")
	}

	return staleEntryResponse{msg: resp, until: hardUntil, boundKey: hardKey}
}

// completeStaleAlias mirrors the ordinary Msg hit's alias completion. The
// chase runs with an isolated cut accumulator that still shares the request
// tree's work ledgers; only records actually merged into the stale answer
// contribute their lifetime. An incomplete result is rejected rather than
// returning a misleading NOERROR response containing only an alias.
func (c *Cache) completeStaleAlias(
	ctx context.Context,
	candidate staleEntryResponse,
	req *dns.Msg,
) *dns.Msg {
	resp := candidate.msg
	if !staleAliasNeedsCompletion(resp) {
		return resp
	}
	depth := cnameChaseDepth(ctx)
	if depth >= maxCnameChaseDepth {
		return nil
	}

	aliasLifetime := time.Until(candidate.until)
	if aliasLifetime < time.Second {
		return nil
	}
	// Resolver-produced DNAME answers normally carry the synthesized CNAME.
	// Preserve that behavior for a retained DNAME-only body so the existing
	// CNAME chase can resolve its target instead of returning a partial reply.
	if !hasCNAME(resp) {
		if target := dnsutil.DnameTarget(resp); target != "" {
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeCNAME,
					Class:  req.Question[0].Qclass,
					Ttl:    uint32(aliasLifetime / time.Second), //nolint:gosec // capped at 30s
				},
				Target: target,
			})
		}
	}

	var chaseMeta *middleware.ResponseMeta
	if parent := middleware.ResponseMetaFrom(ctx); parent != nil {
		chaseMeta = parent.ForkCut()
	} else {
		chaseMeta = new(middleware.ResponseMeta)
	}
	chaseMeta.BoundCutFor(candidate.until, candidate.boundKey)
	chaseCtx := middleware.WithResponseMeta(ctx, chaseMeta)
	chaseCtx = withStaleAliasChase(chaseCtx)
	resp = c.additionalAnswer(withCnameChaseDepth(chaseCtx, depth+1), resp)
	if resp == nil || resp.Rcode != dns.RcodeSuccess ||
		staleAliasNeedsCompletion(resp) || hasZeroTTLRecord(resp) {
		return nil
	}

	// additionalAnswer preserves the TTLs of fresh terminal records. Fold
	// their shortest advertised lifetime together with every exact lineage
	// bound accumulated by the chase, then give the whole composed response
	// one non-zero TTL that cannot outlive any of its parts.
	hardUntil, hardKey := chaseMeta.Cut()
	if ttl, found := minimumRecordTTL(resp); found {
		ttlUntil := time.Now().Add(time.Duration(ttl) * time.Second)
		if hardUntil.IsZero() || ttlUntil.Before(hardUntil) {
			hardUntil, hardKey = ttlUntil, 0
		}
	}
	remaining := time.Until(hardUntil)
	if hardUntil.IsZero() || remaining < time.Second {
		return nil
	}
	setStaleTTLs(resp.Answer, remaining)
	setStaleTTLs(resp.Ns, remaining)
	setStaleTTLs(resp.Extra, remaining)
	if outer := middleware.ResponseMetaFrom(ctx); outer != nil {
		outer.BoundCutFor(hardUntil, hardKey)
	}
	return resp
}

func staleAliasNeedsCompletion(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) != 1 || msg.Rcode == dns.RcodeNameError {
		return false
	}
	q := msg.Question[0]
	if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeDS || respCnameHasType(msg, q.Qtype) {
		return false
	}
	return hasCNAME(msg) || dnsutil.DnameTarget(msg) != ""
}

func hasCNAME(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME {
			return true
		}
	}
	return false
}

func hasZeroTTLRecord(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl == 0 {
				return true
			}
		}
	}
	return false
}

func minimumRecordTTL(msg *dns.Msg) (uint32, bool) {
	var minimum uint32
	found := false
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if !found || rr.Header().Ttl < minimum {
				minimum, found = rr.Header().Ttl, true
			}
		}
	}
	return minimum, found
}

func (e *CacheEntry) hasOriginalZeroTTL() bool {
	return hasZeroTTLRecord(e.storedMsg())
}

func setStaleTTLs(records []dns.RR, ttl time.Duration) {
	seconds := uint32(max(ttl/time.Second, 0)) //nolint:gosec // capped at 30 seconds
	for _, rr := range records {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = seconds
		}
	}
}

func allSignaturesCurrent(msg *dns.Msg, now time.Time) bool {
	found := false
	check := func(records []dns.RR) bool {
		for _, rr := range records {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}
			found = true
			if !sig.ValidityPeriod(now) {
				return false
			}
		}
		return true
	}
	return check(msg.Answer) && check(msg.Ns) && check(msg.Extra) && found
}

// boundRequestToStaleLifetime lets an internal CNAME/DNAME consumer derive
// from a stale answer for at most the advertised 30 seconds, and never beyond
// the original delegation lease. It deliberately does not reuse the expired
// answer TTL as a bound: that would make the just-served response instantly
// unusable by the enclosing cache layer.
func boundRequestToStaleLifetime(ctx context.Context, entry *CacheEntry, now time.Time) {
	if entry == nil {
		return
	}
	hardUntil := now.Add(staleAnswerTTL)
	hardKey := uint64(0)
	if !entry.cutUntil.IsZero() && entry.cutUntil.Before(hardUntil) {
		hardUntil, hardKey = entry.cutUntil, entry.cutKey
	}
	if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
		meta.BoundCutFor(hardUntil, hardKey)
	}
}
