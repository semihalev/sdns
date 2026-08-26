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

// staleResponse applies the single RFC 8767 policy used by both failure
// seams. Every applicable scoped key and then the shared key is checked for a
// fresh entry before any stale answer is returned. Among stale candidates the
// most-specific eligible scope wins, so stale retention cannot let an expired
// narrow scope shadow a fresh wider answer or cross ECS audiences.
func (c *Cache) staleResponse(
	req *dns.Msg,
	requestCD bool,
	clientScope netip.Prefix,
) (*dns.Msg, *CacheEntry) {
	if c == nil || !c.config.ServeStale || req == nil || len(req.Question) != 1 {
		return nil, nil
	}

	now := time.Now()
	q := req.Question[0]
	var (
		stale      *dns.Msg
		staleEntry *CacheEntry
	)
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
			if stale == nil {
				if resp := c.staleResponseFromEntry(entry, req, requestCD, now); resp != nil {
					stale, staleEntry = resp, entry
				}
			}
		}
	}

	want := CacheKey{Question: q, CD: requestCD}
	entry, ok := c.store.lookupRetainedPositiveVerified(want.Hash(), want)
	if ok {
		if entry.remaining(now) > 0 {
			return nil, nil
		}
		if stale == nil {
			if resp := c.staleResponseFromEntry(entry, req, requestCD, now); resp != nil {
				stale, staleEntry = resp, entry
			}
		}
	}
	return stale, staleEntry
}

func (c *Cache) staleResponseFromEntry(
	entry *CacheEntry,
	req *dns.Msg,
	requestCD bool,
	now time.Time,
) *dns.Msg {
	if entry == nil {
		return nil
	}

	ttlRemaining, leaseRemaining := entry.remainingBounds(now)
	if ttlRemaining > 0 {
		return nil
	}
	// A zero cut is explicitly unbounded. A real delegation lease is a
	// non-negotiable security ceiling: never revive an answer after it.
	if !entry.cutUntil.IsZero() && leaseRemaining <= 0 {
		return nil
	}
	if maxStale := c.config.ServeStaleMaxTTL; maxStale > 0 && -ttlRemaining > maxStale {
		return nil
	}

	resp := entry.storedMsg()
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return nil
	}

	originalRcode := resp.Rcode
	originalExtra := resp.Extra
	resp.SetReply(req)
	resp.Rcode = originalRcode
	resp.Extra = originalExtra
	resp.Id = req.Id
	resp.Authoritative = false
	resp.CheckingDisabled = requestCD

	responseTTL := staleAnswerTTL
	if !entry.cutUntil.IsZero() && leaseRemaining < responseTTL {
		// The ordinary response path never advertises a TTL beyond the
		// delegation lease. Preserve that ghost-domain guarantee in the
		// narrow final window where less than RFC 8767's 30 seconds remain.
		responseTTL = leaseRemaining
	}
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

	return resp
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
