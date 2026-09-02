package resolver

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
	"github.com/semihalev/sdns/middleware/resolver/localroot"
)

// consultLocalRoot is the one seam the local root copy (RFC 8806) has into
// the walk: the root step, where nothing deeper is cached and the next
// query would otherwise go to a real root server. Three shapes come back
// from the verified copy:
//
//   - the TLD exists: its delegation is installed exactly as a root
//     referral would have installed it, and the walk continues without a
//     root query (answer=nil, handled=false, servers updated);
//   - the query is the TLD's DS: the parent-side answer is served straight
//     from the copy (handled=true);
//   - the TLD does not exist: the zone's own signed NSEC proof synthesizes
//     the NXDOMAIN (handled=true).
//
// No active verified copy, disabled, never transferred, or past its SOA
// expire, reports consulted=false and the walk proceeds to the real roots
// unchanged.
func (r *Resolver) consultLocalRoot(ctx context.Context, rs *resolveState) (answer *dns.Msg, handled bool) {
	mgr := r.localRoot.Load()
	if mgr == nil {
		return nil, false
	}
	snap := mgr.Active()
	if snap == nil {
		localroot.CountFallback()
		return nil, false
	}

	q := rs.req.Question[0]
	if q.Qclass != dns.ClassINET {
		// The copy is an IN zone and every answer built from it, the
		// delegation key, the NSEC question, the SOA, is IN. Answering a
		// CHAOS or HESIOD question from it would pair the client's class
		// with another class's records, so those go to the real roots.
		localroot.CountFallback()
		return nil, false
	}
	qname := dns.CanonicalName(q.Name)
	cd := rs.req.CheckingDisabled
	tld := localroot.TLDOf(qname)
	if tld == "" {
		// The root's own records, NS, SOA, DNSKEY, are in the copy, and
		// asking a root server for an answer already held here is the one
		// thing this package exists to stop doing.
		answer, handled := r.localRootApexAnswer(rs, snap, q.Qtype, cd)
		if handled {
			noteCopyHorizon(ctx, snap)
		}
		return answer, handled
	}

	if ref, ok := snap.Referral(tld); ok {
		if qname == tld && q.Qtype == dns.TypeDS {
			// A copy that cannot prove the answer does not answer: the
			// real roots do. Handing back a SERVFAIL here would turn a
			// gap in the copy into a client-visible failure, which is
			// the opposite of what the fallback exists for.
			answer := r.localRootDSAnswer(rs, snap, tld, cd)
			if answer == nil {
				localroot.CountFallback()
				return nil, false
			}
			noteCopyHorizon(ctx, snap)
			return answer, true
		}
		if r.installLocalRootReferral(ctx, rs, snap, tld, ref, cd) {
			localroot.CountReferral()
			return nil, false
		}
		// A referral the walk cannot use (no glue at all): the real
		// roots resolve it the ordinary way.
		localroot.CountFallback()
		return nil, false
	}

	proof, ok := snap.Denial(qname)
	if !ok {
		// The TLD is absent from the copy and the copy cannot prove it
		// absent either. That is a gap in the chain worth seeing, not a
		// silent walk to the roots.
		localroot.CountFallback()
		return nil, false
	}

	// The proof must independently classify as this exact NXDOMAIN under
	// the strict RFC 8198 evaluator before anything is served from it: a
	// chain gap the covering search cannot see, an NSEC whose span does
	// not actually reach the name, must fall back to the real roots, not
	// become an authenticated denial.
	var nsecSet []dns.RR
	for _, rr := range proof {
		if rr.Header().Rrtype == dns.TypeNSEC {
			nsecSet = append(nsecSet, rr)
		}
	}
	evalQ := dns.Question{Name: qname, Qtype: q.Qtype, Qclass: dns.ClassINET}
	result, err := dnssec.EvaluateAggressiveNSEC(evalQ, rootzone, nsecSet)
	if err != nil || result.Rcode != dns.RcodeNameError {
		localroot.CountFallback()
		return nil, false
	}

	localroot.CountDenial()
	noteCopyHorizon(ctx, snap)
	return r.localRootDenial(ctx, rs, snap, qname, proof, cd), true
}

// noteCopyHorizon binds the request tree to the copy's serving horizon, so
// the answer cache cannot outlive the copy it was built from.
//
// Bounding the wire TTLs is not enough on its own. The cache applies a
// five-second floor to any TTL below it (dnsutil.MinCacheTTL), so an answer
// taken in the last seconds of the horizon, TTL bounded to zero or one,
// would still be admitted for five, and served from cache after Active() had
// already withdrawn the copy. RFC 8806 asks for an immediate return to the
// real root servers at that instant, not a few seconds later.
//
// The referral path bounds the tree the same way, through the delegation
// lease. The key is zero because this deadline is an exact instant rather
// than one a delegation entry supplied, the same shape the cache's own
// boundRequestTo uses.
func noteCopyHorizon(ctx context.Context, snap *localroot.Snapshot) {
	noteCut(ctx, snap.ValidUntil(), 0)
}

// boundToCopy finishes a response built from the local copy: every record is
// replaced by a copy of itself whose TTL is bounded by the copy's serving
// horizon. Both halves are requirements, not tidiness:
//
//   - RFC 4035 §5.3.3 caps an authenticated RRset's TTL at the remaining life
//     of the signature that authenticates it. The horizon is the earliest
//     RRSIG expiration anywhere in the zone, so bounding by it is at least as
//     strict as the rule demands for every RRset served here. It is the same
//     third bound installLocalRootReferral already applies to a delegation
//     lease, applied now to the answers the copy serves directly, without
//     it, an answer taken shortly before the horizon can advertise days of
//     TTL for records whose signatures lapse within the hour.
//   - The Snapshot is immutable and read by every goroutine serving from the
//     copy. Handing out its records would let any downstream TTL rewrite,
//     clampTTLsToCut is one, and it writes in place, reach into the live
//     copy and silently change what every later answer says, from an
//     arbitrary request goroutine.
//
// A horizon less than a second away yields TTL 0, which is the honest answer:
// serve it, and tell the client not to hold it.
func boundToCopy(resp *dns.Msg, snap *localroot.Snapshot) {
	ttl := uint32(max(time.Until(snap.ValidUntil()), 0) / time.Second) //nolint:gosec // bounded above by the SOA expire interval.
	resp.Answer = copyBoundedTTL(resp.Answer, ttl)
	resp.Ns = copyBoundedTTL(resp.Ns, ttl)
	// Extra carries the priming glue; the OPT record is attached further
	// down the writer stack, well after this.
	resp.Extra = copyBoundedTTL(resp.Extra, ttl)
}

// copyBoundedTTL replaces each record in rrs with a copy capped at ttl. The
// slice itself belongs to the caller's freshly built response, so it is
// rewritten in place; the records do not.
func copyBoundedTTL(rrs []dns.RR, ttl uint32) []dns.RR {
	for i, rr := range rrs {
		c := dns.Copy(rr)
		if c.Header().Ttl > ttl {
			c.Header().Ttl = ttl
		}
		rrs[i] = c
	}
	return rrs
}

// localRootApexAnswer serves a question asked at the root's own name from
// the copy: the signed RRset when the apex holds the type, the apex NSEC as
// the NODATA proof when it does not. A copy that can evidence neither
// answers nothing and the walk goes to the real roots.
//
// This includes DNSKEY, which the RFC 5011 anchor refresh also asks for, so
// that query is answered from the copy too. That is sound and deliberate:
// the copy's DNSKEY RRset is the published one, transferred within the
// refresh interval and verified under an anchor-matched key before
// anything was built from it, a faithful observation of the zone, against
// a hold-down measured in weeks. It is also fail-safe in the direction that
// matters: a rollover the current anchors can no longer verify leaves no
// copy at all, so the refresh falls back to querying the roots live, which
// is exactly when it needs to.
func (r *Resolver) localRootApexAnswer(
	rs *resolveState,
	snap *localroot.Snapshot,
	qtype uint16,
	cd bool,
) (*dns.Msg, bool) {
	rrs, sigs, nsec, nsecSig, ok := snap.ApexAnswer(qtype)
	if !ok {
		localroot.CountFallback()
		return nil, false
	}

	resp := new(dns.Msg)
	resp.SetRcode(rs.req, dns.RcodeSuccess)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	// The handler clears RD before resolution and setTags restores it on
	// the way out; this answer returns early, so it restores its own.
	resp.RecursionDesired = true

	if len(rrs) > 0 {
		resp.Answer = append(resp.Answer, rrs...)
		resp.Answer = append(resp.Answer, sigs...)
		if qtype == dns.TypeNS {
			// A root server answers ". NS" with the addresses of the servers
			// it names (RFC 9609), and the copy holds them as glue. Without
			// them this answer names thirteen servers and gives no way to
			// reach any of them, which is also what the resolver's own
			// 12-hourly priming reads, so it would find no addresses and
			// leave its root server list unrefreshed.
			resp.Extra = append(resp.Extra, snap.ApexGlue()...)
		}
	} else {
		soa, soaSig := snap.SOA()
		resp.Ns = append(resp.Ns, soa)
		resp.Ns = append(resp.Ns, soaSig...)
		resp.Ns = append(resp.Ns, nsec...)
		resp.Ns = append(resp.Ns, nsecSig...)
	}
	if !cd {
		resp.AuthenticatedData = true
	}
	boundToCopy(resp, snap)
	localroot.CountApex()
	return resp, true
}

// installLocalRootReferral stores the TLD's delegation as a root referral
// would have and points the walk at it. The delegation entry persists in
// the delegations cache so upstream RTT evidence accumulates on a stable
// Servers identity across queries.
func (r *Resolver) installLocalRootReferral(
	ctx context.Context,
	rs *resolveState,
	snap *localroot.Snapshot,
	tld string,
	ref localroot.Referral,
	cd bool,
) bool {
	key := cache.Key(dns.Question{Name: tld, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, cd)

	servers := &authority.Servers{Zone: tld}
	for _, nsRR := range ref.NS {
		host := dns.CanonicalName(nsRR.(*dns.NS).Ns)
		for _, glue := range ref.Glue[host] {
			switch g := glue.(type) {
			case *dns.A:
				servers.List = append(servers.List, authority.NewServer(g.A.String()+":53", authority.IPv4))
			case *dns.AAAA:
				if r.cfg.IPv6Access {
					servers.List = append(servers.List, authority.NewServer("["+g.AAAA.String()+"]:53", authority.IPv6))
				}
			}
		}
	}
	if len(servers.List) == 0 {
		return false
	}

	// The lease is the earliest of three bounds, all measured from one
	// observation instant so scheduling delay cannot re-inflate any of
	// them (GHSA-mqfw-f48p-2vc8):
	//
	//   - the NS TTL, which is how long the delegation itself may be held;
	//   - the delegation's security evidence, the DS RRset's TTL when
	//     signed, the denying NSEC's when not, exactly as
	//     processDelegation bounds a referral learned off the wire, so a
	//     withdrawn DS cannot be trusted for the NS set's longer life;
	//   - the copy's own serving horizon, since nothing derived from it may
	//     outlive the signatures and SOA expire that made it trustworthy.
	//
	// A delegation whose security status the copy cannot evidence reports a
	// zero SecurityTTL, which drives the lease into the past: the store
	// refuses it and the walk falls back rather than asserting an unproven
	// status.
	observedAt := time.Now()
	deadline := observedAt.Add(time.Duration(ref.NSTTL) * time.Second)
	if security := observedAt.Add(time.Duration(ref.SecurityTTL) * time.Second); security.Before(deadline) {
		deadline = security
	}
	if until := snap.ValidUntil(); until.Before(deadline) {
		deadline = until
	}
	// The store returns whatever is live under the key, this call's entry,
	// or the one a racing walk published first, and the walk takes that
	// delegation whole. Servers, DS set and lease belong to one entry:
	// pairing a winner's servers with this call's DS chain would validate
	// one delegation's answers against another's keys, so there is no
	// separate readback to get wrong.
	live := r.delegations.SetUntilIfAbsent(key, ref.DS, servers, deadline)
	if live == nil {
		return false
	}

	rs.servers = live.Servers
	rs.parentDS = live.DSSet
	rs.level = 1
	rs.isRoot = false
	rs.cutDeadline, rs.cutKey = minCut(rs.cutDeadline, rs.cutKey, live.ExpiresAt, key)
	noteCut(ctx, rs.cutDeadline, rs.cutKey)
	return true
}

// localRootDSAnswer serves the parent-side DS question for a TLD from the
// verified copy: the signed DS set, or the exact-owner NSEC NODATA proof
// for an unsigned delegation. It returns nil when the copy holds no proof
// of either, the caller falls back to the real roots rather than inventing
// a failure. The reply is built on the live request so the transaction ID
// and flags survive, since this answer returns directly, without the
// normalization the exchange path would apply.
func (r *Resolver) localRootDSAnswer(rs *resolveState, snap *localroot.Snapshot, tld string, cd bool) *dns.Msg {
	ds, dsSig, nsec, nsecSig, ok := snap.DSAnswer(tld)
	if !ok {
		return nil
	}

	resp := new(dns.Msg)
	resp.SetRcode(rs.req, dns.RcodeSuccess)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	// The handler clears RD before resolution and setTags restores it on
	// the way out; this answer returns early, so it restores its own.
	resp.RecursionDesired = true
	localroot.CountDS()
	if len(ds) > 0 {
		resp.Answer = append(resp.Answer, ds...)
		resp.Answer = append(resp.Answer, dsSig...)
	} else {
		soa, soaSig := snap.SOA()
		resp.Ns = append(resp.Ns, soa)
		resp.Ns = append(resp.Ns, soaSig...)
		resp.Ns = append(resp.Ns, nsec...)
		resp.Ns = append(resp.Ns, nsecSig...)
	}
	if !cd {
		resp.AuthenticatedData = true
	}
	boundToCopy(resp, snap)
	return resp
}

// localRootDenial synthesizes the NXDOMAIN a root server would return for a
// name under an absent TLD, from the copy's own signed proof, and marks the
// validated-denial provenance exactly as the live validation path does, the
// RFC 8020 cut and RFC 8198 stores fill from it through their normal seams.
func (r *Resolver) localRootDenial(
	ctx context.Context,
	rs *resolveState,
	snap *localroot.Snapshot,
	qname string,
	proof []dns.RR,
	cd bool,
) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(rs.req, dns.RcodeNameError)
	resp.RecursionAvailable = true
	// As above: the early return misses setTags, so RD is restored here.
	resp.RecursionDesired = true

	soa, soaSig := snap.SOA()
	resp.Ns = append(resp.Ns, soa)
	resp.Ns = append(resp.Ns, soaSig...)
	resp.Ns = append(resp.Ns, proof...)
	// Before the provenance mark, never after: the fingerprint seals the
	// authority section's TTLs, so a rewrite afterwards would disqualify the
	// proof at the admission gate it exists to pass.
	boundToCopy(resp, snap)

	if cd {
		return resp
	}
	// The caller's evaluator gate already classified this exact proof as
	// the NXDOMAIN being served, so the provenance carries the aggressive
	// bit outright, an unclassifiable proof never reaches this builder.
	resp.AuthenticatedData = true
	middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
		Subject:    qname,
		Zone:       rootzone,
		Kind:       middleware.ValidatedNegativeProofNSEC,
		Aggressive: true,
	})
	return resp
}
