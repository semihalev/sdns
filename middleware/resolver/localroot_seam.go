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
// No active verified copy — disabled, never transferred, or past its SOA
// expire — reports consulted=false and the walk proceeds to the real roots
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
		// The copy is an IN zone and every answer built from it — the
		// delegation key, the NSEC question, the SOA — is IN. Answering a
		// CHAOS or HESIOD question from it would pair the client's class
		// with another class's records, so those go to the real roots.
		return nil, false
	}
	qname := dns.CanonicalName(q.Name)
	tld := localroot.TLDOf(qname)
	if tld == "" {
		// The apex itself (. SOA/NS/DNSKEY): rare, and the real roots
		// answer it authoritatively; the copy stays out of it.
		return nil, false
	}
	cd := rs.req.CheckingDisabled

	if ref, ok := snap.Referral(tld); ok {
		if qname == tld && q.Qtype == dns.TypeDS {
			return r.localRootDSAnswer(rs, snap, tld, cd), true
		}
		if r.installLocalRootReferral(ctx, rs, snap, tld, ref, cd) {
			localroot.CountReferral()
			return nil, false
		}
		// A referral the walk cannot use (no glue at all): the real
		// roots resolve it the ordinary way.
		return nil, false
	}

	proof, ok := snap.Denial(qname)
	if !ok {
		return nil, false
	}

	// The proof must independently classify as this exact NXDOMAIN under
	// the strict RFC 8198 evaluator before anything is served from it: a
	// chain gap the covering search cannot see — an NSEC whose span does
	// not actually reach the name — must fall back to the real roots, not
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
	return r.localRootDenial(ctx, rs, snap, qname, proof, cd), true
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
	var minTTL uint32
	for _, nsRR := range ref.NS {
		host := dns.CanonicalName(nsRR.(*dns.NS).Ns)
		if minTTL == 0 || nsRR.Header().Ttl < minTTL {
			minTTL = nsRR.Header().Ttl
		}
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

	// The lease is the earlier of the NS TTL and the copy's own serving
	// horizon: nothing derived from the copy outlives the signatures and
	// SOA expire that made it trustworthy.
	deadline := time.Now().Add(time.Duration(minTTL) * time.Second)
	if until := snap.ValidUntil(); until.Before(deadline) {
		deadline = until
	}
	// The store returns whatever is live under the key — this call's entry,
	// or the one a racing walk published first — and the walk takes that
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
// for an unsigned delegation. The reply is built on the live request so
// the transaction ID and flags survive — this answer returns directly,
// without the normalization the exchange path would apply.
func (r *Resolver) localRootDSAnswer(rs *resolveState, snap *localroot.Snapshot, tld string, cd bool) *dns.Msg {
	ds, dsSig, nsec, nsecSig, ok := snap.DSAnswer(tld)

	resp := new(dns.Msg)
	resp.SetRcode(rs.req, dns.RcodeSuccess)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	// The handler clears RD before resolution and setTags restores it on
	// the way out; this answer returns early, so it restores its own.
	resp.RecursionDesired = true
	if !ok {
		// Unreachable behind a Referral hit, but never answer garbage.
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
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
	return resp
}

// localRootDenial synthesizes the NXDOMAIN a root server would return for a
// name under an absent TLD, from the copy's own signed proof, and marks the
// validated-denial provenance exactly as the live validation path does — the
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

	if cd {
		return resp
	}
	// The caller's evaluator gate already classified this exact proof as
	// the NXDOMAIN being served, so the provenance carries the aggressive
	// bit outright — an unclassifiable proof never reaches this builder.
	resp.AuthenticatedData = true
	middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
		Subject:    qname,
		Zone:       rootzone,
		Kind:       middleware.ValidatedNegativeProofNSEC,
		Aggressive: true,
	})
	return resp
}
