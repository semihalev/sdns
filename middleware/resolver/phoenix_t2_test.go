package resolver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
)

// TestPhoenixT2_NestedDelegationInheritsAncestorDeadline is the Phase-1a
// regression for the Phoenix downward-delegation (T2) variant of
// GHSA-mqfw-f48p-2vc8.
//
// Topology (one loopback listener per zone; TEST-NET-1 glue remapped to those
// listeners via r.resolveTarget, since loopback glue is rejected and the UDP
// fast path uses a pre-parsed address):
//
//	root         delegates ghostzone.        NS TTL 3s   (the SHORT ancestor cut)
//	ghostzone.   delegates sub.ghostzone.    NS TTL 12h  (a LONG nested referral)
//	sub.ghostzone. answers www.sub.ghostzone. A
//
// The nested sub.ghostzone. delegation must NOT be cached for 12h: it inherits
// the 3s ghostzone cut. We assert the nested ExpiresAt is never after the
// ancestor's — the strong, deterministic form of the invariant.
func TestPhoenixT2_NestedDelegationInheritsAncestorDeadline(t *testing.T) {
	var ignore int64

	// Generic authoritative behaviour for DS/AAAA so DNSSEC-off (CD=1) chain
	// walks and background v6 lookups don't error the resolution.
	softNeg := func(zone string) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		m.Ns = []dns.RR{mustRR(t, zone+" 30 IN SOA ns."+zone+" hostmaster."+zone+" 1 30 30 30 30")}
		return m
	}

	// sub.ghostzone. — authoritative leaf.
	subAddr, stopSub := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) == "www.sub.ghostzone." {
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, "www.sub.ghostzone. 300 IN A 192.0.2.55")}
			return m
		}
		return softNeg("sub.ghostzone.")
	})
	defer stopSub()

	// ghostzone. — delegates sub.ghostzone. with a LONG (12h) NS TTL.
	ghostAddr, stopGhost := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeDS {
			return softNeg("ghostzone.")
		}
		if dns.IsSubDomain("sub.ghostzone.", dns.CanonicalName(q.Name)) || dns.CanonicalName(q.Name) == "sub.ghostzone." {
			m := &dns.Msg{} // referral (AA=false)
			m.Ns = []dns.RR{mustRR(t, "sub.ghostzone. 43200 IN NS ns.sub.ghostzone.")}
			m.Extra = []dns.RR{mustRR(t, "ns.sub.ghostzone. 43200 IN A 192.0.2.13")}
			return m
		}
		return softNeg("ghostzone.")
	})
	defer stopGhost()

	// root — delegates ghostzone. with a SHORT (3s) NS TTL.
	rootAddr, stopRoot := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if dns.CanonicalName(q.Name) == "." && q.Qtype == dns.TypeNS {
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, ". 3600 IN NS a.root.")}
			return m
		}
		if q.Qtype == dns.TypeDS {
			return softNeg(".")
		}
		if dns.IsSubDomain("ghostzone.", dns.CanonicalName(q.Name)) || dns.CanonicalName(q.Name) == "ghostzone." {
			m := &dns.Msg{} // referral
			m.Ns = []dns.RR{mustRR(t, "ghostzone. 3 IN NS ns.ghostzone.")}
			m.Extra = []dns.RR{mustRR(t, "ns.ghostzone. 3 IN A 192.0.2.11")}
			return m
		}
		return softNeg(".")
	})
	defer stopRoot()

	// Remap TEST-NET-1 glue to the loopback listeners.
	remap := map[string]string{
		"192.0.2.11:53": ghostAddr,
		"192.0.2.13:53": subAddr,
	}
	mapper := func(addr string) string {
		if to, ok := remap[addr]; ok {
			return to
		}
		return addr
	}

	// Build the resolver with the root pointed at the mock via config (no
	// post-construction write to r.rootServers → no priming race), then
	// install the mapper atomically.
	base := makeTestConfig()
	cfg := *base
	cfg.RootServers = []string{rootAddr}
	cfg.Root6Servers = nil
	// DNSSEC off keeps this hermetic: with glue provided there are then no
	// DNSKEY/DS/NS-address sub-lookups that could escape resolveTarget and
	// hit the real network. (The advisory PoC likewise runs dnssec=off; the
	// inheritance under test is orthogonal to validation.)
	cfg.DNSSEC = "off"
	r := newWiredTestResolver(&cfg)
	r.resolveTarget.Store(&mapper)

	req := new(dns.Msg)
	req.SetQuestion("www.sub.ghostzone.", dns.TypeA)
	req.CheckingDisabled = true
	ctx := context.WithValue(context.Background(), contextKeyRequestID, req.Id)

	resp, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, true, nil)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("expected a positive answer, got rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}

	// Inspect the cached cuts (CD=1 bucket).
	ghostDeleg, gerr := r.delegations.Get(cache.Key(dns.Question{Name: "ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true))
	if gerr != nil {
		t.Fatalf("ghostzone. delegation not cached: %v", gerr)
	}
	subDeleg, serr := r.delegations.Get(cache.Key(dns.Question{Name: "sub.ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true))
	if serr != nil {
		t.Fatalf("sub.ghostzone. delegation not cached: %v", serr)
	}

	t.Logf("ghostzone ExpiresAt=%s  sub ExpiresAt=%s  (Δ=%s)",
		ghostDeleg.ExpiresAt, subDeleg.ExpiresAt, subDeleg.ExpiresAt.Sub(ghostDeleg.ExpiresAt))

	// The nested cut must never outlive its ancestor, despite the 12h
	// referral. In this topology the inherited deadline is stored verbatim
	// (SetUntil, no re-anchoring), so the two must be EXACTLY equal — any
	// drift means the deadline was recomputed or the wrong minimum won.
	if !subDeleg.ExpiresAt.Equal(ghostDeleg.ExpiresAt) {
		t.Fatalf("Phoenix T2: nested sub.ghostzone. cut (ExpiresAt=%s) != ancestor ghostzone. "+
			"(ExpiresAt=%s) — the inherited deadline was re-anchored or the 12h child referral won",
			subDeleg.ExpiresAt, ghostDeleg.ExpiresAt)
	}
	// And it must be far below the 12h it advertised.
	if subDeleg.ExpiresAt.After(time.Now().Add(time.Hour)) {
		t.Fatalf("Phoenix T2: nested cut cached for far longer than the ancestor lease: ExpiresAt=%s", subDeleg.ExpiresAt)
	}
}

// TestPhoenixT2_CachedHitCarriesCurrentReferralDeadline covers the cached-hit
// branch of processDelegation: a referral is received but the delegation is
// ALREADY in the cache (a concurrent resolution inserted it while this one was
// in flight). The freshly observed referral deadline must still bound the
// descent — "the shortest applicable cut always wins" — rather than being
// discarded in favour of the (longer) cached lease.
//
// The race is made deterministic by seeding a 2h ghostzone. entry from inside
// the root mock handler: searchCache has already run (cache was empty), so the
// insert lands exactly between the root query and processDelegation's cache
// check. The root referral carries a 3s NS TTL, so:
//
//	effective deadline = min(2h cached, 3s current referral) = 3s
//
// and the nested sub.ghostzone. delegation inserted during the descent must
// expire within seconds, not hours.
func TestPhoenixT2_CachedHitCarriesCurrentReferralDeadline(t *testing.T) {
	var ignore int64
	var rPtr atomic.Pointer[Resolver]

	softNeg := func(zone string) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		m.Ns = []dns.RR{mustRR(t, zone+" 30 IN SOA ns."+zone+" hostmaster."+zone+" 1 30 30 30 30")}
		return m
	}

	// sub.ghostzone. — authoritative leaf.
	subAddr, stopSub := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) == "www.sub.ghostzone." {
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, "www.sub.ghostzone. 300 IN A 192.0.2.55")}
			return m
		}
		return softNeg("sub.ghostzone.")
	})
	defer stopSub()

	// ghostzone. — delegates sub.ghostzone. with a LONG (12h) NS TTL.
	ghostAddr, stopGhost := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeDS {
			return softNeg("ghostzone.")
		}
		if dns.IsSubDomain("sub.ghostzone.", dns.CanonicalName(q.Name)) || dns.CanonicalName(q.Name) == "sub.ghostzone." {
			m := &dns.Msg{}
			m.Ns = []dns.RR{mustRR(t, "sub.ghostzone. 43200 IN NS ns.sub.ghostzone.")}
			m.Extra = []dns.RR{mustRR(t, "ns.sub.ghostzone. 43200 IN A 192.0.2.13")}
			return m
		}
		return softNeg("ghostzone.")
	})
	defer stopGhost()

	ghostKey := cache.Key(dns.Question{Name: "ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true)

	// root — delegates ghostzone. with a SHORT (3s) NS TTL, and seeds the
	// delegation cache with a LONG (2h) ghostzone. entry while doing so.
	rootAddr, stopRoot := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if dns.CanonicalName(q.Name) == "." && q.Qtype == dns.TypeNS {
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, ". 3600 IN NS a.root.")}
			return m
		}
		if q.Qtype == dns.TypeDS {
			return softNeg(".")
		}
		if dns.IsSubDomain("ghostzone.", dns.CanonicalName(q.Name)) || dns.CanonicalName(q.Name) == "ghostzone." {
			// The concurrent insert: while our referral is on the wire, another
			// resolution finishes and caches ghostzone. for 2h.
			if r := rPtr.Load(); r != nil {
				if _, err := r.delegations.Get(ghostKey); err != nil {
					seeded := &authority.Servers{
						Zone:            "ghostzone.",
						CheckingDisable: true,
						List:            []*authority.Server{authority.NewServer("192.0.2.11:53", authority.IPv4)},
					}
					r.delegations.Set(ghostKey, nil, seeded, 2*time.Hour)
				}
			}
			m := &dns.Msg{}
			m.Ns = []dns.RR{mustRR(t, "ghostzone. 3 IN NS ns.ghostzone.")}
			m.Extra = []dns.RR{mustRR(t, "ns.ghostzone. 3 IN A 192.0.2.11")}
			return m
		}
		return softNeg(".")
	})
	defer stopRoot()

	remap := map[string]string{
		"192.0.2.11:53": ghostAddr,
		"192.0.2.13:53": subAddr,
	}
	mapper := func(addr string) string {
		if to, ok := remap[addr]; ok {
			return to
		}
		return addr
	}

	base := makeTestConfig()
	cfg := *base
	cfg.RootServers = []string{rootAddr}
	cfg.Root6Servers = nil
	cfg.DNSSEC = "off"
	r := newWiredTestResolver(&cfg)
	r.resolveTarget.Store(&mapper)
	rPtr.Store(r)

	req := new(dns.Msg)
	req.SetQuestion("www.sub.ghostzone.", dns.TypeA)
	req.CheckingDisabled = true
	ctx := context.WithValue(context.Background(), contextKeyRequestID, req.Id)

	resp, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, true, nil)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("expected a positive answer, got rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}

	// The cached branch must actually have been taken: the seeded 2h entry
	// survives untouched (a fresh insert would have replaced it with ~3s).
	ghostDeleg, gerr := r.delegations.Get(ghostKey)
	if gerr != nil {
		t.Fatalf("ghostzone. delegation not cached: %v", gerr)
	}
	if ghostDeleg.ExpiresAt.Before(time.Now().Add(time.Hour)) {
		t.Fatalf("test harness: seeded 2h ghostzone. entry was replaced (ExpiresAt=%s) — "+
			"the cached-hit branch was not exercised", ghostDeleg.ExpiresAt)
	}

	// The descent below the cached hit must carry the CURRENT 3s referral
	// deadline, not the 2h cached lease.
	subDeleg, serr := r.delegations.Get(cache.Key(dns.Question{Name: "sub.ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true))
	if serr != nil {
		t.Fatalf("sub.ghostzone. delegation not cached: %v", serr)
	}

	t.Logf("seeded ghostzone ExpiresAt=%s  sub ExpiresAt=%s", ghostDeleg.ExpiresAt, subDeleg.ExpiresAt)

	if subDeleg.ExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("Phoenix T2 cached-hit: nested sub.ghostzone. cut cached until %s — the freshly "+
			"observed 3s referral deadline was discarded in favour of the 2h cached lease",
			subDeleg.ExpiresAt)
	}
}
