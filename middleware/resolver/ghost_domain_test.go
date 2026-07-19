package resolver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
)

// startMockAuth starts a UDP authoritative server on a random loopback port
// whose answers are produced by handle. It returns the ip:port and a cleanup
// func, and increments counter for every request received.
func startMockAuth(t *testing.T, counter *int64, handle func(q dns.Question) *dns.Msg) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt64(counter, 1)
		src := handle(r.Question[0])
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Authoritative = src.Authoritative
		reply.Rcode = src.Rcode
		reply.Answer = src.Answer
		reply.Ns = src.Ns
		reply.Extra = src.Extra
		_ = w.WriteMsg(reply)
	})
	s := &dns.Server{Net: "udp", PacketConn: pc, Handler: mux}
	go func() { _ = s.ActivateAndServe() }()
	time.Sleep(10 * time.Millisecond)
	return pc.LocalAddr().String(), func() { _ = s.Shutdown() }
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

// TestGhostDomain_DelegationLeaseExpiry reproduces and guards against
// GHSA-mqfw-f48p-2vc8 (ghost / phoenix domain) at the delegation-lease layer.
// It seeds r.delegations with explicit ip:port servers and drives
// Resolver.Resolve directly, so it exercises the delegation cache + walk-up.
// It does NOT cover the answer-cache/prefetch pipeline: a full parent-referral
// -> answer-cache -> prefetch -> withdrawal test is deferred to the
// delegation-generation/CAS follow-up.
//
// Topology (random loopback ports):
//   - parent: authoritative for ghostzone. The delegation for loop.ghostzone.
//     has been withdrawn, so it returns NXDOMAIN for the child and below.
//   - child : former authoritative for loop.ghostzone. It still answers
//     loop.ghostzone. NS and www.loop.ghostzone. A.
//
// The resolver delegation cache is seeded with explicit ip:port servers,
// which keeps this hermetic and portable: glue-derived upstreams are always
// :53, which cannot be bound unprivileged in CI.
//
//   - control:  with NO cached child delegation, resolving www.loop.ghostzone.
//     A walks up to the parent and returns NXDOMAIN.
//   - expiry:   a cached child delegation is served only while its
//     parent-granted lease is live; once the lease expires, re-resolution
//     walks back to the parent and returns NXDOMAIN. The former one-hour
//     lower clamp inflated the short lease into an hour and kept the withdrawn
//     child alive — this sub-test fails on that pre-fix behaviour.
func TestGhostDomain_DelegationLeaseExpiry(t *testing.T) {
	var parentHits, childHits int64

	parentSOA := "ghostzone. 30 IN SOA ns.ghostzone. hostmaster.ghostzone. 1 30 30 30 30"
	parentAddr, stopParent := startMockAuth(t, &parentHits, func(q dns.Question) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		name := dns.CanonicalName(q.Name)
		if name == "ghostzone." && q.Qtype == dns.TypeNS {
			m.Answer = []dns.RR{mustRR(t, "ghostzone. 300 IN NS ns.ghostzone.")}
			return m
		}
		// Everything at/below the withdrawn child is NXDOMAIN now.
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{mustRR(t, parentSOA)}
		return m
	})
	defer stopParent()

	childSOA := "loop.ghostzone. 30 IN SOA ns.loop.ghostzone. hostmaster.loop.ghostzone. 1 30 30 30 30"
	childAddr, stopChild := startMockAuth(t, &childHits, func(q dns.Question) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		name := dns.CanonicalName(q.Name)
		switch {
		case name == "loop.ghostzone." && q.Qtype == dns.TypeNS:
			m.Answer = []dns.RR{mustRR(t, "loop.ghostzone. 30 IN NS ns.loop.ghostzone.")}
		case name == "www.loop.ghostzone." && q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{mustRR(t, "www.loop.ghostzone. 30 IN A 192.0.2.55")}
		default:
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{mustRR(t, childSOA)}
		}
		return m
	})
	defer stopChild()

	parentServers := func() *authority.Servers {
		return &authority.Servers{
			Zone:            "ghostzone.",
			List:            []*authority.Server{authority.NewServer(parentAddr, authority.IPv4)},
			CheckingDisable: true,
		}
	}
	childServers := func() *authority.Servers {
		return &authority.Servers{
			Zone:            "loop.ghostzone.",
			List:            []*authority.Server{authority.NewServer(childAddr, authority.IPv4)},
			CheckingDisable: true,
		}
	}

	parentQuestion := dns.Question{Name: "ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	ghostQuestion := dns.Question{Name: "loop.ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}

	newResolver := func() *Resolver {
		return newWiredTestResolver(makeTestConfig())
	}

	// askA drives www.loop.ghostzone. A. The seeded ghostzone. delegation
	// terminates searchCache's walk-up before it reaches the resolver's real
	// root servers, so the start-servers argument is only a placeholder (it
	// is immediately replaced by the searchCache result). Passing a local
	// value avoids reading r.rootServers, which the resolver's background
	// priming goroutine reads concurrently.
	askA := func(r *Resolver) *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("www.loop.ghostzone.", dns.TypeA)
		req.CheckingDisabled = true
		ctx := context.WithValue(context.Background(), contextKeyRequestID, req.Id)
		resp, err := r.Resolve(ctx, req, parentServers(), true, 30, 0, true, nil)
		if err != nil {
			t.Logf("Resolve error: %v", err)
			return nil
		}
		return resp
	}

	t.Run("control_parent_reresolution", func(t *testing.T) {
		atomic.StoreInt64(&parentHits, 0)
		atomic.StoreInt64(&childHits, 0)
		r := newResolver()
		r.delegations.Set(cache.Key(parentQuestion, true), nil, parentServers(), time.Hour)

		resp := askA(r)
		if resp == nil {
			t.Fatal("control: expected a response, got resolve error")
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("control: expected NXDOMAIN from parent, got %s (answers=%d parentHits=%d childHits=%d)",
				dns.RcodeToString[resp.Rcode], len(resp.Answer),
				atomic.LoadInt64(&parentHits), atomic.LoadInt64(&childHits))
		}
	})

	// A cached child delegation is served while its parent-granted lease is
	// live, then must expire on schedule so re-resolution walks back to the
	// parent. Pre-fix the one-hour floor kept the 1s lease alive for an hour,
	// so the second query still hit the child (the ghost). Post-fix the lease
	// is honoured, expires, and the parent's NXDOMAIN wins.
	t.Run("ghost_child_delegation_expires", func(t *testing.T) {
		atomic.StoreInt64(&parentHits, 0)
		atomic.StoreInt64(&childHits, 0)
		r := newResolver()
		r.delegations.Set(cache.Key(parentQuestion, true), nil, parentServers(), time.Hour)
		// Parent granted a short referral TTL; the former child kept it warm.
		r.delegations.Set(cache.Key(ghostQuestion, true), nil, childServers(), time.Second)

		// While the lease is live, the cached child delegation answers.
		if resp := askA(r); resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			var rc string
			if resp != nil {
				rc = dns.RcodeToString[resp.Rcode]
			}
			t.Fatalf("within lease: expected a positive answer from the cached child delegation, got rcode=%s", rc)
		}

		// Let the 1s delegation lease expire.
		time.Sleep(1200 * time.Millisecond)

		// Snapshot hit counters: after expiry the resolver must contact the
		// parent and must NOT contact the former child.
		childBefore := atomic.LoadInt64(&childHits)
		parentBefore := atomic.LoadInt64(&parentHits)

		resp := askA(r)
		if resp == nil {
			t.Fatal("after expiry: expected a response, got resolve error")
		}
		childAfter := atomic.LoadInt64(&childHits)
		parentAfter := atomic.LoadInt64(&parentHits)
		t.Logf("after expiry: rcode=%s answers=%d parentHits=%d->%d childHits=%d->%d",
			dns.RcodeToString[resp.Rcode], len(resp.Answer),
			parentBefore, parentAfter, childBefore, childAfter)

		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("ghost domain: after the parent-granted delegation lease expired the "+
				"resolver must re-resolve via the parent and return NXDOMAIN, got rcode=%s "+
				"answers=%d (the child delegation lease was not honoured)",
				dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}
		if childAfter != childBefore {
			t.Fatalf("after expiry the former child must NOT be contacted, childHits %d -> %d", childBefore, childAfter)
		}
		if parentAfter == parentBefore {
			t.Fatalf("after expiry the parent MUST be re-contacted, parentHits stayed at %d", parentBefore)
		}
	})
}

// TestProcessDelegation_RejectsNonProgressingReferral guards P1 of the
// ghost-domain review: a referral whose NS owner is at the same depth as (or
// shallower than) the zone we queried must never be turned into a cached
// delegation. Otherwise a former child that answers a refresh with its own
// same-zone referral could reinsert its delegation after the parent withdrew
// it (reachable in production via pickFallbackResponse surfacing a
// non-progressing referral). The guard runs before any DNSSEC/glue work, so
// this needs no network.
func TestProcessDelegation_RejectsNonProgressingReferral(t *testing.T) {
	r := newWiredTestResolver(makeTestConfig())

	req := new(dns.Msg)
	req.SetQuestion("loop.ghostzone.", dns.TypeNS)
	req.CheckingDisabled = true

	rs := &resolveState{
		req:     req,
		servers: &authority.Servers{Zone: "loop.ghostzone."},
		level:   dns.CountLabel("loop.ghostzone."),
	}

	// A self-referral: NS owner == the zone we queried (same depth).
	ns := &dns.NS{Ns: "ns.loop.ghostzone."}
	ns.Hdr = dns.RR_Header{Name: "loop.ghostzone.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30}
	resp := new(dns.Msg)
	resp.Ns = []dns.RR{ns}
	nsInfo := delegationInfo{
		hosts:    hostSet{"ns.loop.ghostzone.": struct{}{}},
		nsRecord: ns,
		nsTTL:    30,
	}

	_, err := r.processDelegation(context.Background(), rs, resp, nsInfo, false)
	if !errors.Is(err, errParentDetection) {
		t.Fatalf("non-progressing self-referral must be rejected with errParentDetection, got %v", err)
	}

	// And nothing may have been written to the delegation cache.
	if _, gerr := r.delegations.Get(cache.Key(dns.Question{Name: "loop.ghostzone.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true)); gerr == nil {
		t.Fatal("a non-progressing referral must not populate the delegation cache")
	}
}

// TestProgressingReferral tables the referral-progression guard: a referral
// must be a strict descendant of the queried zone AND an ancestor of the name
// being resolved.
func TestProgressingReferral(t *testing.T) {
	const qname = "www.loop.ghostzone."
	cases := []struct {
		name     string
		referral string
		authZone string
		want     bool
	}{
		{"legit child delegation", "loop.ghostzone.", "ghostzone.", true},
		{"legit tld from root", "ghostzone.", ".", true},
		{"self referral (equal)", "loop.ghostzone.", "loop.ghostzone.", false},
		{"shallower referral", "ghostzone.", "loop.ghostzone.", false},
		{"unrelated but deeper", "evil.attacker.com.", "ghostzone.", false},
		{"in bailiwick but off path to qname", "sub.ghostzone.", "ghostzone.", false},
		{"out of bailiwick", "loop.ghostzone.", "other.tld.", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := progressingReferral(tc.referral, tc.authZone, qname); got != tc.want {
				t.Fatalf("progressingReferral(%q, %q, %q) = %v, want %v",
					tc.referral, tc.authZone, qname, got, tc.want)
			}
		})
	}
}
