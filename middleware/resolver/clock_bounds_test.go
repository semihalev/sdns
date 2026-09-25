package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/middleware"
)

// A delegation bound on both clocks, as one from the verified root copy is,
// passes both to every delegation established below it and to every answer
// resolved under it, on the walk that learns the child and on the next walk
// that finds it cached. Neither is folded into the other on the way.
func TestDelegationLeaseKeepsBothClocks(t *testing.T) {
	var ignore int64
	softNeg := func(zone string) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		m.Ns = []dns.RR{mustRR(t, zone+" 30 IN SOA ns."+zone+" hostmaster."+zone+" 1 30 30 30 30")}
		return m
	}

	subAddr, stopSub := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeA && dns.IsSubDomain("sub.clock.", dns.CanonicalName(q.Name)) {
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, q.Name+" 300 IN A 192.0.2.55")}
			return m
		}
		return softNeg("sub.clock.")
	})
	defer stopSub()

	parentAddr, stopParent := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype != dns.TypeDS && dns.IsSubDomain("sub.clock.", dns.CanonicalName(q.Name)) {
			m := &dns.Msg{}
			m.Ns = []dns.RR{mustRR(t, "sub.clock. 43200 IN NS ns.sub.clock.")}
			m.Extra = []dns.RR{mustRR(t, "ns.sub.clock. 43200 IN A 192.0.2.13")}
			return m
		}
		return softNeg("clock.")
	})
	defer stopParent()

	// The root only answers priming; the walks start from the cached
	// clock. delegation, which the cuts below prove.
	rootAddr, stopRoot := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		if dns.CanonicalName(q.Name) == "." && q.Qtype == dns.TypeNS {
			m.Answer = []dns.RR{mustRR(t, ". 3600 IN NS a.root.")}
		}
		return m
	})
	defer stopRoot()

	remap := map[string]string{"192.0.2.11:53": parentAddr, "192.0.2.13:53": subAddr}
	mapper := func(addr string) string {
		if to, ok := remap[addr]; ok {
			return to
		}
		return addr
	}
	cfg := *makeTestConfig()
	cfg.RootServers = []string{rootAddr}
	cfg.Root6Servers = nil
	cfg.DNSSEC = "off"
	r := newWiredTestResolver(&cfg)
	r.resolveTarget.Store(&mapper)

	now := time.Now()
	mono := now.Add(2 * time.Hour)
	wall := time.Unix(0, now.Add(time.Hour).UnixNano())
	parentKey := cache.Key(dns.Question{Name: "clock.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true)
	r.delegations.SetUntil(parentKey, nil, &authority.Servers{
		Zone:            "clock.",
		CheckingDisable: true,
		List:            []*authority.Server{authority.NewServer("192.0.2.11:53", authority.IPv4)},
	}, lease.Until(mono).Min(lease.Until(wall)))

	resolve := func(name string) lease.Lease {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		req.CheckingDisabled = true
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.WithValue(context.Background(), contextKeyRequestID, req.Id), &meta)
		resp, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, true, nil)
		if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			t.Fatalf("resolve %s: %v %v", name, err, resp)
		}
		return meta.Cut()
	}
	within := func(t *testing.T, what string, cut lease.Lease) {
		t.Helper()
		if !cut.Wall().Until.Equal(wall) {
			t.Fatalf("%s = %+v, lost the ancestor's wall-clock deadline %v", what, cut, wall)
		}
		if got := cut.Mono().Until; got.IsZero() || got.After(mono) {
			t.Fatalf("%s = %+v, its monotonic deadline is not bounded by the ancestor's %v", what, cut, mono)
		}
	}

	within(t, "first answer's cut", resolve("www.sub.clock."))

	child, err := r.delegations.Get(cache.Key(dns.Question{Name: "sub.clock.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true))
	if err != nil {
		t.Fatalf("sub.clock. not cached: %v", err)
	}
	within(t, "child delegation's lease", child.Lease)

	// The next walk starts from the cached child.
	within(t, "warm answer's cut", resolve("mail.sub.clock."))
}
