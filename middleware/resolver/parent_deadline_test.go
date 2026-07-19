package resolver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestGhostDomain_ParentStateAtLeaseDeadline complements the withdrawal
// regressions with the other two parent outcomes at the same boundary: an
// unchanged delegation is renewed through the parent, while a re-delegation
// switches to the new child and never consults the former child again.
func TestGhostDomain_ParentStateAtLeaseDeadline(t *testing.T) {
	for _, tc := range []struct {
		name        string
		redelegate  bool
		wantAddress string
	}{
		{name: "parent unchanged", wantAddress: "192.0.2.10"},
		{name: "parent redelegated", redelegate: true, wantAddress: "192.0.2.20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rootHits, oldHits, newHits int64

			leaf := func(address string) func(dns.Question) *dns.Msg {
				return func(q dns.Question) *dns.Msg {
					m := new(dns.Msg)
					m.Authoritative = true
					if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) == "www.ghost." {
						m.Answer = []dns.RR{mustRR(t, "www.ghost. 300 IN A "+address)}
						return m
					}
					m.Ns = []dns.RR{mustRR(t, "ghost. 30 IN SOA ns.ghost. hostmaster.ghost. 1 30 30 30 30")}
					return m
				}
			}

			oldAddr, stopOld := startMockAuth(t, &oldHits, leaf("192.0.2.10"))
			defer stopOld()
			newAddr, stopNew := startMockAuth(t, &newHits, leaf("192.0.2.20"))
			defer stopNew()

			var switched atomic.Bool
			rootAddr, stopRoot := startMockAuth(t, &rootHits, func(q dns.Question) *dns.Msg {
				m := new(dns.Msg)
				name := dns.CanonicalName(q.Name)
				if name == "." && q.Qtype == dns.TypeNS {
					m.Authoritative = true
					m.Answer = []dns.RR{mustRR(t, ". 3600 IN NS a.root.")}
					return m
				}
				if q.Qtype == dns.TypeDS {
					m.Authoritative = true
					m.Ns = []dns.RR{mustRR(t, ". 30 IN SOA a.root. hostmaster.root. 1 30 30 30 30")}
					return m
				}
				if dns.IsSubDomain("ghost.", name) || name == "ghost." {
					if switched.Load() {
						m.Ns = []dns.RR{mustRR(t, "ghost. 1 IN NS ns2.ghost.")}
						m.Extra = []dns.RR{mustRR(t, "ns2.ghost. 1 IN A 192.0.2.22")}
					} else {
						m.Ns = []dns.RR{mustRR(t, "ghost. 1 IN NS ns1.ghost.")}
						m.Extra = []dns.RR{mustRR(t, "ns1.ghost. 1 IN A 192.0.2.21")}
					}
					return m
				}
				m.Authoritative = true
				m.Ns = []dns.RR{mustRR(t, ". 30 IN SOA a.root. hostmaster.root. 1 30 30 30 30")}
				return m
			})
			defer stopRoot()

			remap := map[string]string{
				"192.0.2.21:53": oldAddr,
				"192.0.2.22:53": newAddr,
			}
			mapper := func(addr string) string {
				if target, ok := remap[addr]; ok {
					return target
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

			ask := func() string {
				t.Helper()
				req := new(dns.Msg)
				req.SetQuestion("www.ghost.", dns.TypeA)
				req.CheckingDisabled = true
				ctx := context.WithValue(context.Background(), contextKeyRequestID, req.Id)
				resp, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, true, nil)
				if err != nil {
					t.Fatalf("resolve failed: %v", err)
				}
				for _, rr := range resp.Answer {
					if a, ok := rr.(*dns.A); ok {
						return a.A.String()
					}
				}
				return ""
			}

			if got := ask(); got != "192.0.2.10" {
				t.Fatalf("initial answer = %q, want former child", got)
			}
			rootBefore := atomic.LoadInt64(&rootHits)
			oldBefore := atomic.LoadInt64(&oldHits)
			if tc.redelegate {
				switched.Store(true)
			}

			time.Sleep(1300 * time.Millisecond)
			if got := ask(); got != tc.wantAddress {
				t.Fatalf("post-deadline answer = %q, want %q", got, tc.wantAddress)
			}
			if atomic.LoadInt64(&rootHits) <= rootBefore {
				t.Fatal("parent was not contacted after the delegation deadline")
			}
			if tc.redelegate {
				if got := atomic.LoadInt64(&oldHits); got != oldBefore {
					t.Fatalf("former child contacted after re-delegation: hits %d -> %d", oldBefore, got)
				}
				if atomic.LoadInt64(&newHits) == 0 {
					t.Fatal("new child was not contacted after re-delegation")
				}
			} else if atomic.LoadInt64(&oldHits) <= oldBefore {
				t.Fatal("unchanged child was not renewed through the parent")
			}
		})
	}
}
