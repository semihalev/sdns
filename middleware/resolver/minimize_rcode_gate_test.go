package resolver

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
)

// TestMinimizedRcodeGateFallsBack pins the fallback decision to the RCODE
// rather than to section shapes. The first version of the fallback keyed on
// "no answer, no authority", so a REFUSED dressed with a SOA or an NXDOMAIN
// dressed in a CNAME answer slipped past it and back into the label walk —
// one unreadable error per hidden label. Whatever a hidden prefix draws
// besides NOERROR and a provable denial, the next question is the full name.
func TestMinimizedRcodeGateFallsBack(t *testing.T) {
	const (
		zone = "gapzone."
		full = "a.b.c.d.e.gapzone."
	)
	soa := zone + " 60 IN SOA ns.gapzone. hostmaster.gapzone. 1 60 60 60 60"

	shapes := []struct {
		name   string
		prefix func(t *testing.T, q dns.Question) *dns.Msg
	}{
		{
			name: "REFUSED with a SOA",
			prefix: func(t *testing.T, q dns.Question) *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused},
					Ns:     []dns.RR{mustRR(t, soa)},
				}
			},
		},
		{
			name: "NXDOMAIN dressed in a CNAME answer",
			prefix: func(t *testing.T, q dns.Question) *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
					Answer: []dns.RR{mustRR(t, dns.Fqdn(q.Name)+" 60 IN CNAME nowhere.invalid.")},
					Ns:     []dns.RR{mustRR(t, soa)},
				}
			},
		},
	}

	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu       sync.Mutex
				askedFor = map[string]int{}
				hits     int64
			)
			addr, stop := startMockAuth(t, &hits, func(q dns.Question) *dns.Msg {
				mu.Lock()
				askedFor[strings.ToLower(dns.CanonicalName(q.Name))]++
				mu.Unlock()

				if dns.CanonicalName(q.Name) == full && q.Qtype == dns.TypeA {
					m := &dns.Msg{Answer: []dns.RR{mustRR(t, full+" 60 IN A 192.0.2.99")}}
					m.Authoritative = true
					return m
				}
				m := tc.prefix(t, q)
				m.Authoritative = true
				return m
			})
			defer stop()

			ten := 10
			cfg := makeTestConfig()
			cfg.QnameMaxMinimizeCount = &ten
			cfg.QnameMinimizeOneLabel = 4
			r := newWiredTestResolver(cfg)

			servers := &authority.Servers{
				Zone:            zone,
				List:            []*authority.Server{authority.NewServer(addr, authority.IPv4)},
				CheckingDisable: true,
			}
			r.delegations.Set(
				cache.Key(dns.Question{Name: zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, true),
				nil, servers, time.Hour)

			req := new(dns.Msg)
			req.SetQuestion(full, dns.TypeA)
			req.CheckingDisabled = true
			resp, err := r.Resolve(context.Background(), req, servers, true, 30, 0, false, nil)
			if err != nil {
				t.Fatalf("resolve %s: %v", full, err)
			}
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
				t.Fatalf("rcode = %s answers = %d, want the full name's answer",
					dns.RcodeToString[resp.Rcode], len(resp.Answer))
			}

			mu.Lock()
			defer mu.Unlock()
			if askedFor["e.gapzone."] == 0 {
				t.Error("the first hidden prefix was never probed")
			}
			if askedFor[full] == 0 {
				t.Error("the full name was never asked")
			}
			for _, interior := range []string{"d.e.gapzone.", "c.d.e.gapzone.", "b.c.d.e.gapzone."} {
				if n := askedFor[interior]; n != 0 {
					t.Errorf("%s was asked %d times, want the label walk abandoned", interior, n)
				}
			}
		})
	}
}
