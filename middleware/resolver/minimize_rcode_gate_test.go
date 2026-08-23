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

// TestMinimizedDenialCutRefusesAliasAnswers pins RFC 2308 section 2.1 onto the
// prefix cut: an NXDOMAIN that carries a CNAME or DNAME answer denies the end
// of the alias chain, not the probed name, so it must never be validated as a
// denial of the prefix — judging the proof against the wrong owner fails a
// legitimately signed chain closed, or blesses a denial of the alias target as
// though it covered the prefix.
//
// The response's echoed Question deliberately mismatches minReq: consulting
// the validator with it errors out, so an error here is the proof that the
// alias guard did not fire first.
func TestMinimizedDenialCutRefusesAliasAnswers(t *testing.T) {
	r := newWiredTestResolver(makeTestConfig())

	req := new(dns.Msg)
	req.SetQuestion("a.b.c.deep.test.", dns.TypeA)
	minReq := new(dns.Msg)
	minReq.SetQuestion("c.deep.test.", dns.TypeA)
	rs := &resolveState{req: req, servers: &authority.Servers{Zone: "deep.test."}}

	aliases := []dns.RR{
		mustRR(t, "c.deep.test. 60 IN CNAME target.deep.test."),
		mustRR(t, "c.deep.test. 60 IN DNAME target.test."),
	}
	for _, alias := range aliases {
		resp := new(dns.Msg)
		resp.SetQuestion("mismatch.deep.test.", dns.TypeA)
		resp.Rcode = dns.RcodeNameError
		resp.Answer = []dns.RR{alias}
		resp.Ns = []dns.RR{mustRR(t, "deep.test. 60 IN SOA ns.deep.test. h.deep.test. 1 60 60 60 60")}

		answer, denied, err := r.minimizedDenialCut(context.Background(), rs, minReq, resp)
		if err != nil {
			t.Fatalf("%s: the alias reached validation: %v", dns.TypeToString[alias.Header().Rrtype], err)
		}
		if denied || answer != nil {
			t.Fatalf("%s: denied=%v answer=%v, want the full-name fallback", dns.TypeToString[alias.Header().Rrtype], denied, answer)
		}
	}
}
