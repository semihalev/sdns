package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// Every reply echoes the client's RD (RFC 1035 §4.1.1), whatever the
// resolution did with the request on the way, and the request holds the
// client's RD again once the handler returns.
func TestResolverRepliesEchoTheClientsRD(t *testing.T) {
	net := newHermeticNet(t)
	net.Delegate("signed.").Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
	handler := net.Handler()

	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
		rd    bool
		rcode int
	}{
		{"resolved, RD=1", "www.signed.", dns.TypeA, true, dns.RcodeSuccess},
		{"root, RD=0", ".", dns.TypeNS, false, dns.RcodeSuccess},
		{"ANY policy answer, RD=0", "www.signed.", dns.TypeANY, false, dns.RcodeNotImplemented},
		{"non-recursive question, RD=0", "www.signed.", dns.TypeA, false, dns.RcodeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, tc.qtype)
			req.SetEdns0(1232, true)
			req.RecursionDesired = tc.rd
			resp := handler.handle(context.Background(), req)
			if resp.Rcode != tc.rcode {
				t.Fatalf("rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
			if resp.RecursionDesired != tc.rd {
				t.Fatalf("reply RD = %v, want the client's %v", resp.RecursionDesired, tc.rd)
			}
			if req.RecursionDesired != tc.rd {
				t.Fatalf("request RD = %v after the handler, want the client's %v back", req.RecursionDesired, tc.rd)
			}
		})
	}
}
