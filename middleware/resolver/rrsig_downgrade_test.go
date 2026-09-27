package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// An RRSIG question asked of a signed zone the resolver has not met yet
// must not leave the zone insecure: the questions after it are validated
// and carry AD, as they do when the RRSIG question never came.
func TestColdRRSIGQuestionLeavesTheZoneSecure(t *testing.T) {
	for _, first := range []struct {
		name  string
		owner string
	}{
		{"at the apex", "signed."},
		{"below the apex", "www.signed."},
	} {
		t.Run(first.name, func(t *testing.T) {
			net := newHermeticNet(t)
			zone := net.Delegate("signed.")
			for _, owner := range []string{"signed.", "www.signed."} {
				a := mustRR(t, owner+" 300 IN A 192.0.2.45")
				zone.Serve(a)
				zone.server.serve(owner, dns.TypeRRSIG, zone.key.sign(t, []dns.RR{a}))
			}
			c := newEDEClient(t, net)

			if resp := c.ask(first.owner, dns.TypeRRSIG, false, false); resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("RRSIG question: %s, want the signatures", dns.RcodeToString[resp.Rcode])
			}
			for _, owner := range []string{"signed.", "www.signed."} {
				for _, wireBorn := range []bool{false, true} {
					resp := c.ask(owner, dns.TypeA, wireBorn, false)
					if resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
						t.Fatalf("%s A (wire-born=%v) after a cold RRSIG question: %s AD=%v, want the validated answer",
							owner, wireBorn, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData)
					}
				}
			}
		})
	}
}
