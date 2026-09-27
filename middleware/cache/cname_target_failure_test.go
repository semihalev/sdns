package cache

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// An alias whose target answers with a failure is that failure: SERVFAIL,
// the target's Extended DNS Error, no alias left standing with AD set, and
// a validation verdict on the target stays a verdict on the alias. A target
// that answers, even with a denial, still composes as before.
func TestAdditionalAnswerTargetFailureFailsTheAlias(t *testing.T) {
	alias := func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("alias.example.", dns.TypeA)
		msg.SetEdns0(dnsutil.DefaultMsgSize, true)
		msg.Response, msg.AuthenticatedData = true, true
		msg.Answer = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "target.example.",
		}}
		return msg
	}

	for _, tc := range []struct {
		name    string
		rcode   int
		verdict bool
		ede     uint16 // what the alias's SERVFAIL carries
	}{
		{"bogus target", dns.RcodeServerFailure, true, dns.ExtendedErrorCodeDNSBogus},
		{"failing target", dns.RcodeServerFailure, false, dns.ExtendedErrorCodeDNSBogus},
		// A REFUSED carries no EDE here, so the alias says Other.
		{"refused target", dns.RcodeRefused, false, dns.ExtendedErrorCodeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 300})
			defer c.Stop()
			ctx := middleware.WithResponseMeta(context.Background(), new(middleware.ResponseMeta))
			c.SetQueryer(queryerFunc(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
				resp := dnsutil.SetRcodeWithEDE(req, tc.rcode, true, dns.ExtendedErrorCodeDNSBogus, "target refused")
				if tc.verdict {
					middleware.MarkValidationFailureResponse(ctx, resp)
				}
				return resp, nil
			}))

			got := c.additionalAnswer(ctx, alias())
			if got.Rcode != dns.RcodeServerFailure || got.AuthenticatedData || len(got.Answer) != 0 {
				t.Fatalf("%s AD=%v %v, want SERVFAIL without the alias",
					dns.RcodeToString[got.Rcode], got.AuthenticatedData, got.Answer)
			}
			var ede *dns.EDNS0_EDE
			if opt := got.IsEdns0(); opt != nil {
				for _, o := range opt.Option {
					if e, ok := o.(*dns.EDNS0_EDE); ok {
						ede = e
					}
				}
			}
			if ede == nil || ede.InfoCode != tc.ede {
				t.Fatalf("EDE %v, want code %d", ede, tc.ede)
			}
			if marked := middleware.IsValidationFailureResponse(ctx, got); marked != tc.verdict {
				t.Fatalf("validation verdict on the alias %v, want %v", marked, tc.verdict)
			}
		})
	}

	t.Run("denied target still composes", func(t *testing.T) {
		c := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer c.Stop()
		c.SetQueryer(queryerFunc(func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetRcode(req, dns.RcodeNameError)
			return resp, nil
		}))
		if got := c.additionalAnswer(context.Background(), alias()); got.Rcode != dns.RcodeNameError || len(got.Answer) != 1 {
			t.Fatalf("%s %v, want the alias with the target's NXDOMAIN", dns.RcodeToString[got.Rcode], got.Answer)
		}
	})
}
