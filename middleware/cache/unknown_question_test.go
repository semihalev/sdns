package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// A question for a type or class with no registered name is passed on like
// any other and answered, never dropped: a silent drop leaves the client to
// time out. Decoded and wire-born requests alike.
func TestUnknownTypeOrClassIsPassedOn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		qtype  uint16
		qclass uint16
	}{
		{"unknown type", 65534, dns.ClassINET},
		{"private-use type", 65280, dns.ClassINET},
		{"unknown class", dns.TypeA, 1234},
	} {
		for _, wireBorn := range []bool{false, true} {
			name := tc.name + "/decoded"
			if wireBorn {
				name = tc.name + "/wire-born"
			}
			t.Run(name, func(t *testing.T) {
				c := New(&config.Config{CacheSize: 1024, Expire: 300})
				defer c.Stop()
				reached := false
				next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
					reached = true
					resp := new(dns.Msg)
					resp.SetRcode(ch.Request.Msg(), dns.RcodeNotImplemented)
					_ = ch.Writer.WriteMsg(resp)
					ch.Cancel()
				})

				q := new(dns.Msg)
				q.SetQuestion("example.test.", tc.qtype)
				q.Question[0].Qclass = tc.qclass
				q.RecursionDesired = true
				w := mock.NewWriter("udp", "192.0.2.9:53000")
				ch := middleware.NewChain([]middleware.Handler{c, next})
				if wireBorn {
					raw, err := q.Pack()
					if err != nil {
						t.Fatal(err)
					}
					req := new(middleware.Request)
					if !req.ParseWire(raw, time.Now(), nil) {
						t.Fatal("eligible query refused by ParseWire")
					}
					ch.ResetWire(w, req)
				} else {
					ch.Reset(w, q)
				}
				ch.Next(context.Background())

				if !reached || !w.Written() {
					t.Fatalf("reached=%v written=%v, want the question passed on and answered", reached, w.Written())
				}
			})
		}
	}
}
