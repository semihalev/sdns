package edns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestWireCookieWithResponseOwnOPT pins the cold-miss shape a plain dig
// causes: a wire-born request carrying a client COOKIE, answered by a
// response that already has its own OPT (the resolver re-attaches one).
// The writer then owns no request OPT, and appending the server cookie
// through the nil w.opt was a panic the recovery middleware ate on every
// such query.
func TestWireCookieWithResponseOwnOPT(t *testing.T) {
	e := New(new(config.Config))

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = append(q.IsEdns0().Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "0011223344556677",
	})
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}

	responder := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.SetEdns0(1232, false)
		rr, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		resp.Answer = append(resp.Answer, rr)
		_ = ch.Writer.WriteMsg(resp)
	})

	ch := middleware.NewChain([]middleware.Handler{e, responder})
	mw := mock.NewWriter("tcp", "127.0.0.2:40000")
	ch.ResetWire(mw, req)
	ch.Next(context.Background())

	if !ch.Writer.Written() {
		t.Fatal("no reply written")
	}
	opt := ch.Writer.Msg().IsEdns0()
	if opt == nil {
		t.Fatal("reply lost its OPT")
	}
	var cookie *dns.EDNS0_COOKIE
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("server cookie missing from the reply")
	}
	if len(cookie.Cookie) <= 16 {
		t.Fatalf("cookie %q carries no server half", cookie.Cookie)
	}
}
