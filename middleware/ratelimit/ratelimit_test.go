package ratelimit

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func Test_RateLimit(t *testing.T) {
	cfg := new(config.Config)
	cfg.ClientRateLimit = 1

	// The registry is process-wide, so a second run in the same process —
	// go test -count=2, say — would otherwise panic on re-registration.
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("ratelimit", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	r := middleware.Get("ratelimit").(*RateLimit)

	if !reflect.DeepEqual("ratelimit", r.Name()) {
		t.Errorf("r.Name() = %v, want %v", r.Name(), "ratelimit")
	}

	ch := middleware.NewChain([]middleware.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, true)

	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "testtesttesttest",
	})

	mw := mock.NewWriter("udp", "")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	mw = mock.NewWriter("udp", "10.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	r.ServeDNS(context.Background(), ch)
	if !(mw.Written()) {
		t.Errorf("mw.Written() is false")
	} else if !reflect.DeepEqual(dns.RcodeBadCookie, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeBadCookie)
	}

	opt.Option = nil
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "testtesttesttest",
	})

	mw = mock.NewWriter("udp", "10.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	mw = mock.NewWriter("tcp", "10.0.0.2:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	r.ServeDNS(context.Background(), ch)
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	opt.Option = nil
	mw = mock.NewWriter("udp", "10.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	r.ServeDNS(context.Background(), ch)
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	mw = mock.NewWriter("udp", "0.0.0.0:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	r.rate = 0

	r.ServeDNS(context.Background(), ch)
}
