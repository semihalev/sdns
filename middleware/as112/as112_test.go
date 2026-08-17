package as112

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

func Test_AS112(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.EmptyZones = []string{
		"10.in-addr.arpa.",
		"example.arpa",
	}

	middleware.Register("as112", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	a := middleware.Get("as112").(*AS112)

	if !reflect.DeepEqual("as112", a.Name()) {
		t.Errorf("a.Name() = %v, want %v", a.Name(), "as112")
	}

	ch := middleware.NewChain([]middleware.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("10.in-addr.arpa.", dns.TypeSOA)
	ch.Request = middleware.NewRequest(req)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	a.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Answer) > 0) {
		t.Errorf("len(mw.Msg().Answer) > 0 = %v, want %v", len(mw.Msg().Answer) > 0, true)
	}
	if !reflect.DeepEqual(dns.RcodeSuccess, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeSuccess)
	}

	req.SetQuestion("10.in-addr.arpa.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Answer) > 0) {
		t.Errorf("len(mw.Msg().Answer) > 0 = %v, want %v", len(mw.Msg().Answer) > 0, true)
	}
	if !reflect.DeepEqual(dns.RcodeSuccess, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeSuccess)
	}

	req.SetQuestion("10.in-addr.arpa.", dns.TypeSOA)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Answer) > 0) {
		t.Errorf("len(mw.Msg().Answer) > 0 = %v, want %v", len(mw.Msg().Answer) > 0, true)
	}
	if !reflect.DeepEqual(dns.RcodeSuccess, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeSuccess)
	}

	req.SetQuestion("10.in-addr.arpa.", dns.TypeDS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	req.SetQuestion("20.in-addr.arpa.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	req.SetQuestion("example.com.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	req.SetQuestion("10.10.in-addr.arpa.", dns.TypeSOA)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Ns) > 0) {
		t.Errorf("len(mw.Msg().Ns) > 0 = %v, want %v", len(mw.Msg().Ns) > 0, true)
	}
	if !reflect.DeepEqual(dns.RcodeNameError, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeNameError)
	}

	req.SetQuestion("10.10.in-addr.arpa.", dns.TypeA)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Ns) > 0) {
		t.Errorf("len(mw.Msg().Ns) > 0 = %v, want %v", len(mw.Msg().Ns) > 0, true)
	}
	if !reflect.DeepEqual(dns.RcodeNameError, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeNameError)
	}

	req.SetQuestion("10.10.in-addr.arpa.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Ns) > 0) {
		t.Errorf("len(mw.Msg().Ns) > 0 = %v, want %v", len(mw.Msg().Ns) > 0, true)
	}
	if !reflect.DeepEqual(dns.RcodeNameError, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeNameError)
	}
}
