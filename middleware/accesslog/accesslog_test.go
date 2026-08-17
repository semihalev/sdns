package accesslog

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

func Test_accesslog(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := &config.Config{
		AccessLog: "access_test.log",
	}

	middleware.Register("accesslog", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)
	a := middleware.Get("accesslog").(*Log)

	if !reflect.DeepEqual("accesslog", a.Name()) {
		t.Errorf("a.Name() = %v, want %v", a.Name(), "accesslog")
	}
	if a.logFile == nil {
		t.Fatalf("a.logFile is nil")
	}

	ch := middleware.NewChain([]middleware.Handler{a})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	ch.Reset(mw, req)

	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	resp.Question = req.Copy().Question

	_ = ch.Writer.WriteMsg(resp)

	a.ServeDNS(context.Background(), ch)

	if !reflect.DeepEqual(dns.RcodeServerFailure, mw.Msg().Rcode) {
		t.Errorf("mw.Msg().Rcode = %v, want %v", mw.Msg().Rcode, dns.RcodeServerFailure)
	}

	resp.CheckingDisabled = true
	a.ServeDNS(context.Background(), ch)

	if !(resp.CheckingDisabled) {
		t.Errorf("resp.CheckingDisabled is false")
	}

	if err := a.logFile.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	a.ServeDNS(context.Background(), ch)

	if err := os.Remove(cfg.AccessLog); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
