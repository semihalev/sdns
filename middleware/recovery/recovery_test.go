package recovery

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

func Test_Recovery(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)

	middleware.Register("recovery", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(&config.Config{})

	r := middleware.Get("recovery").(*Recovery)

	if !reflect.DeepEqual("recovery", r.Name()) {
		t.Errorf("r.Name() = %v, want %v", r.Name(), "recovery")
	}

	ch := middleware.NewChain([]middleware.Handler{r, nil})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	ch.Reset(mw, req)

	r.ServeDNS(context.Background(), ch)

	if !reflect.DeepEqual(dns.RcodeServerFailure, mw.Msg().Rcode) {
		t.Errorf("mw.Msg().Rcode = %v, want %v", mw.Msg().Rcode, dns.RcodeServerFailure)
	}

	ch = middleware.NewChain([]middleware.Handler{r})
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	os.Stderr = stderr
}
