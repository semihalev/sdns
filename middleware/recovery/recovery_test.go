package recovery

import (
	"context"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Recovery(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)

	middleware.Register("recovery", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(&config.Config{})

	r := middleware.Get("recovery").(*Recovery)

	assert.Equal(t, "recovery", r.Name())

	ch := middleware.NewChain([]middleware.Handler{r, nil})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	ch.Reset(mw, req)

	r.ServeDNS(context.Background(), ch)

	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode)

	ch = middleware.NewChain([]middleware.Handler{r})
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	os.Stderr = stderr
}
