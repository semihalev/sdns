package loop

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

func Test_loop(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)

	middleware.Setup(&config.Config{})
	l := middleware.Get("loop").(*Loop)
	assert.Equal(t, "loop", l.Name())

	ch := middleware.NewChain([]middleware.Handler{l, l, l, l, l, l, l, l, l, l, l})

	ctx := context.Background()
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ch.Reset(mw, req)

	l.ServeDNS(ctx, ch)

	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode)

	os.Stderr = stderr
}
