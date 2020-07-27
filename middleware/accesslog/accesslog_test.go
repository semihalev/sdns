package accesslog

import (
	"context"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_accesslog(t *testing.T) {
	cfg := &config.Config{
		AccessLog: "access_test.log",
	}

	middleware.Setup(cfg)
	a := middleware.Get("accesslog").(*AccessLog)

	assert.Equal(t, "accesslog", a.Name())
	assert.NotNil(t, a.logFile)

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

	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode)

	resp.CheckingDisabled = true
	a.ServeDNS(context.Background(), ch)

	assert.True(t, resp.CheckingDisabled)

	assert.NoError(t, a.logFile.Close())

	a.ServeDNS(context.Background(), ch)

	assert.NoError(t, os.Remove(cfg.AccessLog))
}
