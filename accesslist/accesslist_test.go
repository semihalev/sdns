package accesslist

import (
	"testing"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Accesslist(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(config.Config)
	cfg.AccessList = []string{"127.0.0.1/32", "1"}

	a := New(cfg)
	assert.Equal(t, "accesslist", a.Name())

	dc := ctx.New([]ctx.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1")
	dc.DNSWriter = mw
	a.ServeDNS(dc)

	mw = mock.NewWriter("udp", "0.0.0.0")
	dc.DNSWriter = mw
	a.ServeDNS(dc)
}
