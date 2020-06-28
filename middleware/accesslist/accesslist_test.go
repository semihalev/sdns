package accesslist

import (
	"context"
	"testing"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Accesslist(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(config.Config)
	cfg.AccessList = []string{"127.0.0.1/32", "1"}

	middleware.Setup(cfg)

	a := middleware.Get("accesslist").(*AccessList)
	assert.Equal(t, "accesslist", a.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	ctx := context.Background()

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(ctx, ch)

	mw = mock.NewWriter("udp", "0.0.0.0:0")
	ch.Writer = mw
	a.ServeDNS(ctx, ch)
}
