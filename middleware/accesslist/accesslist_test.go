package accesslist

import (
	"context"
	"reflect"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

func Test_AccesslistDefaults(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.AccessList = []string{}

	a := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{a})

	mw := mock.NewWriter("udp", "8.8.8.8:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
}

func Test_Accesslist(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.AccessList = []string{"127.0.0.1/32", "1"}

	middleware.Register("accesslist", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	a := middleware.Get("accesslist").(*List)
	if !reflect.DeepEqual("accesslist", a.Name()) {
		t.Errorf("a.Name() = %v, want %v", a.Name(), "accesslist")
	}

	ch := middleware.NewChain([]middleware.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.255:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)

	mw = mock.NewWriter("udp", "0.0.0.0:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
}

// The access list runs before the cache, so it runs on every query the
// server answers, and the shipped configuration spells the open default
// out as "0.0.0.0/0" and "::0/0" rather than leaving the list empty. That
// is the configuration almost every deployment runs, and under it this
// middleware used to convert the client address into a freshly allocated
// slice per query, which a profile of a loaded server found at the top of
// the allocation list.
func Test_AccesslistServesWithoutAllocating(t *testing.T) {
	cfg := new(config.Config)
	cfg.AccessList = []string{"0.0.0.0/0", "::0/0"}
	a := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{})
	ch.Writer = mock.NewWriter("udp", "192.0.2.44:53")
	ctx := context.Background()

	if allocs := testing.AllocsPerRun(200, func() {
		a.ServeDNS(ctx, ch)
	}); allocs != 0 {
		t.Fatalf("the access list allocated %.2f objects per query", allocs)
	}
}
