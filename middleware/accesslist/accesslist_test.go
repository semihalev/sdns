package accesslist

import (
	"context"
	"reflect"
	"slices"
	"sync"
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

// A reload builds the new list without touching the one in use and swaps
// it in on commit, while queries keep arriving.
func TestReloadSwapsTheListOnCommit(t *testing.T) {
	a := New(&config.Config{AccessList: []string{"192.0.2.0/24"}})
	allowed := func(addr string) bool {
		next := &reached{}
		ch := middleware.NewChain([]middleware.Handler{next})
		ch.Writer = mock.NewWriter("udp", addr)
		a.ServeDNS(context.Background(), ch)
		return next.ok
	}
	if !slices.Equal(a.ReloadKeys(), []string{"accesslist"}) {
		t.Fatalf("keys %v", a.ReloadKeys())
	}

	if _, err := a.PrepareReload(&config.Config{AccessList: []string{"not a cidr"}}); err == nil {
		t.Fatal("prepared a list with an entry that does not parse")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				allowed("192.0.2.1:0")
			}
		}
	})

	commit, err := a.PrepareReload(&config.Config{AccessList: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if allowed("198.51.100.1:0") || !allowed("192.0.2.1:0") {
		t.Fatal("prepare changed the list in use")
	}
	commit()
	close(stop)
	wg.Wait()
	if !allowed("198.51.100.1:0") || allowed("192.0.2.1:0") {
		t.Fatal("commit did not put the new list in use")
	}
}

// reached records whether the access list passed the query on.
type reached struct{ ok bool }

func (r *reached) Name() string                                    { return "reached" }
func (r *reached) ServeDNS(_ context.Context, _ *middleware.Chain) { r.ok = true }
