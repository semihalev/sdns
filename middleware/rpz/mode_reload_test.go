package rpz

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// A reload flips the mode on commit, while queries keep arriving: shadow
// counts a match as observed and passes the query on, enforce acts on it
// and counts it enforced.
func TestReloadFlipsTheModeOnCommit(t *testing.T) {
	r := newRPZ(t, "shadow", config.RPZZone{Name: "flip", File: writeZone(t, testZone)})
	if !slices.Equal(r.ReloadKeys(), []string{"rpz.mode"}) {
		t.Fatalf("keys %v", r.ReloadKeys())
	}
	serve := func() bool {
		_, passed := serveFrom(t, r, "192.0.2.1:0", "nx.example.com.", dns.TypeA)
		return passed
	}

	observed := counterValue(t, "flip", "nxdomain", outcomeObserved)
	if !serve() || counterValue(t, "flip", "nxdomain", outcomeObserved) != observed+1 {
		t.Fatal("shadow: want the query passed on and counted observed")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				serve()
			}
		}
	})

	commit, err := r.PrepareReload(&config.Config{RPZ: config.RPZ{Enabled: true, Mode: "enforce"}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !serve() {
		t.Fatal("prepare put enforce in use")
	}
	commit()
	close(stop)
	wg.Wait()

	enforced := counterValue(t, "flip", "nxdomain", outcomeEnforced)
	if serve() || counterValue(t, "flip", "nxdomain", outcomeEnforced) != enforced+1 {
		t.Fatal("enforce after commit: want the query answered and counted enforced")
	}
}

// An inline pass hands its query to a worker, and a reload flips the mode
// between the two: the replay must finish the query in the mode its inline
// pass judged and counted it in, not act on a match counted as observed.
func TestReplayKeepsTheModeOfItsInlinePass(t *testing.T) {
	r := newRPZ(t, "shadow", config.RPZZone{Name: "pinned", File: writeZone(t, testZone)})

	q := new(dns.Msg)
	q.SetQuestion("nx.example.com.", dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("refused")
	}
	passed := false
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		ch.Cancel()
	})
	ch := middleware.NewChain([]middleware.Handler{r, next})

	w := mock.NewWriter("udp", "192.0.2.1:0")
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if !passed {
		t.Fatal("shadow inline pass did not pass the query on")
	}

	commit, err := r.PrepareReload(&config.Config{RPZ: config.RPZ{Enabled: true, Mode: "enforce"}})
	if err != nil {
		t.Fatal(err)
	}
	commit()

	passed = false
	carry := ch.Carry()
	w = mock.NewWriter("udp", "192.0.2.1:0")
	ch.ResetWire(w, req)
	ch.SetReplay()
	ch.Restore(carry)
	ch.Next(context.Background())
	if !passed || w.Written() {
		t.Fatal("the replay acted in enforce mode on a match its shadow inline pass counted as observed")
	}

	// A new query reads the new mode.
	if _, passed := serveFrom(t, r, "192.0.2.1:0", "nx.example.com.", dns.TypeA); passed {
		t.Fatal("a new query did not take the reloaded mode")
	}
}
