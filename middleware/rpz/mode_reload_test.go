package rpz

import (
	"slices"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
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
