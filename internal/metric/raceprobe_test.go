package metric

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestRaceConcurrentFlushAll: tight loop of concurrent FlushAll calls
// while a writer adds to the counter. flushAll's flushMu must
// serialise the underlying Counter.flush calls so the lastSent
// read-modify-write doesn't race.
func TestRaceConcurrentFlushAll(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()

	prom := prometheus.NewCounter(prometheus.CounterOpts{Name: "race_probe", Help: "x"})
	c := &Counter{prom: prom}
	defaultRegistry.add(c)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			<-start
			for range 5_000 {
				FlushAll()
			}
		})
	}
	// Writer to ensure flush always has work to do.
	wg.Go(func() {
		<-start
		for range 1_000_000 {
			c.Inc()
		}
	})

	close(start)
	wg.Wait()

	// Final correctness check: the counter must equal what the
	// writer added (no double-counting from concurrent flushes).
	FlushAll()
	if got := c.Value(); got != 1_000_000 {
		t.Errorf("Value = %d, want 1_000_000", got)
	}
	if got := promValue(t, prom); got != 1_000_000 {
		t.Errorf("Prom value = %v, want 1_000_000 (double-counting bug)", got)
	}
}
