package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/metric"
	wirepack "github.com/semihalev/sdns/internal/wire"
)

// An expired answer leaves the positive cache when a lookup meets it or
// when an insert evicts it. One nobody asks for again, under a capacity
// that is rarely reached, stays in memory for good, counted as cached. The
// pruner removes those: a background pass every pruneInterval, one small
// step at a time (cache.Prune), resting pruneRest between steps so it takes
// no more than a sliver of a core and never holds a segment lock for longer
// than one step's slots.
const (
	pruneInterval = 5 * time.Minute
	pruneRest     = 250 * time.Microsecond
)

var cachePruned = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_cache_pruned_total",
	Help: "Expired answers the background pruner removed from the answer cache because nothing could serve them again",
})

// pruner runs the background pass; stop ends it.
type pruner struct {
	stop    chan struct{}
	stopped atomic.Bool
	once    sync.Once
}

// startPruning starts the background pass over the answer cache.
func (s *Store) startPruning() {
	s.pruner = &pruner{stop: make(chan struct{})}
	go s.pruneLoop(s.pruner)
}

func (s *Store) stopPruning() {
	if p := s.pruner; p != nil {
		p.once.Do(func() {
			p.stopped.Store(true)
			close(p.stop)
		})
	}
}

func (s *Store) pruneLoop(p *pruner) {
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		cachePruned.Add(int64(s.prunePass(&p.stopped, pruneRest)))
	}
}

// prunePass walks the whole answer cache once, resting rest between steps,
// and returns how many answers it removed. It ends early once stopped.
func (s *Store) prunePass(stopped *atomic.Bool, rest time.Duration) int {
	var (
		cur     cache.PruneCursor
		removed int
	)
	for !stopped.Load() {
		now := time.Now()
		dead := func(e *CacheEntry) bool { return s.unservable(e, now) }
		take := func(e *CacheEntry) bool { return s.takeForPrune(e, now) }
		n, done := s.positive.cache.Prune(&cur, dead, take)
		removed += n
		if done {
			break
		}
		if rest > 0 {
			time.Sleep(rest)
		}
	}
	return removed
}

// takeForPrune is the removal's decision, under the segment's write lock:
// e is still unservable, and the removal takes its refresh claim. A
// refresh that claimed it first keeps it; one that tries after finds it
// claimed and starts nothing, so no refresh is left writing back to an
// entry already gone.
func (s *Store) takeForPrune(e *CacheEntry, now time.Time) bool {
	return s.unservable(e, now) && e.prefetch.CompareAndSwap(false, true)
}

// unservable reports that nothing can answer from e again: it has expired,
// and serve-stale, if on, may not serve it either, being a denial or its
// delegation lease or serve_stale_max_ttl having run out (the bounds
// staleResponseFromEntry applies). An entry whose refresh is under way is left to the refresh,
// which replaces it by pointer; removing it first would drop the result.
func (s *Store) unservable(e *CacheEntry, now time.Time) bool {
	if e == nil || e.prefetch.Load() {
		return false
	}
	ttlRemaining, leaseRemaining := e.remainingBounds(now)
	leased := !e.cutUntil.IsZero()
	if ttlRemaining > 0 && (!leased || leaseRemaining > 0) {
		return false
	}
	if !s.cfg.ServeStale || !staleEligible(e) {
		return true
	}
	if leased && leaseRemaining <= 0 {
		return true
	}
	maxStale := s.cfg.ServeStaleMaxTTL
	return maxStale > 0 && -ttlRemaining > maxStale
}

// staleEligible reports whether serve-stale could ever answer from e: a
// NOERROR with answer records (staleResponseFromEntry). A denial, NXDOMAIN
// or NODATA, never is, and has nothing to wait for once it expires. Read
// from the stored header, no decode.
func staleEligible(e *CacheEntry) bool {
	h, ok := wirepack.ParseHeader(e.wire)
	return ok && h.Rcode() == dns.RcodeSuccess && h.ANCount > 0
}
