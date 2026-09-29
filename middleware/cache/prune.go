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
// that is rarely reached, would stay in memory for good, counted as
// cached. The pruner removes those without walking the cache: every answer
// is filed in the cache's expiry index for the instant nothing can serve
// it any more (lifeOf), and every pruneInterval the pruner opens the
// buckets whose time has passed and removes what it finds there unservable.
const pruneInterval = 10 * time.Second

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
		cachePruned.Add(int64(s.prune()))
	}
}

// prune removes the answers whose expiry records have come due and that
// nothing can serve any more, and returns how many.
func (s *Store) prune() int {
	return s.positive.cache.Expire(s.judgeExpired)
}

// judgeExpired is the verdict on an answer whose expiry record came due,
// under its segment's write lock. An unservable answer is removed, and the
// removal takes its refresh claim: a refresh that claimed it first keeps
// it, and is looked at again later; one that tries after finds it claimed
// and starts nothing, so no refresh is left writing back to an entry
// already gone. A servable answer reports how long it has left.
func (s *Store) judgeExpired(e *CacheEntry) (cache.Verdict, time.Duration) {
	now := time.Now()
	if s.pruneClock != nil {
		now = s.pruneClock()
	}
	if s.unservable(e, now) {
		if e.prefetch.CompareAndSwap(false, true) {
			return cache.Dead, 0
		}
		return cache.Busy, 0
	}
	if e.prefetch.Load() {
		return cache.Busy, 0
	}
	return cache.Alive, s.lifeOf(e, now)
}

// lifeOf is how long from now e can still be served, the instant from
// which unservable holds for it (a refresh claim aside): the earlier of
// its TTL and its lease, and, where serve-stale may answer from it, the
// earlier of its lease and serve_stale_max_ttl past its TTL, or no end
// with neither.
func (s *Store) lifeOf(e *CacheEntry, now time.Time) time.Duration {
	ttlRemaining, leaseRemaining := e.remainingBounds(now)
	end := ttlRemaining
	if s.cfg.ServeStale && staleEligible(e) {
		end = cache.Forever
		if maxStale := s.cfg.ServeStaleMaxTTL; maxStale > 0 {
			end = ttlRemaining + maxStale
		}
	}
	if !e.cutUntil.IsZero() && leaseRemaining < end {
		end = leaseRemaining
	}
	return end
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
