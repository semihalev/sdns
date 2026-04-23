package cache

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

// PrefetchRequest represents a DNS query to be prefetched.
type PrefetchRequest struct {
	Request *dns.Msg
	Key     uint64
	Cache   *Cache      // Reference to the cache to store prefetched results
	Entry   *CacheEntry // Entry that claimed the prefetch; used to release the claim on failure/drop
}

// PrefetchQueue manages prefetch requests with worker pool.
type PrefetchQueue struct {
	items   chan PrefetchRequest
	workers int
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	metrics *CacheMetrics
}

// NewPrefetchQueue creates a new prefetch queue.
func NewPrefetchQueue(workers, queueSize int, metrics *CacheMetrics) *PrefetchQueue {
	ctx, cancel := context.WithCancel(context.Background())

	pq := &PrefetchQueue{
		items:   make(chan PrefetchRequest, queueSize),
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
		metrics: metrics,
	}

	// Start workers
	for i := 0; i < workers; i++ {
		pq.wg.Add(1)
		go pq.worker()
	}

	return pq
}

// (*PrefetchQueue).Add add queues a prefetch request.
func (pq *PrefetchQueue) Add(req PrefetchRequest) bool {
	select {
	case pq.items <- req:
		return true
	default:
		// Queue is full, drop the request
		zlog.Debug("Prefetch queue full, dropping request", "query", formatQuestion(req.Request.Question[0]))
		return false
	}
}

// (*PrefetchQueue).Stop stop gracefully shuts down the prefetch queue.
func (pq *PrefetchQueue) Stop() {
	pq.cancel()
	close(pq.items)
	pq.wg.Wait()
}

// worker processes prefetch requests.
func (pq *PrefetchQueue) worker() {
	defer pq.wg.Done()

	for {
		select {
		case <-pq.ctx.Done():
			return
		case req, ok := <-pq.items:
			if !ok {
				return
			}
			pq.processPrefetch(req)
		}
	}
}

// processPrefetch executes a prefetch request. The claim on
// req.Entry is released on any path that doesn't produce a
// fresh replacement entry — otherwise a failed or empty
// prefetch would leave prefetch=true on the hot entry and
// ShouldPrefetch would stay false until unrelated expiry.
func (pq *PrefetchQueue) processPrefetch(req PrefetchRequest) {
	ctx, cancel := context.WithTimeout(pq.ctx, 5*time.Second)
	defer cancel()

	zlog.Debug("Processing prefetch", "query", formatQuestion(req.Request.Question[0]))

	// Make a copy for internal query
	prefetchReq := req.Request.Copy()

	// Execute the prefetch query
	resp, err := util.ExchangeInternal(ctx, prefetchReq)
	if err != nil {
		zlog.Debug("Prefetch failed", "query", formatQuestion(req.Request.Question[0]), "error", err.Error())
		releasePrefetchClaim(req.Entry)
		return
	}

	// Store the response in cache if we have a cache reference.
	// Cache.Set replaces the entry (new entry's prefetch flag
	// defaults to false), so we only need to release the claim
	// explicitly on the no-answer path.
	if req.Cache != nil && resp != nil && len(resp.Answer) > 0 {
		// Log TTL information for debugging
		minTTL := uint32(0)
		for _, rr := range resp.Answer {
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}

		// Use the key that was passed in the request
		req.Cache.Set(req.Key, resp)
		zlog.Debug("Prefetch stored in cache", "query", formatQuestion(req.Request.Question[0]), "answers", len(resp.Answer), "minTTL", minTTL)
	} else {
		releasePrefetchClaim(req.Entry)
	}

	pq.metrics.Prefetch()
	zlog.Debug("Prefetch completed", "query", formatQuestion(req.Request.Question[0]))
}

// releasePrefetchClaim clears the prefetch flag so future
// cache hits can attempt another prefetch. Called from the
// drop path and from failure/no-answer paths in the worker.
func releasePrefetchClaim(entry *CacheEntry) {
	if entry != nil {
		entry.prefetch.Store(false)
	}
}

// formatQuestion formats a DNS question for logging.
func formatQuestion(q dns.Question) string {
	return q.Name + " " + dns.TypeToString[q.Qtype] + " " + dns.ClassToString[q.Qclass]
}
