package cache

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
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
// req.Entry is released on every exit path — SetFromResponse
// classifies and stores (or skips, for rcodes it doesn't cache)
// a fresh entry under the same key; the hot entry's prefetch
// flag has to be cleared whether the new write happened or not,
// otherwise ShouldPrefetch would stay false until unrelated expiry.
func (pq *PrefetchQueue) processPrefetch(req PrefetchRequest) {
	ctx, cancel := context.WithTimeout(pq.ctx, 5*time.Second)
	defer cancel()
	defer releasePrefetchClaim(req.Entry)

	zlog.Debug("Processing prefetch", "query", formatQuestion(req.Request.Question[0]))

	// Copy the original client request so upstream mutations
	// (CD bit, EDNS options) don't bleed into the shared Request
	// held by other callers or into the stored entry's question.
	prefetchReq := req.Request.Copy()

	// Force DO=1 on the refresh. The cache stores the COMPLETE answer
	// (RRSIGs + AD) and is keyed on CD, not DO — DNSSEC is stripped
	// per-client at serve time by edns. On the external path the cache
	// sits below edns and stores the full answer; the prefetch sub-
	// pipeline runs edns, so copying a DO=0 trigger's bit would let edns
	// strip the refresh and overwrite the entry with an AD-less answer
	// that downgrades every later DO=1 client. Mirror the internal
	// NS/DS lookups, which always query with DO set. CD is preserved
	// from the copy (it is the cache key and the validation opt-out).
	if opt := prefetchReq.IsEdns0(); opt != nil {
		opt.SetDo(true)
	} else {
		prefetchReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	}

	// Route through the cache-less prefetch sub-pipeline so the
	// refresh reaches the upstream resolver/forwarder instead of
	// its own about-to-expire entry. Local-answer middleware
	// (hostsfile, blocklist, kubernetes, as112) and failover still
	// apply; metrics/dnstap/accesslog do not.
	resp, err := req.Cache.prefetchExchange(ctx, prefetchReq)
	if err != nil {
		zlog.Debug("Prefetch failed", "query", formatQuestion(req.Request.Question[0]), "error", err.Error())
		return
	}
	if resp == nil {
		return
	}

	// Key off the client request's CD bit — the same keying rule
	// as the external chain writeback. prefetchReq may have been
	// mutated by upstream middleware; using req.Request.CD
	// preserves the dedup invariant that CD=1 and CD=0 entries
	// stay separate.
	req.Cache.store.SetFromResponseWithKey(req.Key, resp)
	pq.metrics.Prefetch()

	if len(resp.Answer) > 0 {
		minTTL := uint32(0)
		for _, rr := range resp.Answer {
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		zlog.Debug("Prefetch stored in cache", "query", formatQuestion(req.Request.Question[0]), "answers", len(resp.Answer), "minTTL", minTTL)
	} else {
		zlog.Debug("Prefetch completed", "query", formatQuestion(req.Request.Question[0]), "rcode", dns.RcodeToString[resp.Rcode])
	}
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
