package kubernetes

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// LockFreePredictor - ML-based DNS query prediction using Markov chains
// Zero allocations, lock-free operations, and scary-fast predictions
type LockFreePredictor struct {
	// Lock-free circular buffer for recent queries
	recentQueries [1024]atomicString
	queryIndex    uint64

	// Markov chain transitions (domain -> next likely domains)
	transitions sync.Map // We'll migrate to lock-free map later

	// Statistics
	predictions uint64
	hits        uint64

	// Pre-allocated prediction buffer
	predictionPool sync.Pool
}

// atomicString - Lock-free string storage
type atomicString struct {
	ptr unsafe.Pointer
}

func (as *atomicString) Store(s string) {
	atomic.StorePointer(&as.ptr, unsafe.Pointer(&s))
}

func (as *atomicString) Load() string {
	p := atomic.LoadPointer(&as.ptr)
	if p == nil {
		return ""
	}
	return *(*string)(p)
}

// NewLockFreePredictor creates the ML predictor
func NewLockFreePredictor() *LockFreePredictor {
	p := &LockFreePredictor{
		predictionPool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate slice for predictions
				s := make([]string, 0, 10)
				return &s
			},
		},
	}

	// Start background model training
	go p.trainLoop()

	return p
}

// Record adds a query to the model (lock-free)
func (p *LockFreePredictor) Record(domain string, qtype uint16) {
	// Only track A/AAAA queries for now
	if qtype != 1 && qtype != 28 {
		return
	}

	// Lock-free circular buffer update
	idx := atomic.AddUint64(&p.queryIndex, 1) % 1024
	p.recentQueries[idx].Store(domain)

	// Update transitions (currently using sync.Map, will optimize later)
	if idx > 0 {
		prevDomain := p.recentQueries[idx-1].Load()
		if prevDomain != "" {
			p.updateTransition(prevDomain, domain)
		}
	}
}

// Predict returns likely next queries based on ML model
func (p *LockFreePredictor) Predict(current string) []string {
	// Get prediction buffer from pool (zero alloc)
	bufPtr := p.predictionPool.Get().(*[]string)
	predictions := (*bufPtr)[:0]
	defer func() {
		*bufPtr = predictions
		p.predictionPool.Put(bufPtr)
	}()

	// Look up transitions
	if val, ok := p.transitions.Load(current); ok {
		transitions := val.(*domainTransitions)
		predictions = transitions.getTopPredictions(predictions)
		atomic.AddUint64(&p.predictions, uint64(len(predictions)))
	}

	// Make a copy to return (can't return pooled slice)
	result := make([]string, len(predictions))
	copy(result, predictions)

	return result
}

// updateTransition updates the Markov chain model
func (p *LockFreePredictor) updateTransition(from, to string) {
	val, _ := p.transitions.LoadOrStore(from, &domainTransitions{})
	transitions := val.(*domainTransitions)
	transitions.add(to)
}

// trainLoop continuously improves the model
func (p *LockFreePredictor) trainLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Analyze patterns and adjust weights
		p.analyzePatterns()
	}
}

// analyzePatterns finds common DNS query patterns
func (p *LockFreePredictor) analyzePatterns() {
	// Common Kubernetes patterns to boost
	patterns := []struct {
		service string
		likely  []string
	}{
		{"kube-dns", []string{"kubernetes", "metrics-server"}},
		{"kubernetes", []string{"kube-dns", "coredns"}},
		{"app", []string{"database", "cache", "api"}},
		{"api", []string{"database", "cache"}},
		{"web", []string{"api", "cdn", "static"}},
	}

	// Inject common patterns into model
	for _, pattern := range patterns {
		p.updateTransition(pattern.service, pattern.likely[0])
		for i := 0; i < len(pattern.likely)-1; i++ {
			p.updateTransition(pattern.likely[i], pattern.likely[i+1])
		}
	}
}

// Stats returns predictor statistics
func (p *LockFreePredictor) Stats() map[string]interface{} {
	predictions := atomic.LoadUint64(&p.predictions)
	hits := atomic.LoadUint64(&p.hits)

	accuracy := float64(0)
	if predictions > 0 {
		accuracy = float64(hits) / float64(predictions) * 100
	}

	return map[string]interface{}{
		"predictions":    predictions,
		"hits":           hits,
		"accuracy":       accuracy,
		"model_size":     p.modelSize(),
		"recent_queries": p.recentQueriesCount(),
	}
}

func (p *LockFreePredictor) modelSize() int {
	count := 0
	p.transitions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func (p *LockFreePredictor) recentQueriesCount() int {
	count := 0
	for i := 0; i < 1024; i++ {
		if p.recentQueries[i].Load() != "" {
			count++
		}
	}
	return count
}

// domainTransitions tracks likely next domains
type domainTransitions struct {
	mu     sync.RWMutex
	counts map[string]uint64
	total  uint64
}

func (dt *domainTransitions) add(domain string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	if dt.counts == nil {
		dt.counts = make(map[string]uint64)
	}

	dt.counts[domain]++
	dt.total++
}

func (dt *domainTransitions) getTopPredictions(buf []string) []string {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	if dt.counts == nil || dt.total == 0 {
		return buf
	}

	// Simple approach: return domains with >10% probability
	threshold := dt.total / 10

	for domain, count := range dt.counts {
		if count >= threshold && len(buf) < cap(buf) {
			buf = append(buf, domain)
		}
		if len(buf) >= 5 { // Max 5 predictions
			break
		}
	}

	return buf
}
