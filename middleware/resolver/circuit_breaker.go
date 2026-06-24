package resolver

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
)

// circuitBreaker tracks server failures and temporarily disables failing servers
type circuitBreaker struct {
	mu       sync.RWMutex
	failures map[string]*serverFailure
}

type serverFailure struct {
	count       atomic.Int32
	lastFailure atomic.Int64 // Unix timestamp
	disabled    atomic.Bool
}

func newCircuitBreaker() *circuitBreaker {
	cb := &circuitBreaker{
		failures: make(map[string]*serverFailure),
	}

	// Cleanup old entries periodically
	go cb.cleanup()

	return cb
}

// canQuery checks if we can query this server
func (cb *circuitBreaker) canQuery(server string) bool {
	cb.mu.RLock()
	sf, exists := cb.failures[server]
	cb.mu.RUnlock()

	if !exists {
		return true
	}

	// If disabled, check if enough time has passed
	if sf.disabled.Load() {
		lastFailure := time.Unix(sf.lastFailure.Load(), 0)
		if time.Since(lastFailure) > 30*time.Second {
			// Reset after 30 seconds
			if sf.disabled.CompareAndSwap(true, false) {
				circuitBreakerResets.Inc()
			}
			sf.count.Store(0)
			return true
		}
		return false
	}

	return true
}

// recordFailure records a server failure
func (cb *circuitBreaker) recordFailure(server string) {
	cb.mu.Lock()
	sf, exists := cb.failures[server]
	if !exists {
		sf = &serverFailure{}
		cb.failures[server] = sf
	}
	cb.mu.Unlock()

	count := sf.count.Add(1)
	sf.lastFailure.Store(time.Now().Unix())

	// Disable server after 5 consecutive failures
	if count >= 5 && sf.disabled.CompareAndSwap(false, true) {
		circuitBreakerTrips.Inc()
		zlog.Warn("Circuit breaker tripped for DNS server", "server", server, "failures", count)
	}
}

// recordSuccess records a successful query
func (cb *circuitBreaker) recordSuccess(server string) {
	cb.mu.RLock()
	sf, exists := cb.failures[server]
	cb.mu.RUnlock()

	if exists {
		oldCount := sf.count.Swap(0)
		wasDisabled := sf.disabled.Swap(false)

		if wasDisabled && oldCount > 0 {
			circuitBreakerResets.Inc()
			zlog.Info("Circuit breaker reset for DNS server", "server", server)
		}
	}
}

// cleanup removes old failure records periodically.
func (cb *circuitBreaker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cb.cleanupOnce(time.Now().Unix())
	}
}

// cleanupOnce evicts every entry with no failure in the last 5 minutes.
//
// Eviction must NOT be gated on count==0: count only returns to zero on a
// recordSuccess, so a server that failed a few times (below the 5-failure
// trip threshold) and was then never queried again would keep count>0 and
// leak its map entry forever. A recursive resolver contacts an unbounded
// set of authoritative IPs, so that is an unbounded-growth vector under
// ordinary (and adversarial) traffic. Idle time alone is the correct
// signal: any disable expires after 30s, so a 5-minute-idle entry is stale
// regardless of its counter.
func (cb *circuitBreaker) cleanupOnce(now int64) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	for server, sf := range cb.failures {
		if now-sf.lastFailure.Load() > 300 {
			delete(cb.failures, server)
		}
	}
}
