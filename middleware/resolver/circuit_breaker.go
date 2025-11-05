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
			sf.disabled.Store(false)
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
	if count >= 5 && !sf.disabled.Load() {
		sf.disabled.Store(true)
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
			zlog.Info("Circuit breaker reset for DNS server", "server", server)
		}
	}
}

// cleanup removes old failure records periodically
func (cb *circuitBreaker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cb.mu.Lock()
		now := time.Now().Unix()
		for server, sf := range cb.failures {
			// Remove entries older than 5 minutes with no recent failures
			lastFailure := sf.lastFailure.Load()
			if sf.count.Load() == 0 && now-lastFailure > 300 {
				delete(cb.failures, server)
			}
		}
		cb.mu.Unlock()
	}
}
