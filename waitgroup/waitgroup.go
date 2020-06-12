package waitgroup

import (
	"context"
	"sync"
	"time"
)

// WaitGroup waits for other same processes based key with timeout.
type WaitGroup struct {
	mu sync.RWMutex

	groups map[uint64]*call

	timeout time.Duration
}

type call struct {
	ctx    context.Context
	dups   int
	cancel func()
}

// New return a new WaitGroup with timeout.
func New(timeout time.Duration) *WaitGroup {
	return &WaitGroup{
		groups: make(map[uint64]*call),

		timeout: timeout,
	}
}

// Get return count of dups with key.
func (wg *WaitGroup) Get(key uint64) int {
	wg.mu.RLock()
	defer wg.mu.RUnlock()

	if c, ok := wg.groups[key]; ok {
		return c.dups
	}

	return 0
}

// Wait blocks until WaitGroup context cancelled or timedout with key.
func (wg *WaitGroup) Wait(key uint64) {
	wg.mu.RLock()

	if c, ok := wg.groups[key]; ok {
		wg.mu.RUnlock()
		<-c.ctx.Done()
		return
	}

	wg.mu.RUnlock()
}

// Add adds a new caller or if the caller exists increment dups with key.
func (wg *WaitGroup) Add(key uint64) {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if c, ok := wg.groups[key]; ok {
		c.dups++
		return
	}

	c := new(call)
	c.dups++
	c.ctx, c.cancel = context.WithTimeout(context.Background(), wg.timeout)
	wg.groups[key] = c
}

// Done cancels the group context or if the caller dups more then zero, decrements the dups with key.
func (wg *WaitGroup) Done(key uint64) {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if c, ok := wg.groups[key]; ok {
		if c.dups > 1 {
			c.dups--
			return
		}
		c.cancel()
	}

	delete(wg.groups, key)
}
