package waitgroup

import (
	"context"
	"sync"
	"time"
)

// WaitGroup type
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

// New func
func New(timeout time.Duration) *WaitGroup {
	return &WaitGroup{
		groups: make(map[uint64]*call),

		timeout: timeout,
	}
}

// Get func
func (wg *WaitGroup) Get(key uint64) int {
	wg.mu.RLock()
	defer wg.mu.RUnlock()

	if c, ok := wg.groups[key]; ok {
		return c.dups
	}

	return 0
}

// Wait func
func (wg *WaitGroup) Wait(key uint64) {
	wg.mu.RLock()

	if c, ok := wg.groups[key]; ok {
		wg.mu.RUnlock()
		<-c.ctx.Done()
		return
	}

	wg.mu.RUnlock()
}

// Add func
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

// Done func
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
