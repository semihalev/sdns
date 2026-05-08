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

// (*WaitGroup).Get get return count of dups with key.
func (wg *WaitGroup) Get(key uint64) int {
	wg.mu.RLock()
	defer wg.mu.RUnlock()

	if c, ok := wg.groups[key]; ok {
		return c.dups
	}

	return 0
}

// (*WaitGroup).Wait wait blocks until WaitGroup context cancelled or timedout with key.
func (wg *WaitGroup) Wait(key uint64) {
	wg.mu.RLock()

	if c, ok := wg.groups[key]; ok {
		wg.mu.RUnlock()
		<-c.ctx.Done()
		return
	}

	wg.mu.RUnlock()
}

// Join atomically decides leadership for key. It returns nil and
// registers the caller as the leader (caller must call Done when
// finished). If a leader already exists, Join returns a channel that
// closes when the leader finishes; followers must NOT call Done —
// they never registered as a participant, so calling Done would
// either over-decrement the dup counter or cancel the leader's
// context out from under it.
//
// This API closes the Wait-then-Add race in the older Wait/Add
// sequence: two simultaneous first callers both saw "no leader" and
// both became leaders, so the dedup didn't actually dedup.
func (wg *WaitGroup) Join(key uint64) <-chan struct{} {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if c, ok := wg.groups[key]; ok {
		// Follower: share the leader's ctx.Done. No counter bump —
		// followers are not participants, they just observers.
		return c.ctx.Done()
	}

	c := new(call)
	c.dups = 1
	c.ctx, c.cancel = context.WithTimeout(context.Background(), wg.timeout) //nolint:gosec // G118 - cancel is stored in c.cancel and called in Done()
	wg.groups[key] = c
	return nil
}

// (*WaitGroup).Add add adds a new caller or if the caller exists increment dups with key.
func (wg *WaitGroup) Add(key uint64) {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if c, ok := wg.groups[key]; ok {
		c.dups++
		return
	}

	c := new(call)
	c.dups++
	c.ctx, c.cancel = context.WithTimeout(context.Background(), wg.timeout) //nolint:gosec // G118 - cancel is stored in c.cancel and called in Done()
	wg.groups[key] = c
}

// (*WaitGroup).Done done cancels the group context or if the caller dups more then zero, decrements the dups with key.
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
