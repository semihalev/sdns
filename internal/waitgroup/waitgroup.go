package waitgroup

import (
	"context"
	"errors"
	"sync"
	"time"
)

// WaitGroup waits for other same processes based key with timeout.
type WaitGroup struct {
	mu sync.RWMutex

	groups map[uint64]*Generation

	timeout time.Duration
}

// Generation is one immutable leadership generation for a key. Followers keep
// this token after it completes so Regroup can link every member of that cohort
// to the same next generation, even when the next leader finishes before a
// late follower wakes.
type Generation struct {
	ctx    context.Context
	dups   int
	cancel func()

	nextMu sync.Mutex
	next   *Generation
}

// New return a new WaitGroup with timeout.
func New(timeout time.Duration) *WaitGroup {
	return &WaitGroup{
		groups: make(map[uint64]*Generation),

		timeout: timeout,
	}
}

// Done returns a channel closed when this generation's leader finishes or its
// bounded wait expires.
func (g *Generation) Done() <-chan struct{} {
	if g == nil {
		return nil
	}
	return g.ctx.Done()
}

// Err reports why the generation ended. DeadlineExceeded distinguishes an
// abandoned/timed-out leader from a normal Done cancellation.
func (g *Generation) Err() error {
	if g == nil {
		return nil
	}
	return g.ctx.Err()
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

// Join atomically decides leadership for key. It is the legacy key-only API;
// callers must not mix Join/Done with JoinGeneration/DoneGeneration for the
// same key. It returns nil and registers the caller as the leader (caller must
// call Done when finished). If a leader already exists, Join returns a channel
// that closes when the leader finishes; followers must NOT call Done, they
// never registered as a participant, so calling Done would either
// over-decrement the dup counter or cancel the leader's context out from under
// it.
//
// This API closes the Wait-then-Add race in the older Wait/Add
// sequence: two simultaneous first callers both saw "no leader" and
// both became leaders, so the dedup didn't actually dedup.
func (wg *WaitGroup) Join(key uint64) <-chan struct{} {
	generation, leader := wg.JoinGeneration(key)
	if leader {
		return nil
	}
	return generation.Done()
}

// JoinGeneration atomically decides leadership for key and returns the exact
// generation token. The leader must call DoneGeneration with that same token;
// followers wait on Generation.Done and must not call DoneGeneration.
func (wg *WaitGroup) JoinGeneration(key uint64) (*Generation, bool) {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if generation, ok := wg.groups[key]; ok {
		return generation, false
	}

	generation := wg.newGeneration()
	wg.groups[key] = generation
	return generation, true
}

// Regroup links every follower of previous to one common next generation for
// key. Callers must wait for previous.Done and must handle a timed-out
// generation without regrouping. The link is retained on previous, so a late
// follower cannot create a third generation merely because the shared next
// leader already completed.
func (wg *WaitGroup) Regroup(key uint64, previous *Generation) (*Generation, bool) {
	if previous == nil {
		return wg.JoinGeneration(key)
	}
	if errors.Is(previous.Err(), context.DeadlineExceeded) {
		// Keep an abandoned leader as a tombstone until its token-specific
		// Done arrives. Replacing it on every waiter timeout would admit an
		// unbounded series of concurrent stuck leaders for a hot key.
		return previous, false
	}

	previous.nextMu.Lock()
	defer previous.nextMu.Unlock()
	if previous.next != nil {
		return previous.next, false
	}

	wg.mu.Lock()
	defer wg.mu.Unlock()
	if current, ok := wg.groups[key]; ok && current != previous {
		previous.next = current
		return current, false
	}

	generation := wg.newGeneration()
	wg.groups[key] = generation
	previous.next = generation
	return generation, true
}

func (wg *WaitGroup) newGeneration() *Generation {
	generation := new(Generation)
	generation.dups = 1
	generation.ctx, generation.cancel = context.WithTimeout(context.Background(), wg.timeout) //nolint:gosec // G118 - cancel is stored and called by DoneGeneration
	return generation
}

// (*WaitGroup).Add add adds a new caller or if the caller exists increment dups with key.
func (wg *WaitGroup) Add(key uint64) {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if generation, ok := wg.groups[key]; ok {
		generation.dups++
		return
	}

	generation := wg.newGeneration()
	wg.groups[key] = generation
}

// (*WaitGroup).Done done cancels the group context or if the caller dups more then zero, decrements the dups with key.
func (wg *WaitGroup) Done(key uint64) {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if generation, ok := wg.groups[key]; ok {
		if generation.dups > 1 {
			generation.dups--
			return
		}
		generation.cancel()
	}

	delete(wg.groups, key)
}

// DoneGeneration completes generation and removes it only if it is still the
// current value for key. The identity check prevents an old, timed-out leader
// from deleting a newer regroup generation.
func (wg *WaitGroup) DoneGeneration(key uint64, generation *Generation) {
	if generation == nil {
		return
	}

	wg.mu.Lock()
	defer wg.mu.Unlock()

	if generation.dups > 1 {
		generation.dups--
		return
	}
	generation.cancel()
	if wg.groups[key] == generation {
		delete(wg.groups, key)
	}
}
