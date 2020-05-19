package lqueue

import (
	"context"
	"sync"
	"time"
)

// LQueue type
type LQueue struct {
	mu sync.RWMutex

	l map[uint64]*call

	duration time.Duration
}

type call struct {
	ctx    context.Context
	dups   int
	cancel func()
}

// New func
func New(duration time.Duration) *LQueue {
	return &LQueue{
		l: make(map[uint64]*call),

		duration: duration,
	}
}

// Get func
func (q *LQueue) Get(key uint64) int {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if c, ok := q.l[key]; ok {
		return c.dups
	}

	return 0
}

// Wait func
func (q *LQueue) Wait(key uint64) {
	q.mu.RLock()

	if c, ok := q.l[key]; ok {
		q.mu.RUnlock()
		<-c.ctx.Done()
		return
	}

	q.mu.RUnlock()
}

// Add func
func (q *LQueue) Add(key uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if c, ok := q.l[key]; ok {
		c.dups++
		return
	}

	c := new(call)
	c.dups++
	c.ctx, c.cancel = context.WithTimeout(context.Background(), q.duration)
	q.l[key] = c
}

// Done func
func (q *LQueue) Done(key uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if c, ok := q.l[key]; ok {
		if c.dups > 1 {
			c.dups--
			return
		}
		c.cancel()
	}

	delete(q.l, key)
}
