package lqueue

import (
	"sync"
	"time"
)

// LQueue type
type LQueue struct {
	mu sync.RWMutex

	queue map[uint64]chan struct{}
}

// New func
func New() *LQueue {
	return &LQueue{
		queue: make(map[uint64]chan struct{}),
	}
}

// Get func
func (q *LQueue) Get(key uint64) <-chan struct{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if c, ok := q.queue[key]; ok {
		return c
	}

	return nil
}

// Wait func
func (q *LQueue) Wait(key uint64) {
	q.mu.RLock()

	if c, ok := q.queue[key]; ok {
		q.mu.RUnlock()
		select {
		case <-c:
		case <-time.After(10 * time.Second): // 10 seconds timeout
		}
		return
	}

	q.mu.RUnlock()
}

// Add func
func (q *LQueue) Add(key uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.queue[key] = make(chan struct{})
}

// Done func
func (q *LQueue) Done(key uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if c, ok := q.queue[key]; ok {
		close(c)
	}

	delete(q.queue, key)
}
