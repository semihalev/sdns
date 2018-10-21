package main

import (
	"sync"
	"time"
)

// LQueue type
type LQueue struct {
	mu sync.RWMutex

	delay map[string]chan struct{}
}

// NewLookupQueue func
func NewLookupQueue() *LQueue {
	return &LQueue{
		delay: make(map[string]chan struct{}),
	}
}

// Get func
func (q *LQueue) Get(key string) <-chan struct{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if c, ok := q.delay[key]; ok {
		return c
	}

	return nil
}

// Wait func
func (q *LQueue) Wait(key string) {
	q.mu.RLock()

	if c, ok := q.delay[key]; ok {
		q.mu.RUnlock()
		select {
		case <-c:
		case <-time.After(10 * time.Second):
		}
		return
	}

	q.mu.RUnlock()
}

// Add func
func (q *LQueue) Add(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.delay[key] = make(chan struct{})
}

// Done func
func (q *LQueue) Done(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if c, ok := q.delay[key]; ok {
		close(c)
	}

	delete(q.delay, key)
}
