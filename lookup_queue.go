package main

import (
	"sync"
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
		<-c
		return
	}

	q.mu.RUnlock()
}

// New func
func (q *LQueue) New(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.delay[key] = make(chan struct{})
}

// Broadcast func
func (q *LQueue) Broadcast(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if c, ok := q.delay[key]; ok {
		close(c)
	}

	delete(q.delay, key)
}
