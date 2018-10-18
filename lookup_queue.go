package main

import (
	"sync"
	"time"
)

// LQueue type
type LQueue struct {
	mu sync.RWMutex

	delay map[string]chan bool
}

// NewLookupQueue func
func NewLookupQueue() *LQueue {
	return &LQueue{
		delay: make(map[string]chan bool),
	}
}

// Wait func
func (q *LQueue) Wait(key string) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if ch, ok := q.delay[key]; ok {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
		}
	}
}

// New func
func (q *LQueue) New(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.delay[key] = make(chan bool)
}

// Broadcast func
func (q *LQueue) Broadcast(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if ch, ok := q.delay[key]; ok {
		close(ch)
	}

	delete(q.delay, key)
}
