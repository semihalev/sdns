package main

import (
	"sync"
)

// LQueue type
type LQueue struct {
	mu sync.RWMutex

	wqm map[string][]chan struct{}
}

// WaitQueue is a lockable work queue
type WaitQueue struct {
	locked bool
	work   chan struct{}
}

// NewLookupQueue func
func NewLookupQueue() *LQueue {
	return &LQueue{
		wqm: make(map[string][]chan struct{}),
	}
}

// Wait func
func (q *LQueue) Wait(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if w, ok := q.wqm[key]; ok {
		c := make(chan struct{})
		w = append(w, c)

		<-c
	}
}

// New func
func (q *LQueue) New(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.wqm[key] = []chan struct{}{}
}

// Broadcast func
func (q *LQueue) Broadcast(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if w, ok := q.wqm[key]; ok {
		for _, c := range w {
			c <- struct{}{}
			close(c)
		}
	}

	delete(q.wqm, key)
}
