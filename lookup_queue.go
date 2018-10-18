package main

import "sync"

// LQueue type
type LQueue struct {
	mu sync.RWMutex

	delay map[string]*sync.Cond
}

// NewLookupQueue func
func NewLookupQueue() *LQueue {
	return &LQueue{
		delay: make(map[string]*sync.Cond),
	}
}

// Wait func
func (q *LQueue) Wait(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if cond, ok := q.delay[key]; ok {
		cond.Wait()
	}
}

// Set func
func (q *LQueue) Set(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.delay[key] = sync.NewCond(&q.mu)
}

// Remove func
func (q *LQueue) Remove(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if cond, ok := q.delay[key]; ok {
		delete(q.delay, key)

		cond.Broadcast()
	}
}
