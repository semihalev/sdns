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

// Get func
func (q *LQueue) Get(key string) *sync.Cond {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if cond, ok := q.delay[key]; ok {
		return cond
	}

	return nil
}

// Set func
func (q *LQueue) Set(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.delay[key] = sync.NewCond(&sync.Mutex{})
}

// Remove func
func (q *LQueue) Remove(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if cond, ok := q.delay[key]; ok {
		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()
	}

	delete(q.delay, key)
}
