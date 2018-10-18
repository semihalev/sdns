package main

import "sync"

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
func (q *LQueue) Get(key string) chan struct{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if ch, ok := q.delay[key]; ok {
		return ch
	}

	return nil
}

// Set func
func (q *LQueue) Set(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.delay[key] = make(chan struct{})
}

// Remove func
func (q *LQueue) Remove(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if ch, ok := q.delay[key]; ok {
		ch <- struct{}{}

		close(ch)
	}

	delete(q.delay, key)
}
