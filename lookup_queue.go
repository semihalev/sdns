package main

import "sync"

// LQueue type
type LQueue struct {
	sync.Mutex

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
	q.Lock()
	defer q.Unlock()

	if cond, ok := q.delay[key]; ok {
		cond.Wait()
	}
}

// New func
func (q *LQueue) New(key string) {
	q.Lock()
	defer q.Unlock()

	q.delay[key] = sync.NewCond(q)
}

// Broadcast func
func (q *LQueue) Broadcast(key string) {
	q.Lock()
	defer q.Unlock()

	if cond, ok := q.delay[key]; ok {
		delete(q.delay, key)

		cond.Broadcast()
	}
}
