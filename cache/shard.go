// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import "sync"

// shard is a cache with random eviction.
type shard struct {
	items map[uint64]interface{}
	size  int

	sync.RWMutex
}

// newShard returns a new shard with size.
func newShard(size int) *shard { return &shard{items: make(map[uint64]interface{}), size: size} }

// Add adds element indexed by key into the cache. Any existing element is overwritten
func (s *shard) Add(key uint64, el interface{}) {
	l := s.Len()
	if l+1 > s.size {
		s.Evict()
	}

	s.Lock()
	s.items[key] = el
	s.Unlock()
}

// Remove removes the element indexed by key from the cache.
func (s *shard) Remove(key uint64) {
	s.Lock()
	delete(s.items, key)
	s.Unlock()
}

// Evict removes a random element from the cache.
func (s *shard) Evict() {
	hasKey := false
	var key uint64

	s.RLock()
	for k := range s.items {
		key = k
		hasKey = true
		break
	}
	s.RUnlock()

	if !hasKey {
		// empty cache
		return
	}

	// If this item is gone between the RUnlock and Lock race we don't care.
	s.Remove(key)
}

// Get looks up the element indexed under key.
func (s *shard) Get(key uint64) (interface{}, bool) {
	s.RLock()
	el, found := s.items[key]
	s.RUnlock()
	return el, found
}

// Len returns the current length of the cache.
func (s *shard) Len() int {
	s.RLock()
	l := len(s.items)
	s.RUnlock()
	return l
}

const shardSize = 256
