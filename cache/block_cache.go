package cache

import (
	"errors"
	"strings"
	"sync"
)

// BlockCache type
type BlockCache struct {
	mu sync.RWMutex

	m map[string]bool
}

// NewBlockCache returns a new blockcache
func NewBlockCache() *BlockCache {
	return &BlockCache{
		m: make(map[string]bool),
	}
}

// Get returns the entry for a key or an error
func (c *BlockCache) Get(key string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key = strings.ToLower(key)
	val, ok := c.m[key]

	if !ok {
		return false, errors.New("block not found")
	}

	return val, nil
}

// Remove removes an entry from the cache
func (c *BlockCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key = strings.ToLower(key)
	delete(c.m, key)
}

// Set sets a value in the BlockCache
func (c *BlockCache) Set(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key = strings.ToLower(key)
	c.m[key] = true
}

// Exists returns whether or not a key exists in the cache
func (c *BlockCache) Exists(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key = strings.ToLower(key)
	_, ok := c.m[key]

	return ok
}

// Length returns the caches length
func (c *BlockCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.m)
}
