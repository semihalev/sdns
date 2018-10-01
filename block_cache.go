package main

import (
	"strings"
	"sync"

	glob "github.com/ryanuber/go-glob"
)

const (
	// BlockCacheEntryString const
	BlockCacheEntryString = iota
	// BlockCacheEntryRegexp const
	BlockCacheEntryRegexp
	// BlockCacheEntryGlob const
	BlockCacheEntryGlob
)

// BlockCacheSpecial type
type BlockCacheSpecial struct {
	Data string
	Type int
}

// MemoryBlockCache type
type MemoryBlockCache struct {
	Backend map[string]bool
	Special []BlockCacheSpecial
	mu      sync.RWMutex
}

// Get returns the entry for a key or an error
func (c *MemoryBlockCache) Get(key string) (bool, error) {
	key = strings.ToLower(key)

	c.mu.RLock()
	val, ok := c.Backend[key]
	c.mu.RUnlock()

	if !ok {
		return false, KeyNotFound{key}
	}

	return val, nil
}

// Remove removes an entry from the cache
func (c *MemoryBlockCache) Remove(key string) {
	key = strings.ToLower(key)

	c.mu.Lock()
	delete(c.Backend, key)
	c.mu.Unlock()
}

// Set sets a value in the BlockCache
func (c *MemoryBlockCache) Set(key string, value bool) error {
	key = strings.ToLower(key)
	const globChars = "?*"

	c.mu.Lock()
	if strings.ContainsAny(key, globChars) {
		c.Special = append(
			c.Special,
			BlockCacheSpecial{Data: key, Type: BlockCacheEntryGlob})
	} else {
		c.Backend[key] = value
	}
	c.mu.Unlock()

	return nil
}

// Exists returns whether or not a key exists in the cache
func (c *MemoryBlockCache) Exists(key string) bool {
	key = strings.ToLower(key)

	c.mu.RLock()
	_, ok := c.Backend[key]
	if !ok {
		for _, element := range c.Special {
			if element.Type == BlockCacheEntryRegexp {
				panic("Unsupported")
			} else if element.Type == BlockCacheEntryGlob {
				if glob.Glob(element.Data, key) {
					ok = true
				}
			}
		}
	}
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *MemoryBlockCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Backend)
}
