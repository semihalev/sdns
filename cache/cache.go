// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"errors"
)

var (
	// ErrCacheNotFound error
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error
	ErrCacheExpired = errors.New("cache expired")
)

// Cache is cache.
type Cache struct {
	shards [shardSize]*shard
}

// New returns a new cache.
func New(size int) *Cache {
	ssize := size / shardSize
	if ssize < 4 {
		ssize = 4
	}

	c := &Cache{}

	// Initialize all the shards
	for i := 0; i < shardSize; i++ {
		c.shards[i] = newShard(ssize)
	}
	return c
}

// Get looks up element index under key.
func (c *Cache) Get(key uint64) (interface{}, bool) {
	shard := key & (shardSize - 1)
	return c.shards[shard].Get(key)
}

// Add adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) Add(key uint64, el interface{}) {
	shard := key & (shardSize - 1)
	c.shards[shard].Add(key, el)
}

// Remove removes the element indexed with key.
func (c *Cache) Remove(key uint64) {
	shard := key & (shardSize - 1)
	c.shards[shard].Remove(key)
}

// Len returns the number of elements in the cache.
func (c *Cache) Len() int {
	l := 0
	for _, s := range c.shards {
		l += s.Len()
	}
	return l
}
