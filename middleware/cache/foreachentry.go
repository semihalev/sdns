package cache

// ForEachEntry iterates over positive and negative cache entries.
// Iteration is not atomic with concurrent updates.
// Returning false from fn stops iteration.
func (c *Cache) ForEachEntry(fn func(positive bool, key uint64, entry *CacheEntry) bool) {
	c.store.ForEach(fn)
}
