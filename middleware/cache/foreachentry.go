package cache

import "github.com/semihalev/sdns/cache"

// ForEachEntry iterates over positive and negative cache entries.
// Iteration is not atomic with concurrent updates.
// Returning false from fn stops iteration.
func (c *Cache) ForEachEntry(fn func(positive bool, key uint64, entry *CacheEntry) bool) {
	keepGoing := true
	for _, cache := range []*cache.Cache{c.positive.cache, c.negative.cache} {
		cache.ForEach(func(key uint64, value any) bool {
			if keepGoing {
				if entry, ok := value.(*CacheEntry); ok && entry != nil {
					keepGoing = fn(cache == c.positive.cache, key, entry)
				}
			}
			return keepGoing
		})
	}
}
