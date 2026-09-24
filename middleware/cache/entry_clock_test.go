package cache

import "time"

// setStoredAt moves an entry's admission instant to t, the way tests age an
// entry without waiting.
func (e *CacheEntry) setStoredAt(t time.Time) { e.stored = monoOffset(t) }
