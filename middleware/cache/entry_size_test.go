package cache

import (
	"testing"
	"unsafe"
)

// An entry is paid for once per cached answer, a million times over on a
// busy resolver, so its size is held here. A field that grows it past this
// should earn its place against the memory it costs, and move what only few
// entries use into entryRare.
func TestCacheEntrySize(t *testing.T) {
	const limit = 160
	if got := unsafe.Sizeof(CacheEntry{}); got > limit {
		t.Fatalf("CacheEntry is %d bytes, over the %d it is held to", got, limit)
	}
}
