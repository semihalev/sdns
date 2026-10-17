package server

import (
	"fmt"
	"math"

	"github.com/semihalev/zlog/v2"
)

const (
	cacheMemoryBaseBytes      uint64 = 50_000_000
	cacheMemoryPerAnswerBytes uint64 = 2_500
	defaultCacheEntries              = 1024
	bytesPerGigabyte          uint64 = 1_000_000_000
)

// cacheMemoryEstimate is the approximate resident memory at full cache
// occupancy. A zero size uses the cache's default capacity.
func cacheMemoryEstimate(cacheSize int) uint64 {
	if cacheSize == 0 {
		cacheSize = defaultCacheEntries
	}
	entries := uint64(cacheSize)
	if entries > (math.MaxUint64-cacheMemoryBaseBytes)/cacheMemoryPerAnswerBytes {
		return math.MaxUint64
	}
	return cacheMemoryBaseBytes + entries*cacheMemoryPerAnswerBytes
}

func formatMemoryGB(bytes uint64) string {
	return fmt.Sprintf("%.1f GB", float64(bytes)/float64(bytesPerGigabyte))
}

// cacheMemoryWarning returns an advisory message when the estimated full
// cache exceeds a known memory budget. A zero budget means unavailable.
func cacheMemoryWarning(cacheSize int, budget uint64) string {
	if budget == 0 {
		return ""
	}
	needed := cacheMemoryEstimate(cacheSize)
	if needed <= budget {
		return ""
	}
	if cacheSize == 0 {
		cacheSize = defaultCacheEntries
	}
	return fmt.Sprintf("cachesize %d needs about %s at full occupancy, the memory budget is %s",
		cacheSize, formatMemoryGB(needed), formatMemoryGB(budget))
}

// WarnCacheSizeMemory reports when the configured cache may exceed the
// process's memory budget. It never rejects or changes the configuration.
func WarnCacheSizeMemory(cacheSize int) {
	if warning := cacheMemoryWarning(cacheSize, memoryBudget()); warning != "" {
		zlog.Warn(warning)
	}
}
