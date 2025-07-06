package cache

import (
	"math/bits"
	"testing"
)

// Original hash function for comparison
func hashOriginal(key uint64) uint64 {
	key *= 0xd6e8feb86659fd93
	key = bits.RotateLeft64(key, 32) ^ key
	return key
}

// FNV-1a style hash
func hashFNV1a(key uint64) uint64 {
	key ^= key >> 33
	key *= 0xff51afd7ed558ccd
	key ^= key >> 33
	key *= 0xc4ceb9fe1a85ec53
	key ^= key >> 33
	return key
}

// Benchmark different hash functions
func BenchmarkHashFunctions(b *testing.B) {
	b.Run("Original", func(b *testing.B) {
		var sum uint64
		for i := 0; i < b.N; i++ {
			sum += hashOriginal(uint64(i))
		}
		_ = sum
	})

	b.Run("FNV1a", func(b *testing.B) {
		var sum uint64
		for i := 0; i < b.N; i++ {
			sum += hashFNV1a(uint64(i))
		}
		_ = sum
	})

	// b.Run("XXHash", func(b *testing.B) {
	// 	var sum uint64
	// 	for i := 0; i < b.N; i++ {
	// 		sum += hash64(uint64(i))
	// 	}
	// 	_ = sum
	// })
}

// Test distribution quality
func TestHashDistribution(t *testing.T) {
	const buckets = 1024
	const samples = 1000000

	testCases := []struct {
		name string
		hash func(uint64) uint64
	}{
		{"Original", hashOriginal},
		{"FNV1a", hashFNV1a},
		// {"XXHash", hash64}, // hash64 is not exported
	}

	for _, tc := range testCases {
		distribution := make([]int, buckets)

		// Sequential keys
		for i := uint64(0); i < samples; i++ {
			bucket := tc.hash(i) % buckets
			distribution[bucket]++
		}

		// Calculate standard deviation
		mean := float64(samples) / float64(buckets)
		var variance float64
		for _, count := range distribution {
			diff := float64(count) - mean
			variance += diff * diff
		}
		variance /= float64(buckets)
		stdDev := variance // simplified, actual would be sqrt(variance)

		// Find min/max
		min, max := distribution[0], distribution[0]
		for _, count := range distribution {
			if count < min {
				min = count
			}
			if count > max {
				max = count
			}
		}

		t.Logf("%s distribution: min=%d, max=%d, variance=%.2f",
			tc.name, min, max, stdDev)

		// Good distribution should have max/min ratio close to 1
		ratio := float64(max) / float64(min)
		if ratio > 1.5 {
			t.Errorf("%s: poor distribution, max/min ratio = %.2f", tc.name, ratio)
		}
	}
}
