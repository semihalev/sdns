package blocklist

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/semihalev/sdns/config"
)

func BenchmarkBlocklistExists(b *testing.B) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_bench")

	blocklist := New(cfg)

	// Add various entries to simulate a large blocklist
	sizes := []int{1000, 10000, 50000, 100000, 200000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			// Reset blocklist
			blocklist = New(cfg)

			// Add exact matches
			for i := 0; i < size*80/100; i++ { // 80% exact matches
				domain := fmt.Sprintf("blocked%d.com.", i)
				blocklist.set(domain)
			}

			// Add wildcards
			for i := 0; i < size*20/100; i++ { // 20% wildcards
				domain := fmt.Sprintf("*.wild%d.com.", i)
				blocklist.set(domain)
			}

			// Test domains
			testDomains := []string{
				"blocked999.com.",      // Should be found (exact)
				"sub.wild100.com.",     // Should be found (wildcard)
				"notblocked.com.",      // Should not be found
				"deep.sub.wild50.com.", // Should be found (wildcard)
				"blocked50000.com.",    // Should be found if size >= 50000
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for _, domain := range testDomains {
					_ = blocklist.Exists(domain)
				}
			}
		})
	}
}

func BenchmarkBlocklistExistsWorstCase(b *testing.B) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_bench_worst")

	blocklist := New(cfg)

	// Add 200k entries
	for i := 0; i < 160000; i++ { // 80% exact matches
		domain := fmt.Sprintf("blocked%d.com.", i)
		blocklist.set(domain)
	}

	for i := 0; i < 40000; i++ { // 20% wildcards
		domain := fmt.Sprintf("*.wild%d.com.", i)
		blocklist.set(domain)
	}

	// Test with domains that don't exist (worst case - checks all wildcards)
	testDomain := "this.domain.does.not.exist.com."

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = blocklist.Exists(testDomain)
	}
}

func BenchmarkBlocklistMemory(b *testing.B) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_bench_mem")

	b.Run("memory_200k", func(b *testing.B) {
		blocklist := New(cfg)

		b.ResetTimer()

		// Add 200k entries
		for i := 0; i < 160000; i++ {
			domain := fmt.Sprintf("blocked%d.com.", i)
			blocklist.set(domain)
		}

		for i := 0; i < 40000; i++ {
			domain := fmt.Sprintf("*.wild%d.com.", i)
			blocklist.set(domain)
		}

		b.ReportAllocs()
	})
}
