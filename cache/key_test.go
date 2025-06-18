package cache

import (
	"fmt"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	tests := []struct {
		name     string
		question dns.Question
		cd       []bool
		want     uint64
	}{
		{
			name: "simple A query",
			question: dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
			want: Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}),
		},
		{
			name: "AAAA query",
			question: dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			},
			want: Key(dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}),
		},
		{
			name: "case insensitive",
			question: dns.Question{
				Name:   "EXAMPLE.COM.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
			want: Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}),
		},
		{
			name: "with CD flag",
			question: dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
			cd:   []bool{true},
			want: Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, true),
		},
		{
			name: "different types same name",
			question: dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeMX,
				Qclass: dns.ClassINET,
			},
			want: Key(dns.Question{Name: "example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Key(tt.question, tt.cd...)
			assert.Equal(t, tt.want, got)

			// Verify consistency
			got2 := Key(tt.question, tt.cd...)
			assert.Equal(t, got, got2, "Key should be consistent")
		})
	}
}

func TestKeyUniqueness(t *testing.T) {
	// Test that different queries produce different keys
	keys := make(map[uint64]string)

	testCases := []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "subdomain.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS},
	}

	// Test without CD flag
	for _, q := range testCases {
		key := Key(q)
		if existing, ok := keys[key]; ok {
			t.Errorf("Key collision: %+v and %s produce same key", q, existing)
		}
		keys[key] = fmt.Sprintf("%+v", q)
	}

	// Test with CD flag
	for _, q := range testCases {
		key := Key(q, true)
		if existing, ok := keys[key]; ok {
			t.Errorf("Key collision with CD: %+v and %s produce same key", q, existing)
		}
		keys[key] = fmt.Sprintf("%+v with CD", q)
	}
}

func TestKeyConcurrency(t *testing.T) {
	// Test concurrent access to ensure pool safety
	const numGoroutines = 100
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				q := dns.Question{
					Name:   fmt.Sprintf("test%d-%d.example.com.", id, j),
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				key1 := Key(q)
				key2 := Key(q)

				if key1 != key2 {
					t.Errorf("Inconsistent keys in concurrent access: %v != %v", key1, key2)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestKeyLongDomainNames(t *testing.T) {
	// Test with domain names longer than initial buffer size
	longName := "very-long-subdomain-name-that-exceeds-thirty-two-characters.example.com."
	q := dns.Question{
		Name:   longName,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	key1 := Key(q)
	key2 := Key(q)

	assert.Equal(t, key1, key2, "Keys for long domain names should be consistent")

	// Test with mixed case
	q2 := dns.Question{
		Name:   "VERY-LONG-SUBDOMAIN-NAME-THAT-EXCEEDS-THIRTY-TWO-CHARACTERS.EXAMPLE.COM.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	key3 := Key(q2)
	assert.Equal(t, key1, key3, "Case should be normalized for long names")
}

// Benchmarks

func BenchmarkKey(b *testing.B) {
	q := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Key(q)
	}
}

func BenchmarkKeyWithCD(b *testing.B) {
	q := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Key(q, true)
	}
}

func BenchmarkKeyLongDomain(b *testing.B) {
	q := dns.Question{
		Name:   "very-long-subdomain-name-that-exceeds-thirty-two-characters.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Key(q)
	}
}

func BenchmarkKeyParallel(b *testing.B) {
	q := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Key(q)
		}
	})
}

// Benchmark to compare with non-pooled version.
func BenchmarkKeyNoPool(b *testing.B) {
	q := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = KeySimple(q)
	}
}
