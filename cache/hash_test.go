package cache

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_Hash(t *testing.T) {

	q := dns.Question{Name: "@", Qtype: dns.TypeA, Qclass: dns.ClassANY}

	asset := Hash(q)

	assert.Equal(t, asset, uint64(15658190276026904132))
}

func Benchmark_Hash(b *testing.B) {
	q := dns.Question{Name: "@", Qtype: dns.TypeA, Qclass: dns.ClassANY}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Hash(q)
	}
}
