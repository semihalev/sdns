// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_Hash(t *testing.T) {

	q := dns.Question{Name: "goOgle.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	asset := Hash(q)

	assert.Equal(t, uint64(13726664550454464700), asset)

	asset = Hash(q, true)

	assert.Equal(t, uint64(8882204296994448420), asset)
}

func Benchmark_Hash(b *testing.B) {
	q := dns.Question{Name: "goOgle.com.", Qtype: dns.TypeA, Qclass: dns.ClassANY}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Hash(q)
	}
}
