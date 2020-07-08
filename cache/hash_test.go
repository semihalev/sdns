// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_Hash(t *testing.T) {

	q := dns.Question{Name: "goOgle.com.", Qtype: dns.TypeA, Qclass: dns.ClassANY}

	asset := Hash(q)

	assert.Equal(t, asset, uint64(9436806681948056182))

	asset = Hash(q, true)

	assert.NotEqual(t, asset, uint64(9436806681948056182))
}

func Benchmark_Hash(b *testing.B) {
	q := dns.Question{Name: "goOgle.com.", Qtype: dns.TypeA, Qclass: dns.ClassANY}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Hash(q)
	}
}
