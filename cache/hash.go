// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"bytes"
	"hash"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
)

// Hash returns a hash for cache
func Hash(q dns.Question, cd ...bool) uint64 {
	h := AcquireHash()
	defer ReleaseHash(h)

	buf := AcquireBuf()
	defer ReleaseBuf(buf)

	buf.Write([]byte{uint8(q.Qtype >> 8), uint8(q.Qtype & 0xff)})

	if len(cd) > 0 && cd[0] {
		buf.WriteByte(1)
	}

	for i := range q.Name {
		c := q.Name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf.WriteByte(c)
	}

	_, _ = h.Write(buf.Bytes())

	return h.Sum64()
}

var bufferPool sync.Pool
var hashPool sync.Pool

// AcquireHash returns a hash from pool
func AcquireHash() hash.Hash64 {
	v := hashPool.Get()
	if v == nil {
		return xxhash.New()
	}
	return v.(hash.Hash64)
}

// ReleaseHash returns hash to pool
func ReleaseHash(h hash.Hash64) {
	h.Reset()
	hashPool.Put(h)
}

// AcquireBuf returns a buf from pool
func AcquireBuf() *bytes.Buffer {
	v := bufferPool.Get()
	if v == nil {
		return &bytes.Buffer{}
	}
	return v.(*bytes.Buffer)
}

// ReleaseBuf returns buf to pool
func ReleaseBuf(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}
