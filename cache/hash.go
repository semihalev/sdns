package cache

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"sync"

	"github.com/miekg/dns"
)

// Hash returns a hash for cache
func Hash(q dns.Question, cd ...bool) uint64 {
	h := fnv.New64()
	buf := AcquireBuf()
	defer ReleaseBuf(buf)

	binary.Write(buf, binary.BigEndian, q.Qtype)

	if len(cd) > 0 && cd[0] == true {
		buf.WriteByte(1)
	}

	for i := range q.Name {
		c := q.Name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf.WriteByte(c)
	}

	h.Write(buf.Bytes())

	return h.Sum64()
}

var bufferPool sync.Pool

// AcquireBuf returns an buf from pool
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
