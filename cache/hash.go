package cache

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"

	"github.com/miekg/dns"
)

// Hash returns a hash for cache
func Hash(q dns.Question, cd ...bool) uint64 {
	h := fnv.New64()
	buf := bytes.NewBuffer(nil)

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

// HashZone returns a hash for cache
func HashZone(q dns.Question, cd ...bool) uint64 {
	h := fnv.New64()
	buf := bytes.NewBuffer(nil)

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
