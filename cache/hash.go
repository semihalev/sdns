package cache

import (
	"encoding/binary"
	"hash/fnv"

	"github.com/miekg/dns"
)

// Hash returns a hash for cache
func Hash(q dns.Question) uint64 {
	h := fnv.New64()

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, q.Qtype)
	h.Write(b)

	for i := range q.Name {
		c := q.Name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h.Write([]byte{c})
	}

	return h.Sum64()
}
