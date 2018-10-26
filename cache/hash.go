package cache

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"

	"github.com/miekg/dns"
)

// Hash returns a hash for cache
func Hash(q dns.Question) uint64 {
	h := fnv.New64()
	buf := bytes.NewBuffer(nil)

	binary.Write(buf, binary.BigEndian, q.Qtype)

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
