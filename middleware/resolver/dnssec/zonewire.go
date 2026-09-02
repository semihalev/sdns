package dnssec

import (
	"github.com/miekg/dns"
)

// CanonicalWireRR returns one record's canonical on-the-wire form as RFC
// 4034 §6.2 defines it for zone-content digests (RFC 8976): the owner and
// the RDATA names §6.2 lists are lowercased, the record packs without
// compression, and the record's own TTL is retained, the original-TTL
// substitution belongs to signature computation, not to a digest of the
// zone as published. rdataOff is where the RDATA begins in wire, so a
// caller ordering records per §6.3 can compare RDATA without re-walking
// the owner labels.
func CanonicalWireRR(r dns.RR) (wire []byte, rdataOff int, err error) {
	r1 := dns.Copy(r)
	r1.Header().Name = dns.CanonicalName(r1.Header().Name)
	canonicalizeRdataNames(r1)

	wire = make([]byte, dns.Len(r1)+1)
	n, err := dns.PackRR(r1, wire, 0, nil, false)
	if err != nil {
		return nil, 0, err
	}
	wire = wire[:n]

	off, ok := wireRdataOffset(wire)
	if !ok {
		return nil, 0, dns.ErrRdata
	}
	return wire, off, nil
}
