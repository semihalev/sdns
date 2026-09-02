package cache

import (
	"encoding/binary"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
)

// The record recomposer: one stored, name-compressed record re-encoded
// into a composed reply whose offsets differ from the source body's. Owner
// names and compressible rdata names are decompressed; everything else is
// copied verbatim, which is only sound for types whose rdata cannot carry
// a compressed name. Every append is capacity-guarded against the caller's
// lease, so composition never allocates and refuses cleanly when it does
// not fit.

// wireRecomposable reports whether appendRecomposedRR can re-encode a
// record of this type. CNAME and SOA are rewritten (their rdata names may
// be compressed); the rest are verbatim-safe: their rdata is name-free or
// their names are packed uncompressed (RRSIG signer per RFC 4034 §6.2,
// NSEC next-domain per RFC 4034 §4.1.1, miekg's packer honors both).
func wireRecomposable(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeCNAME, dns.TypeSOA,
		dns.TypeA, dns.TypeAAAA, dns.TypeTXT,
		dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDS:
		return true
	}
	return false
}

// appendRecomposedRR re-encodes the record rr of src into dst with the
// given TTL. When clientName is non-nil and the owner folds equal to it,
// the client's spelling is echoed (0x20 compatibility for records owned by
// the question name).
func appendRecomposedRR(
	dst, src []byte,
	rr wire.RR,
	ttl uint32,
	clientName []byte,
) ([]byte, bool) {
	// Owner, uncompressed.
	ownerStart := len(dst)
	dst, ok := wire.AppendName(dst, src, rr.NameOff)
	if !ok {
		return nil, false
	}
	if clientName != nil && foldWireNamesEqual(dst[ownerStart:], clientName) {
		copy(dst[ownerStart:], clientName)
	}
	// TYPE and CLASS verbatim, the caller's TTL.
	nameEnd := rr.TTLOff - 4
	if dst, ok = appendCapped(dst, src[nameEnd:nameEnd+4]); !ok {
		return nil, false
	}
	if len(dst)+4 > cap(dst) {
		return nil, false
	}
	dst = binary.BigEndian.AppendUint32(dst, ttl)

	rdataOff := rr.End - rr.RDLen
	switch rr.Type {
	case dns.TypeCNAME:
		// Re-encoded target: reserve the RDLENGTH, decompress, fix.
		if len(dst)+2 > cap(dst) {
			return nil, false
		}
		rdlenOff := len(dst)
		dst = append(dst, 0, 0)
		dst, ok = wire.AppendName(dst, src, rdataOff)
		if !ok {
			return nil, false
		}
		binary.BigEndian.PutUint16(dst[rdlenOff:], uint16(len(dst)-rdlenOff-2)) //nolint:gosec // a name is at most 255 octets
	case dns.TypeSOA:
		// MNAME and RNAME re-encoded, the five fixed counters verbatim.
		if len(dst)+2 > cap(dst) {
			return nil, false
		}
		rdlenOff := len(dst)
		dst = append(dst, 0, 0)
		dst, ok = wire.AppendName(dst, src, rdataOff)
		if !ok {
			return nil, false
		}
		mnameEnd := wire.SkipName(src, rdataOff)
		if mnameEnd < 0 {
			return nil, false
		}
		dst, ok = wire.AppendName(dst, src, mnameEnd)
		if !ok {
			return nil, false
		}
		rnameEnd := wire.SkipName(src, mnameEnd)
		if rnameEnd < 0 || rr.End-rnameEnd != 20 {
			return nil, false
		}
		if dst, ok = appendCapped(dst, src[rnameEnd:rr.End]); !ok {
			return nil, false
		}
		binary.BigEndian.PutUint16(dst[rdlenOff:], uint16(len(dst)-rdlenOff-2)) //nolint:gosec // two names and five counters
	default:
		if !wireRecomposable(rr.Type) {
			return nil, false
		}
		// RDLENGTH and rdata verbatim.
		if dst, ok = appendCapped(dst, src[rdataOff-2:rr.End]); !ok {
			return nil, false
		}
	}
	return dst, true
}
