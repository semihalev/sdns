package cache

import (
	"encoding/binary"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
)

// The record recomposer: one stored, name-compressed record re-encoded
// into a composed reply whose offsets differ from the source body's. Owner
// names and compressible rdata names are expanded from the source, and a
// name that repeats one the reply already holds in full is written as a
// pointer to it; everything else is
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

// replyName is a name written in full in the reply being composed: the
// offset and length of its uncompressed form. A zero length is none.
type replyName struct {
	off, n int
}

// replyNames is what a composed reply points a name at, without searching:
// the question, the owner of the record before, and the target of the last
// CNAME. In a composed answer those are the names the next record repeats,
// the alias is owned by the question, a target's records by the target, and
// a signature follows the RRset it covers. Only a whole-name, byte-for-byte
// match is taken, so no name is ever spelled differently for being pointed
// at. It lives on the composer's stack.
type replyNames struct {
	question, owner, target replyName
	// ownerSrc and ownerRef are the source body the owner before came from
	// and the pointer it was stored as there, when it was one: a record of
	// the same body whose owner is the same pointer has the same owner, and
	// is pointed at it without the name being expanded or compared.
	ownerSrc *byte
	ownerRef [2]byte
}

// sameStoredOwner reports whether the owner at off in src is stored as the
// very pointer the owner before was, in the same body.
func (t *replyNames) sameStoredOwner(src []byte, off int) bool {
	return t.ownerSrc != nil && t.ownerSrc == &src[0] && off+1 < len(src) &&
		src[off]&0xC0 == 0xC0 && src[off] == t.ownerRef[0] && src[off+1] == t.ownerRef[1]
}

// noteStoredOwner remembers how the owner just written was stored, for
// sameStoredOwner.
func (t *replyNames) noteStoredOwner(src []byte, off int) {
	t.ownerSrc = nil
	if off+1 < len(src) && src[off]&0xC0 == 0xC0 {
		t.ownerSrc = &src[0]
		t.ownerRef = [2]byte{src[off], src[off+1]}
	}
}

// seed records the question written at off in body.
func (t *replyNames) seed(body []byte, off int) {
	if end := wire.SkipName(body, off); end > off {
		t.question = replyName{off: off, n: end - off}
	}
}

// settle takes the name just written in full at start in dst and, when the
// same name is already in the reply in full, replaces it with a pointer
// there. It returns where the name's full form lives, for the caller to
// keep. The name is written first and compared in place, so a name that
// does not repeat costs a comparison and nothing more; a pointer is never
// longer than the name it replaces, so the lease always holds it.
func (t *replyNames) settle(dst []byte, start int) ([]byte, replyName) {
	n := len(dst) - start
	if n > 2 {
		// The owner before is the likeliest repeat, then the last target,
		// then the question. The length check keeps a miss to a compare of
		// two integers for most names.
		switch {
		case t.owner.n == n && t.sameName(dst, t.owner, start):
			return pointTo(dst, start, t.owner), t.owner
		case t.target.n == n && t.sameName(dst, t.target, start):
			return pointTo(dst, start, t.target), t.target
		case t.question.n == n && t.sameName(dst, t.question, start):
			return pointTo(dst, start, t.question), t.question
		}
	}
	return dst, replyName{off: start, n: n}
}

// sameName reports whether the name written in full as known repeats, byte
// for byte, the one at start, and can be pointed at.
func (t *replyNames) sameName(dst []byte, known replyName, start int) bool {
	return known.off <= 0x3FFF &&
		string(dst[known.off:known.off+known.n]) == string(dst[start:])
}

// pointTo replaces the name at start with a pointer to known.
func pointTo(dst []byte, start int, known replyName) []byte {
	return append(dst[:start], 0xC0|byte(known.off>>8), byte(known.off&0xFF)) //nolint:gosec // off is at most 0x3FFF
}

// appendRecomposedRR re-encodes the record rr of src into dst with the
// given TTL. When clientName is non-nil and the owner folds equal to it,
// the client's spelling is echoed (0x20 compatibility for records owned by
// the question name). With names, an owner or CNAME target that repeats a
// name the reply already holds in full is written as a pointer to it.
func appendRecomposedRR(
	dst, src []byte,
	rr wire.RR,
	ttl uint32,
	clientName []byte,
	names *replyNames,
) ([]byte, bool) {
	// Owner: a repeat of the owner before, as its stored pointer shows, is
	// pointed at it outright; any other is written in full and settled
	// against the reply.
	var ok bool
	if names != nil && names.owner.n > 0 && names.owner.off <= 0x3FFF &&
		names.sameStoredOwner(src, rr.NameOff) {
		if len(dst)+2 > cap(dst) {
			return nil, false
		}
		dst = append(dst, 0xC0|byte(names.owner.off>>8), byte(names.owner.off&0xFF)) //nolint:gosec // off is at most 0x3FFF
	} else {
		ownerStart := len(dst)
		dst, ok = wire.AppendName(dst, src, rr.NameOff)
		if !ok {
			return nil, false
		}
		if clientName != nil && foldWireNamesEqual(dst[ownerStart:], clientName) {
			copy(dst[ownerStart:], clientName)
		}
		if names != nil {
			dst, names.owner = names.settle(dst, ownerStart)
			names.noteStoredOwner(src, rr.NameOff)
		}
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
		// Re-encoded target: reserve the RDLENGTH, decompress, settle, fix.
		if len(dst)+2 > cap(dst) {
			return nil, false
		}
		rdlenOff := len(dst)
		dst = append(dst, 0, 0)
		targetStart := len(dst)
		dst, ok = wire.AppendName(dst, src, rdataOff)
		if !ok {
			return nil, false
		}
		if names != nil {
			dst, names.target = names.settle(dst, targetStart)
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
