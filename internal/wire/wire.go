// Package wire provides zero-allocation cursors over packed DNS messages.
//
// Full Msg.Unpack materializes every record as a heap graph; most byte-path
// consumers need only the header, one section's skeleton, or a handful of
// fixed-position fields. These helpers read exactly the bytes a caller asks
// about and nothing else, so sectional inspection stays off the allocator
// entirely and a future partial decode (unpack just the answers, just the
// authority) can build on the same offsets.
package wire

import "encoding/binary"

// HeaderLen is the fixed DNS header size (RFC 1035 §4.1.1).
const HeaderLen = 12

// Flag bits within Header.Flags.
const (
	FlagAD = 1 << 5 // authenticated data (RFC 4035 §3.1.6)
	FlagTC = 1 << 9 // truncated
)

// Header is the fixed-size DNS message header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Rcode extracts the response code from the flags word.
func (h Header) Rcode() int { return int(h.Flags & 0x0F) }

// AD reports the authenticated-data bit.
func (h Header) AD() bool { return h.Flags&FlagAD != 0 }

// ParseHeader reads the fixed header. ok is false when the body is short.
func ParseHeader(body []byte) (Header, bool) {
	if len(body) < HeaderLen {
		return Header{}, false
	}
	return Header{
		ID:      binary.BigEndian.Uint16(body[0:2]),
		Flags:   binary.BigEndian.Uint16(body[2:4]),
		QDCount: binary.BigEndian.Uint16(body[4:6]),
		ANCount: binary.BigEndian.Uint16(body[6:8]),
		NSCount: binary.BigEndian.Uint16(body[8:10]),
		ARCount: binary.BigEndian.Uint16(body[10:12]),
	}, true
}

// SetID stamps a message ID in place.
func SetID(body []byte, id uint16) {
	if len(body) >= 2 {
		binary.BigEndian.PutUint16(body[0:2], id)
	}
}

// SetARCount stamps the additional-section count in place.
func SetARCount(body []byte, n uint16) {
	if len(body) >= HeaderLen {
		binary.BigEndian.PutUint16(body[10:12], n)
	}
}

// ClearAD clears the authenticated-data bit in place.
func ClearAD(body []byte) {
	if len(body) >= 4 {
		body[3] &^= FlagAD
	}
}

// SkipName advances past a (possibly compressed) domain name starting at
// off and returns the offset of the first byte after it, or -1 when the
// name is malformed or runs past the body.
func SkipName(body []byte, off int) int {
	for off < len(body) {
		c := int(body[off])
		switch {
		case c == 0:
			return off + 1
		case c&0xC0 == 0xC0:
			if off+2 > len(body) {
				return -1
			}
			return off + 2
		case c&0xC0 != 0:
			return -1 // reserved label types
		default:
			off += 1 + c
		}
	}
	return -1
}

// Question is the skeleton of one question entry.
type Question struct {
	NameOff int // start of the owner name (== HeaderLen for the first)
	NameLen int // packed name length in bytes
	Qtype   uint16
	Qclass  uint16
	End     int // offset of the first byte after this question
}

// ParseQuestion reads the question at off. ok is false on malformed input.
func ParseQuestion(body []byte, off int) (Question, bool) {
	nameEnd := SkipName(body, off)
	if nameEnd < 0 || nameEnd+4 > len(body) {
		return Question{}, false
	}
	return Question{
		NameOff: off,
		NameLen: nameEnd - off,
		Qtype:   binary.BigEndian.Uint16(body[nameEnd:]),
		Qclass:  binary.BigEndian.Uint16(body[nameEnd+2:]),
		End:     nameEnd + 4,
	}, true
}

// RR is the skeleton of one resource record: fixed-field offsets without
// any rdata interpretation. TTLOff is the field byte-patch serving needs;
// End lets an iterator continue to the next record.
type RR struct {
	NameOff int
	Type    uint16
	Class   uint16
	TTLOff  int
	RDLen   int
	End     int
}

// ParseRR reads the record skeleton at off. ok is false on malformed input.
func ParseRR(body []byte, off int) (RR, bool) {
	nameEnd := SkipName(body, off)
	if nameEnd < 0 || nameEnd+10 > len(body) {
		return RR{}, false
	}
	rdlen := int(binary.BigEndian.Uint16(body[nameEnd+8:]))
	end := nameEnd + 10 + rdlen
	if end > len(body) {
		return RR{}, false
	}
	return RR{
		NameOff: off,
		Type:    binary.BigEndian.Uint16(body[nameEnd:]),
		Class:   binary.BigEndian.Uint16(body[nameEnd+2:]),
		TTLOff:  nameEnd + 4,
		RDLen:   rdlen,
		End:     end,
	}, true
}

// SetTTL stamps a TTL value at a previously recorded offset.
func SetTTL(body []byte, ttlOff int, ttl uint32) {
	if ttlOff >= 0 && ttlOff+4 <= len(body) {
		binary.BigEndian.PutUint32(body[ttlOff:], ttl)
	}
}
