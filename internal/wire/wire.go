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

// Flag bits within Header.Flags (RFC 1035 §4.1.1 layout).
const (
	FlagRcodeMask = 0x000F
	FlagCD        = 1 << 4  // checking disabled
	FlagAD        = 1 << 5  // authenticated data (RFC 4035 §3.1.6)
	FlagRA        = 1 << 7  // recursion available
	FlagRD        = 1 << 8  // recursion desired
	FlagTC        = 1 << 9  // truncated
	FlagAA        = 1 << 10 // authoritative answer
	FlagOpcodeSh  = 11      // opcode occupies bits 11-14
	FlagOpcodeMsk = 0xF << FlagOpcodeSh
	FlagQR        = 1 << 15 // response
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

// QR reports the response bit.
func (h Header) QR() bool { return h.Flags&0x8000 != 0 }

// Opcode extracts the operation code from the flags word.
func (h Header) Opcode() int { return int(h.Flags>>11) & 0xF }

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

// ApplyReply stamps onto a packed response the header fields miekg's
// SetReply derives from the request, plus the cache's own reply shaping:
// the request ID, QR, the request opcode, the copied RD/CD bits, and a
// cleared AA (a cached answer is never authoritative). RA and TC are left
// as stored, matching the message path.
func ApplyReply(body []byte, id uint16, opcode int, rd, cd bool) {
	if len(body) < HeaderLen {
		return
	}
	binary.BigEndian.PutUint16(body[0:2], id)

	flags := binary.BigEndian.Uint16(body[2:4])
	flags |= FlagQR
	flags &^= FlagAA
	flags = (flags &^ FlagOpcodeMsk) | (uint16(opcode)<<FlagOpcodeSh)&FlagOpcodeMsk //nolint:gosec // masked to the 4-bit opcode field
	if rd {
		flags |= FlagRD
	} else {
		flags &^= FlagRD
	}
	if cd {
		flags |= FlagCD
	} else {
		flags &^= FlagCD
	}
	binary.BigEndian.PutUint16(body[2:4], flags)
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

// AppendName appends the uncompressed wire form of the (possibly
// compressed) name starting at off in src. ok is false on malformed
// input, a name exceeding 255 octets, or insufficient dst capacity — the
// append never grows dst's backing array, so a caller composing into a
// fixed lease can treat false as a clean refusal.
func AppendName(dst, src []byte, off int) ([]byte, bool) {
	const maxJumps = 32
	written, jumps := 0, 0
	for {
		if off < 0 || off >= len(src) {
			return dst, false
		}
		c := int(src[off])
		switch {
		case c == 0:
			if written+1 > 255 || len(dst)+1 > cap(dst) {
				return dst, false
			}
			return append(dst, 0), true
		case c&0xC0 == 0xC0:
			if off+1 >= len(src) {
				return dst, false
			}
			jumps++
			if jumps > maxJumps {
				return dst, false
			}
			off = int(src[off]&0x3F)<<8 | int(src[off+1])
		case c&0xC0 != 0:
			return dst, false
		default:
			if off+1+c > len(src) || written+1+c > 255 || len(dst)+1+c > cap(dst) {
				return dst, false
			}
			dst = append(dst, src[off:off+1+c]...)
			written += 1 + c
			off += 1 + c
		}
	}
}

// SetRcode overwrites the header's 4-bit RCODE field.
func SetRcode(body []byte, rcode int) {
	if len(body) >= HeaderLen {
		body[3] = body[3]&0xF0 | byte(rcode&0x0F) //nolint:gosec // masked to the 4-bit field
	}
}

// SetRA sets the recursion-available bit.
func SetRA(body []byte) {
	if len(body) >= HeaderLen {
		body[3] |= 0x80
	}
}

// SetAD sets the authenticated-data bit.
func SetAD(body []byte) {
	if len(body) >= HeaderLen {
		body[3] |= 0x20
	}
}

// SetTTL stamps a TTL value at a previously recorded offset.
func SetTTL(body []byte, ttlOff int, ttl uint32) {
	if ttlOff >= 0 && ttlOff+4 <= len(body) {
		binary.BigEndian.PutUint32(body[ttlOff:], ttl)
	}
}

// OPT record geometry (RFC 6891 §6.1.2).
const (
	// OPTFixedLen is the record's size before any option: the root owner
	// name, TYPE, CLASS (the requestor's UDP size), TTL (extended RCODE,
	// version and flags) and RDLENGTH.
	OPTFixedLen = 11
	// OPTOptionHdrLen is the per-option code and length prefix.
	OPTOptionHdrLen = 4

	optDOFlag = 1 << 15 // DNSSEC OK, the high bit of the OPT TTL field
)

// AppendOPTHeader writes an OPT record's fixed part and returns the buffer
// along with the offset of its RDLENGTH field, which FinishOPT fills in
// once the options are known. Encoding the record directly avoids building
// a dns.OPT and its option objects only for the library to pack them —
// and, for options carried as hex text, avoids encoding bytes to hex just
// so the packer can decode them back.
func AppendOPTHeader(dst []byte, udpSize uint16, do bool) ([]byte, int) {
	dst = append(dst, 0) // root owner name
	dst = binary.BigEndian.AppendUint16(dst, 41)
	dst = binary.BigEndian.AppendUint16(dst, udpSize)
	var ttl uint32
	if do {
		ttl |= optDOFlag
	}
	dst = binary.BigEndian.AppendUint32(dst, ttl)
	rdlenOff := len(dst)
	return append(dst, 0, 0), rdlenOff
}

// AppendOption writes one EDNS0 option in wire form.
//
// Options are written as the bytes the wire carries. Several of them —
// NSID and the cookies among them — are held in text form by the library's
// option types and hex-decoded during packing, so producing that text only
// to have it decoded back is pure waste on a hot path.
func AppendOption(dst []byte, code uint16, data []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, code)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(data))) //nolint:gosec // callers bound option data to the message size
	return append(dst, data...)
}

// AppendOptionString is AppendOption for an option whose payload is already
// held as a string, appended without a byte-slice conversion.
func AppendOptionString(dst []byte, code uint16, data string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, code)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(data))) //nolint:gosec // callers bound option data to the message size
	return append(dst, data...)
}

// optCodeEDE is the RFC 8914 Extended DNS Error option code.
const optCodeEDE = 15

// AppendOptionEDE writes an RFC 8914 Extended DNS Error option — the
// two-byte info code followed by the extra text — without materializing a
// payload buffer or a library option object.
func AppendOptionEDE(dst []byte, infoCode uint16, text string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, optCodeEDE)
	dst = binary.BigEndian.AppendUint16(dst, uint16(2+len(text))) //nolint:gosec // callers bound option data to the message size
	dst = binary.BigEndian.AppendUint16(dst, infoCode)
	return append(dst, text...)
}

// FinishOPT records the RDLENGTH of the options written since
// AppendOPTHeader returned rdlenOff.
func FinishOPT(dst []byte, rdlenOff int) []byte {
	if rdlenOff < 0 || rdlenOff+2 > len(dst) {
		return dst
	}
	binary.BigEndian.PutUint16(dst[rdlenOff:], uint16(len(dst)-rdlenOff-2)) //nolint:gosec // bounded by the message size
	return dst
}
