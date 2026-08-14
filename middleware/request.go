package middleware

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/ecs"
	"github.com/semihalev/sdns/internal/wire"
)

// Request is the one request representation the chain carries. It is
// wire-first: a strict-path request is born from the raw packet with every
// fact the default chain needs parsed as offsets and scalars, and no
// decoded message exists until a handler asks for one through
// Chain.Materialize. A request born from an already decoded message (the
// internal sub-pipeline, DoH/DoQ, embedders, tests) starts with Msg set and
// the accessors read through it.
//
// Raw borrows the transport job's receive buffer: it is valid until the job
// is released, which happens only after the middleware unwind completes.
// Nothing may retain it (zero-path contract §2).
//
// Accessors report the client's original request facts. Materialization is
// one-way — wire → normalized → Msg — and never rewrites the parsed facts,
// so a handler that only needs the question or the EDNS shape never pays
// for decoding.
type Request struct {
	raw []byte

	id     uint16
	flags  uint16
	qtype  uint16
	qclass uint16

	// Question name region within raw (wire form, uncompressed).
	nameOff, nameLen int
	// questionEnd is the offset just past the question section.
	questionEnd int

	// OPT facts (zero-valued when the request carried no OPT).
	hasOPT    bool
	udpSize   uint16
	do        bool
	version   uint8
	hasECS    bool
	hasNSID   bool
	cookieOff int // raw client cookie bytes within raw; 0 when absent
	cookieLen int

	// readTime is when the transport read the packet; the effective
	// deadline is readTime + the query timeout, carried by the job carrier.
	readTime time.Time

	// ednsWriterSlot optionally points at job-owned storage for the edns
	// writer wrapper, so the strict path does not draw it from a pool.
	ednsWriterSlot any

	// msg is the decoded form: set at birth for message-born requests, by
	// materialize for wire-born ones, nil until then.
	msg *dns.Msg

	// Normalization state recorded by the edns handler's wire branch so
	// materialization can produce the normalized message.
	ednsRan    bool
	ecsPolicy  *ecs.Policy
	clientAddr netip.Addr
}

// SetMsg initializes the request from an already decoded message.
func (r *Request) SetMsg(m *dns.Msg) {
	*r = Request{msg: m}
}

// NewRequest returns a message-born Request. Chain.Reset does this with
// pooled storage; this constructor serves callers building chains by hand.
func NewRequest(m *dns.Msg) *Request {
	r := new(Request)
	r.SetMsg(m)
	return r
}

// Msg returns the decoded request, decoding a wire-born one on first
// call. It never returns nil for a request the chain accepted, so the
// mechanical migration from the old `ch.Request` (a *dns.Msg) is safe:
// reading the message costs a decode, it does not panic.
//
// The decode alone is not the whole transition, though. A handler that
// goes on to call Next must not hand the job carrier to downstream
// handlers — Chain.Next detects a request materialized this way and
// detaches for them. A handler that needs the detached context for its
// own work (it starts recursion, derives a deadline, pins request-tree
// state) asks for both at once with Chain.Materialize.
func (r *Request) Msg() *dns.Msg {
	if r.msg == nil {
		return r.materialize()
	}
	return r.msg
}

// Undecoded reports whether the request is still wire-only — no message
// has been built for it. It is the gate a handler puts in front of its
// wire branch: reading it never triggers a decode, where Msg does.
func (r *Request) Undecoded() bool { return r.msg == nil }

// decoded returns the decoded message without triggering a decode: the
// chain's own probe for "has this request left the wire path yet".
func (r *Request) decoded() *dns.Msg { return r.msg }

// wireBorn reports whether this request entered as raw bytes.
func (r *Request) wireBorn() bool { return r.raw != nil }

// Raw returns the raw packet, or nil for a message-born request.
func (r *Request) Raw() []byte { return r.raw }

// ReadTime returns the transport read time (zero for message-born requests).
func (r *Request) ReadTime() time.Time { return r.readTime }

// EDNSWriterSlot returns job-owned storage for the edns writer wrapper, if
// the transport offered one.
func (r *Request) EDNSWriterSlot() any { return r.ednsWriterSlot }

// ID returns the request's DNS message ID.
func (r *Request) ID() uint16 {
	if r.msg != nil {
		return r.msg.Id
	}
	return r.id
}

// Qtype returns the question type.
func (r *Request) Qtype() uint16 {
	if r.msg != nil {
		if len(r.msg.Question) > 0 {
			return r.msg.Question[0].Qtype
		}
		return 0
	}
	return r.qtype
}

// Qclass returns the question class.
func (r *Request) Qclass() uint16 {
	if r.msg != nil {
		if len(r.msg.Question) > 0 {
			return r.msg.Question[0].Qclass
		}
		return 0
	}
	return r.qclass
}

// RD reports the recursion-desired bit.
func (r *Request) RD() bool {
	if r.msg != nil {
		return r.msg.RecursionDesired
	}
	return r.flags&0x0100 != 0
}

// CD reports the checking-disabled bit.
func (r *Request) CD() bool {
	if r.msg != nil {
		return r.msg.CheckingDisabled
	}
	return r.flags&0x0010 != 0
}

// AD reports the authenticated-data bit as the client sent it.
func (r *Request) AD() bool {
	if r.msg != nil {
		return r.msg.AuthenticatedData
	}
	return r.flags&0x0020 != 0
}

// Opcode extracts the opcode.
func (r *Request) Opcode() int {
	if r.msg != nil {
		return r.msg.Opcode
	}
	return int(r.flags>>11) & 0xF
}

// HasOPT reports whether the request carried an OPT record.
func (r *Request) HasOPT() bool {
	if r.msg != nil {
		return r.msg.IsEdns0() != nil
	}
	return r.hasOPT
}

// UDPSize returns the client's advertised EDNS UDP size (0 without OPT).
func (r *Request) UDPSize() uint16 {
	if r.msg != nil {
		if opt := r.msg.IsEdns0(); opt != nil {
			return opt.UDPSize()
		}
		return 0
	}
	return r.udpSize
}

// DO reports the client's DNSSEC-OK bit.
func (r *Request) DO() bool {
	if r.msg != nil {
		if opt := r.msg.IsEdns0(); opt != nil {
			return opt.Do()
		}
		return false
	}
	return r.do
}

// EDNSVersion returns the OPT version field (meaningful only with HasOPT).
func (r *Request) EDNSVersion() uint8 {
	if r.msg != nil {
		if opt := r.msg.IsEdns0(); opt != nil {
			return opt.Version()
		}
		return 0
	}
	return r.version
}

// HasECS reports whether the request carried an EDNS client-subnet option.
func (r *Request) HasECS() bool {
	if r.msg != nil {
		if opt := r.msg.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if o.Option() == dns.EDNS0SUBNET {
					return true
				}
			}
		}
		return false
	}
	return r.hasECS
}

// HasNSID reports whether the request asked for NSID.
func (r *Request) HasNSID() bool {
	if r.msg != nil {
		if opt := r.msg.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if o.Option() == dns.EDNS0NSID {
					return true
				}
			}
		}
		return false
	}
	return r.hasNSID
}

// WireName returns the question name's wire bytes (borrowed from Raw).
// Valid only for wire-born requests.
func (r *Request) WireName() []byte { return r.raw[r.nameOff : r.nameOff+r.nameLen] }

// WireQuestionEnd returns the offset just past the question section within
// Raw. Valid only for wire-born requests.
func (r *Request) WireQuestionEnd() int { return r.questionEnd }

// ClientCookie returns the raw client cookie half, or nil. Valid only for
// wire-born requests; the message path reads the cookie from the message.
func (r *Request) ClientCookie() []byte {
	if r.cookieLen == 0 {
		return nil
	}
	return r.raw[r.cookieOff : r.cookieOff+r.cookieLen]
}

// RecordEDNSNormalization is called by the edns handler's wire branch: it
// commits the facts materialization needs to normalize the request exactly
// as SetEdns0 would.
func (r *Request) RecordEDNSNormalization(policy *ecs.Policy, client netip.Addr) {
	r.ednsRan = true
	r.ecsPolicy = policy
	r.clientAddr = client
}

// materialize decodes the wire-born request and applies the pending edns
// normalization. Idempotent; the chain drives it through Materialize.
func (r *Request) materialize() *dns.Msg {
	if r.msg != nil {
		return r.msg
	}
	m := new(dns.Msg)
	if err := m.Unpack(r.raw); err != nil {
		// Eligibility should have refused this shape; refuse late rather
		// than serve from unvalidated bytes.
		return nil
	}
	if r.ednsRan {
		// One-way wire → normalized → Msg: the decoded request gets the
		// exact upstream shape SetEdns0 produces (options stripped, clamped
		// ECS re-attached, DO forced, size normalized). The edns writer
		// wrapper already holds the client's original facts.
		_, _, _, _, _ = dnsutil.SetEdns0(m, r.ecsPolicy, r.clientAddr)
	}
	r.msg = m
	return m
}

// ParseWire parses and validates raw into the request. It allocates
// nothing: every fact is a scalar or an offset into raw. Eligibility is
// conservative — exactly one question over an uncompressed name, empty
// answer/authority, at most one well-formed root OPT, plain query opcode —
// and false means the packet must take the decoded entry instead.
func (r *Request) ParseWire(raw []byte, readTime time.Time, ednsSlot any) bool {
	*r = Request{}
	header, ok := wire.ParseHeader(raw)
	if !ok {
		return false
	}
	if header.Opcode() != dns.OpcodeQuery || header.QR() {
		return false
	}
	if header.QDCount != 1 || header.ANCount != 0 || header.NSCount != 0 || header.ARCount > 1 {
		return false
	}

	// Question: uncompressed name, then type and class.
	off := wire.HeaderLen
	nameOff := off
	for {
		if off >= len(raw) {
			return false
		}
		c := int(raw[off])
		if c == 0 {
			off++
			break
		}
		if c&0xC0 != 0 {
			return false
		}
		off += 1 + c
		if off > len(raw) {
			return false
		}
	}
	nameLen := off - nameOff
	if nameLen > 255 || off+4 > len(raw) {
		return false
	}
	qtype := binary.BigEndian.Uint16(raw[off : off+2])
	qclass := binary.BigEndian.Uint16(raw[off+2 : off+4])
	off += 4
	questionEnd := off

	r.raw = raw
	r.id = header.ID
	r.flags = header.Flags
	r.qtype = qtype
	r.qclass = qclass
	r.nameOff = nameOff
	r.nameLen = nameLen
	r.questionEnd = questionEnd
	r.readTime = readTime
	r.ednsWriterSlot = ednsSlot

	if header.ARCount == 1 {
		if !r.parseWireOPT(off) {
			*r = Request{}
			return false
		}
	} else if off != len(raw) {
		// Trailing bytes after the question with no additional record: not
		// a shape the strict path serves from.
		*r = Request{}
		return false
	}
	return true
}

// parseWireOPT validates the single additional record as a root OPT and
// extracts the strict path's EDNS facts. Any other shape refuses.
func (r *Request) parseWireOPT(off int) bool {
	raw := r.raw
	// Root name, OPT type.
	if off+11 > len(raw) || raw[off] != 0 {
		return false
	}
	if binary.BigEndian.Uint16(raw[off+1:off+3]) != dns.TypeOPT {
		return false
	}
	udpSize := binary.BigEndian.Uint16(raw[off+3 : off+5])
	extRcode := raw[off+5]
	version := raw[off+6]
	flags := binary.BigEndian.Uint16(raw[off+7 : off+9])
	rdlen := int(binary.BigEndian.Uint16(raw[off+9 : off+11]))
	off += 11
	if off+rdlen != len(raw) {
		// The OPT must consume the rest of the packet exactly.
		return false
	}
	if extRcode != 0 {
		// An extended-rcode query is not a shape the strict path knows.
		return false
	}

	r.hasOPT = true
	r.udpSize = udpSize
	r.version = version
	r.do = flags&0x8000 != 0

	end := off + rdlen
	for off < end {
		if off+4 > end {
			return false
		}
		code := binary.BigEndian.Uint16(raw[off : off+2])
		optLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		off += 4
		if off+optLen > end {
			return false
		}
		switch code {
		case dns.EDNS0COOKIE:
			// RFC 7873: client half is 8 bytes, full cookie 8..40.
			if optLen < 8 || optLen > 40 {
				return false
			}
			r.cookieOff = off
			r.cookieLen = 8
		case dns.EDNS0NSID:
			r.hasNSID = true
		case dns.EDNS0SUBNET:
			r.hasECS = true
		}
		off += optLen
	}
	return off == end
}

// WireTransportLeaser is implemented by transport writers whose reply
// buffer lives in job-owned storage: the base response writer's BeginWire
// leases from it instead of allocating. nil means the transport cannot
// lease this size and the caller falls back.
type WireTransportLeaser interface {
	LeaseWire(capacity int) []byte
}
