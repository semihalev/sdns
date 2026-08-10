package cache

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// wireServeState is derived once at admission by a single skeleton walk over
// the packed body (internal/wire cursors — no record is materialized). A
// body the walk cannot fully account for simply never takes the byte path:
// eligibility is a performance property, not a correctness gate, and any
// surprise degrades to the Msg path.
type wireServeState struct {
	eligible   bool
	hasDNSSEC  bool
	authData   bool
	chaseSafe  bool
	rcode      int
	qnameLen   int
	ttlOffsets []uint16
}

const wireServeSpareCapacity = 96 // room for the edns layer's appended OPT

// prepareWireServe records the byte-serving plan. Admission strips OPT, so
// an eligible body has ARCOUNT==0; RRSIG-question entries are excluded
// because the DO=0 Msg path treats them specially, and EDE-bearing entries
// stay on the Msg path that knows how to re-attach the option.
func prepareWireServe(body []byte, ede *dns.EDNS0_EDE) wireServeState {
	state := wireServeState{}
	if ede != nil {
		return state
	}
	header, ok := wire.ParseHeader(body)
	if !ok || header.QDCount != 1 || header.ARCount != 0 {
		return state
	}
	question, ok := wire.ParseQuestion(body, wire.HeaderLen)
	if !ok || question.Qtype == dns.TypeRRSIG {
		return state
	}
	state.qnameLen = question.NameLen

	off := question.End
	total := int(header.ANCount) + int(header.NSCount)
	state.ttlOffsets = make([]uint16, 0, total)
	hasQtypeAnswer, hasCNAMEAnswer := false, false
	for i := range total {
		rr, ok := wire.ParseRR(body, off)
		if !ok || rr.TTLOff > 0xFFFF {
			return wireServeState{}
		}
		switch rr.Type {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			state.hasDNSSEC = true
		}
		if i < int(header.ANCount) {
			if rr.Type == question.Qtype {
				hasQtypeAnswer = true
			}
			if rr.Type == dns.TypeCNAME {
				hasCNAMEAnswer = true
			}
		}
		state.ttlOffsets = append(state.ttlOffsets, uint16(rr.TTLOff)) //nolint:gosec // bounded by the 0xFFFF guard above
		off = rr.End
	}
	if off != len(body) {
		return wireServeState{}
	}

	state.rcode = header.Rcode()
	state.authData = header.AD()
	// The hit path's CNAME chase rewrites the response only when the answer
	// carries an alias without the terminal qtype record. Anything else is
	// chase-invariant and safe to serve as bytes.
	state.chaseSafe = state.rcode == dns.RcodeNameError ||
		question.Qtype == dns.TypeCNAME || question.Qtype == dns.TypeDS ||
		hasQtypeAnswer || !hasCNAMEAnswer
	state.eligible = true
	return state
}

// wireServable runs every predicate that needs no allocation and no body
// copy. The expensive work in serveWire happens only after this gate, so a
// request that will end on the Msg path costs a few field reads — never
// both paths.
func (e *CacheEntry) wireServable(req *dns.Msg, do bool) bool {
	return e != nil && e.wireServe.eligible && e.wireServe.chaseSafe &&
		req != nil && len(req.Question) == 1 &&
		(do || !e.wireServe.hasDNSSEC)
}

// serveWire produces a transport-ready body (sans OPT) for req. The
// returned body is a private copy with spare capacity for the edns layer's
// OPT append.
func (e *CacheEntry) serveWire(req *dns.Msg) ([]byte, middleware.WireInfo, bool) {
	remaining := e.remaining(time.Now())
	if remaining <= 0 {
		return nil, middleware.WireInfo{}, false
	}

	// The client's question-name spelling is echoed byte-for-byte (0x20
	// compatibility). Names compare case-insensitively, so a wire-length
	// mismatch means this is not actually the stored question.
	var qname [255]byte
	n, err := dns.PackDomainName(req.Question[0].Name, qname[:], 0, nil, false)
	if err != nil || n != e.wireServe.qnameLen {
		return nil, middleware.WireInfo{}, false
	}

	body := make([]byte, len(e.wire), len(e.wire)+wireServeSpareCapacity)
	copy(body, e.wire)

	wire.SetID(body, req.Id)
	copy(body[wire.HeaderLen:], qname[:n])

	ttl := uint32(remaining.Seconds())
	for _, off := range e.wireServe.ttlOffsets {
		wire.SetTTL(body, int(off), ttl)
	}

	authData := e.wireServe.authData
	if req.CheckingDisabled && authData {
		wire.ClearAD(body)
		authData = false
	}

	return body, middleware.WireInfo{
		Rcode:             e.wireServe.rcode,
		AuthenticatedData: authData,
		HasDNSSEC:         e.wireServe.hasDNSSEC,
	}, true
}
