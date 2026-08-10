package cache

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// wireServeState is the admission-time verdict on byte serving. It holds no
// pointers: an entry outlives millions of hits, so anything stored per entry
// is paid for in the collector's mark set forever. The TTL offsets are
// deliberately *not* kept — re-deriving them costs one allocation-free walk
// per hit, while retaining them would add a live object to every entry.
type wireServeState struct {
	rcode     int
	qnameLen  int
	eligible  bool
	hasDNSSEC bool
	authData  bool
	chaseSafe bool
}

const wireServeSpareCapacity = 96 // room for the edns layer's appended OPT

// prepareWireServe records the byte-serving verdict. Admission strips OPT,
// so an eligible body has ARCOUNT==0; RRSIG questions are excluded because
// the DO=0 Msg path treats them specially, and EDE-bearing entries stay on
// the path that knows how to re-attach the option.
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
	hasQtypeAnswer, hasCNAMEAnswer := false, false
	for i := range int(header.ANCount) + int(header.NSCount) {
		rr, ok := wire.ParseRR(body, off)
		if !ok {
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

// wireServable is the complete allocation-free gate. Every condition that
// can refuse the byte path — including the client's real DO bit and the
// transport's size ceiling, both supplied by the writer chain's preflight —
// is decided here, before any body exists.
func (e *CacheEntry) wireServable(req *dns.Msg, capability middleware.WireCapability) bool {
	if e == nil || !e.wireServe.eligible || !e.wireServe.chaseSafe ||
		req == nil || len(req.Question) != 1 {
		return false
	}
	if !capability.DO && e.wireServe.hasDNSSEC {
		return false
	}
	if capability.MaxSize > 0 && len(e.wire)+capability.Reserve > capability.MaxSize {
		return false
	}
	return true
}

// serveWire produces a transport-ready body (sans OPT) for req: the stored
// bytes with this reply's header, the client's question spelling, and the
// remaining TTL written at every record. The TTL walk reuses the packed
// message's own structure rather than a stored offset table.
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
	copy(body[wire.HeaderLen:], qname[:n])

	// Apply the same header the Msg path derives from the request: ID, QR,
	// opcode, the copied RD/CD bits, and AA cleared — a cached answer is
	// never authoritative, however the upstream marked it.
	wire.ApplyReply(body, req.Id, req.Opcode, req.RecursionDesired, req.CheckingDisabled)

	header, ok := wire.ParseHeader(body)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}
	question, ok := wire.ParseQuestion(body, wire.HeaderLen)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}
	ttl := uint32(remaining.Seconds())
	off := question.End
	for range int(header.ANCount) + int(header.NSCount) {
		rr, ok := wire.ParseRR(body, off)
		if !ok {
			return nil, middleware.WireInfo{}, false
		}
		wire.SetTTL(body, rr.TTLOff, ttl)
		off = rr.End
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
