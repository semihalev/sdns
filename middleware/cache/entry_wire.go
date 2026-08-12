package cache

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// wireServeFlags is the admission-time verdict on byte serving, kept as a
// single byte. An entry outlives millions of hits, so anything stored per
// entry is paid for in the collector's mark set forever: the rcode, the
// question length and the AD bit are all re-read from the packed header at
// serve time, where they cost nothing, rather than retained here.
type wireServeFlags uint8

const (
	wireEligible wireServeFlags = 1 << iota
	wireHasDNSSEC
	wireChaseSafe
)

// prepareWireServe records the byte-serving verdict. Admission strips OPT,
// so an eligible body has ARCOUNT==0; RRSIG questions are excluded because
// the DO=0 Msg path treats them specially, and EDE-bearing entries stay on
// the path that knows how to re-attach the option.
func prepareWireServe(body []byte, ede *dns.EDNS0_EDE) wireServeFlags {
	var flags wireServeFlags
	if ede != nil {
		return 0
	}
	header, ok := wire.ParseHeader(body)
	if !ok || header.QDCount != 1 || header.ARCount != 0 {
		return 0
	}
	question, ok := wire.ParseQuestion(body, wire.HeaderLen)
	if !ok || question.Qtype == dns.TypeRRSIG {
		return 0
	}

	off := question.End
	hasQtypeAnswer, hasCNAMEAnswer := false, false
	for i := range int(header.ANCount) + int(header.NSCount) {
		rr, ok := wire.ParseRR(body, off)
		if !ok {
			return 0
		}
		switch rr.Type {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			flags |= wireHasDNSSEC
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
		return 0
	}

	// The hit path's CNAME chase rewrites the response only when the answer
	// carries an alias without the terminal qtype record. Anything else is
	// chase-invariant and safe to serve as bytes.
	if header.Rcode() == dns.RcodeNameError ||
		question.Qtype == dns.TypeCNAME || question.Qtype == dns.TypeDS ||
		hasQtypeAnswer || !hasCNAMEAnswer {
		flags |= wireChaseSafe
	}
	return flags | wireEligible
}

// wireEligibleFor is the entry-local half of the gate: everything knowable
// without consulting the writer chain. It runs first so a request this
// entry can never serve as bytes does not even trigger the chain preflight.
func (e *CacheEntry) wireEligibleFor(req *dns.Msg) bool {
	const ready = wireEligible | wireChaseSafe
	return e != nil && e.wireServe&ready == ready &&
		req != nil && len(req.Question) == 1
}

// wireFitsChain is the second half: the facts only the writer chain knows —
// the client's real DO bit and the transport's size ceiling. Both halves
// are allocation-free and complete, so no body is ever built for a request
// that will fall back.
func (e *CacheEntry) wireFitsChain(capability middleware.WireCapability) bool {
	return e.wireChainMismatch(capability) == nil
}

// wireChainMismatch is wireFitsChain naming what turned the request away, for
// the counter that reports which gate a hit failed.
func (e *CacheEntry) wireChainMismatch(
	capability middleware.WireCapability,
) *metric.Counter {
	if !capability.DO && e.wireServe&wireHasDNSSEC != 0 {
		return wireSkipDNSSEC
	}
	if capability.MaxSize > 0 && len(e.wire)+capability.Reserve > capability.MaxSize {
		return wireSkipSize
	}
	return nil
}

// serveWire produces a transport-ready body (sans OPT) for req: the stored
// bytes with this reply's header, the client's question spelling, and the
// remaining TTL written at every record. The TTL walk reuses the packed
// message's own structure rather than a stored offset table.
func (e *CacheEntry) serveWire(req *dns.Msg, reserve int) ([]byte, middleware.WireInfo, bool) {
	remaining := e.remaining(time.Now())
	if remaining <= 0 {
		return nil, middleware.WireInfo{}, false
	}

	header, ok := wire.ParseHeader(e.wire)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}
	question, ok := wire.ParseQuestion(e.wire, wire.HeaderLen)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}

	// The client's question-name spelling is echoed byte-for-byte (0x20
	// compatibility). Almost always the stored bytes already carry that
	// spelling — clients overwhelmingly ask in one consistent case — and
	// then the name needs no re-encoding at all.
	//
	// The stored name and the stored bytes come from one message: the entry
	// keeps msg.Question[0] and packs that same msg, and neither is touched
	// afterwards. So an identical spelling here means the packed question is
	// already identical too, which a string compare settles outright.
	name := req.Question[0].Name
	rewrite := name != e.question.Name

	// Exactly the capacity the chain reported it needs: no slack to carry
	// per hit, and no second buffer for the OPT append.
	body := make([]byte, len(e.wire), len(e.wire)+reserve)
	copy(body, e.wire)

	if rewrite {
		// Encoded straight over the stored name, so the spelling swap needs
		// no scratch buffer of its own. A length change would mean the
		// request's name is not the stored one after all — impossible for an
		// entry the lookup key already matched, since names that fold to the
		// same key encode to the same length. Checked anyway; the body is
		// simply dropped.
		//
		// Records are stored compressed, so an answer whose owner name is
		// the question points back here and now decodes with the client's
		// spelling too, where the message path would return the stored one.
		// Intended: names are case-insensitive, and echoing the client's
		// case throughout is what a 0x20-aware server should do.
		end, err := dns.PackDomainName(name, body, wire.HeaderLen, nil, false)
		if err != nil || end-wire.HeaderLen != question.NameLen {
			return nil, middleware.WireInfo{}, false
		}
	}

	// Apply the same header the Msg path derives from the request: ID, QR,
	// opcode, the copied RD/CD bits, and AA cleared — a cached answer is
	// never authoritative, however the upstream marked it.
	wire.ApplyReply(body, req.Id, req.Opcode, req.RecursionDesired, req.CheckingDisabled)

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

	authData := header.AD()
	if req.CheckingDisabled && authData {
		wire.ClearAD(body)
		authData = false
	}

	return body, middleware.WireInfo{
		Rcode:             header.Rcode(),
		AuthenticatedData: authData,
		HasDNSSEC:         e.wireServe&wireHasDNSSEC != 0,
	}, true
}
