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
// so any additional records in an eligible body are real RRs the TTL walk
// covers. The DNSSEC flag is taken from the answer and authority sections
// only — ClearDNSSEC never filters the additional section, and mirroring
// that keeps the DO=0 wire body identical to the Msg path's. An explicit
// RRSIG question is eligible too: its signatures are the payload, which
// ClearDNSSEC leaves untouched for any DO.
func prepareWireServe(body []byte) wireServeFlags {
	var flags wireServeFlags
	header, ok := wire.ParseHeader(body)
	if !ok || header.QDCount != 1 {
		return 0
	}
	question, ok := wire.ParseQuestion(body, wire.HeaderLen)
	if !ok {
		return 0
	}

	off := question.End
	answered := int(header.ANCount) + int(header.NSCount)
	hasQtypeAnswer, hasCNAMEAnswer := false, false
	for i := range answered + int(header.ARCount) {
		rr, ok := wire.ParseRR(body, off)
		if !ok {
			return 0
		}
		if i < answered {
			switch rr.Type {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				flags |= wireHasDNSSEC
			}
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
	body, _ := e.wireBodyFor(capability.DO)
	if body == nil {
		return wireSkipDNSSEC
	}
	if capability.MaxSize > 0 &&
		len(body)+capability.Reserve+e.wireEDEReserve() > capability.MaxSize {
		return wireSkipSize
	}
	return nil
}

// wireEDEReserve is the encoded length of the entry's Extended DNS Error
// option, zero without one. It rides the lease reserve so the edns layer
// appends the option into existing capacity.
func (e *CacheEntry) wireEDEReserve() int {
	if e.ede == nil {
		return 0
	}
	return wire.OPTOptionHdrLen + 2 + len(e.ede.ExtraText)
}

// wireBodyFor returns the stored body this client may be served, and the
// verdict that goes with it. A client that asked for DNSSEC gets the stored
// message; one that did not gets the stripped form, which is nil when the
// entry has none — that client keeps the Msg path, which strips as it goes.
// An explicit RRSIG question serves the stored message for any DO, exactly
// as ClearDNSSEC leaves such a response untouched.
func (e *CacheEntry) wireBodyFor(do bool) ([]byte, wireServeFlags) {
	if do || e.wireServe&wireHasDNSSEC == 0 || e.question.Qtype == dns.TypeRRSIG {
		return e.wire, e.wireServe
	}
	if e.stripped == nil {
		return nil, 0
	}
	return e.stripped, e.strippedServe
}

// serveWire produces a transport-ready body (sans OPT) for req: the stored
// bytes with this reply's header, the client's question spelling, and the
// remaining TTL written at every record. The TTL walk reuses the packed
// message's own structure rather than a stored offset table.
//
// Exactly the capacity the chain reported it needs is allocated: no slack
// to carry per hit, and no second buffer for the OPT append. Callers that
// hold a writer lease build into it with serveWireInto instead.
func (e *CacheEntry) serveWire(
	req *dns.Msg,
	reserve int,
	do bool,
) ([]byte, middleware.WireInfo, bool) {
	stored, _ := e.wireBodyFor(do)
	if stored == nil {
		return nil, middleware.WireInfo{}, false
	}
	return e.serveWireInto(
		make([]byte, 0, len(stored)+reserve+e.wireEDEReserve()), req, do)
}

// serveWireInto is serveWire building into caller-owned storage: dst must
// have capacity for the stored body (the caller sized it from the entry via
// wireChainMismatch/wireBodyFor, plus the chain's reserve). The returned
// slice aliases dst. Insufficient capacity refuses rather than allocates.
func (e *CacheEntry) serveWireInto(
	dst []byte,
	req *dns.Msg,
	do bool,
) ([]byte, middleware.WireInfo, bool) {
	remaining := e.remaining(time.Now())
	if remaining <= 0 {
		return nil, middleware.WireInfo{}, false
	}

	stored, flags := e.wireBodyFor(do)
	if stored == nil || cap(dst) < len(stored) {
		return nil, middleware.WireInfo{}, false
	}

	header, ok := wire.ParseHeader(stored)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}
	question, ok := wire.ParseQuestion(stored, wire.HeaderLen)
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

	body := dst[:len(stored)]
	copy(body, stored)

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

	ttl := servedSeconds(remaining)
	off := question.End
	for range int(header.ANCount) + int(header.NSCount) + int(header.ARCount) {
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

	return body, e.wireInfoFor(header, flags, authData), true
}

// wireInfoFor assembles the reply facts the writer chain acts on. The
// DNSSEC bit is suppressed for an explicit RRSIG question — its
// signatures are the payload, and the edns layer must not divert such a
// DO=0 reply back to the Msg path. The entry's Extended DNS Error rides
// along for the OPT append.
func (e *CacheEntry) wireInfoFor(
	header wire.Header,
	flags wireServeFlags,
	authData bool,
) middleware.WireInfo {
	info := middleware.WireInfo{
		Rcode:             header.Rcode(),
		AuthenticatedData: authData,
		HasDNSSEC:         flags&wireHasDNSSEC != 0 && e.question.Qtype != dns.TypeRRSIG,
	}
	if e.ede != nil {
		info.HasEDE = true
		info.EDECode = e.ede.InfoCode
		info.EDEText = e.ede.ExtraText
	}
	return info
}

// serveWireIntoRequest is serveWireInto for a wire-born request: every
// reply fact comes from the parsed request, and the 0x20 spelling echo
// copies the client's wire-form name straight over the stored question —
// the lookup key already proved the names fold equal, so the lengths match
// by construction (checked anyway; a mismatch drops the body).
func (e *CacheEntry) serveWireIntoRequest(
	dst []byte,
	req *middleware.Request,
	do bool,
) ([]byte, middleware.WireInfo, bool) {
	remaining := e.remaining(time.Now())
	if remaining <= 0 {
		return nil, middleware.WireInfo{}, false
	}

	stored, flags := e.wireBodyFor(do)
	if stored == nil || cap(dst) < len(stored) {
		return nil, middleware.WireInfo{}, false
	}

	header, ok := wire.ParseHeader(stored)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}
	question, ok := wire.ParseQuestion(stored, wire.HeaderLen)
	if !ok {
		return nil, middleware.WireInfo{}, false
	}

	body := dst[:len(stored)]
	copy(body, stored)

	clientName := req.WireName()
	if len(clientName) != question.NameLen {
		return nil, middleware.WireInfo{}, false
	}
	// Echo the client's exact spelling. When it matches the stored bytes
	// the copy is a no-op-shaped overwrite; when only the case differs it
	// is the whole rewrite — no re-encoding, the client's wire name IS
	// the encoding.
	copy(body[wire.HeaderLen:wire.HeaderLen+question.NameLen], clientName)

	wire.ApplyReply(body, req.ID(), req.Opcode(), req.RD(), req.CD())

	ttl := servedSeconds(remaining)
	off := question.End
	for range int(header.ANCount) + int(header.NSCount) + int(header.ARCount) {
		rr, ok := wire.ParseRR(body, off)
		if !ok {
			return nil, middleware.WireInfo{}, false
		}
		wire.SetTTL(body, rr.TTLOff, ttl)
		off = rr.End
	}

	authData := header.AD()
	if req.CD() && authData {
		wire.ClearAD(body)
		authData = false
	}

	return body, e.wireInfoFor(header, flags, authData), true
}
