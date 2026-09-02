package cache

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	internalcache "github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// nxDomainCutHashSalt separates the cut cache's private hash index from
// the canonical key space its inputs come from.
const nxDomainCutHashSalt = 0x8020c07f5a3d91e4

// nxDomainCutHash is the canonical hash of a cut identity: the denied
// name with a zero qtype — bit-identical whether computed from the
// presentation name (record time) or wire bytes (lookup time).
func nxDomainCutHash(deniedName string, qclass uint16) uint64 {
	q := dns.Question{Name: deniedName, Qtype: 0, Qclass: qclass}
	return internalcache.Key(q, false) ^ nxDomainCutHashSalt
}

// prepareWire packs the cut's serve templates: the proof authority section
// behind a template question, full and DNSSEC-stripped, both validated for
// recomposition. A shape the composer cannot re-encode leaves wireFull
// nil, and the cut serves through the Msg path only.
func (e *nxDomainCutEntry) prepareWire() {
	e.hash = nxDomainCutHash(e.deniedName, e.qclass)

	tmpl := new(dns.Msg)
	tmpl.Question = []dns.Question{{Name: e.deniedName, Qtype: dns.TypeSOA, Qclass: e.qclass}}
	tmpl.Ns = e.msg.Ns
	tmpl.Compress = true
	full, err := wire.PackClone(tmpl)
	if err != nil || !nxCutWireServable(full) {
		return
	}
	e.wireFull = full

	// The DO=0 body: ClearDNSSEC replaces the section it filters, so the
	// template's own slice is untouched. When nothing is stripped the full
	// body serves both audiences.
	stripped := *tmpl
	dnsutil.ClearDNSSEC(&stripped)
	if len(stripped.Ns) == len(tmpl.Ns) {
		e.wireStripped = full
		return
	}
	e.wireDNSSEC = true
	strippedBody, err := wire.PackClone(&stripped)
	if err != nil || !nxCutWireServable(strippedBody) {
		return
	}
	e.wireStripped = strippedBody
}

// nxCutWireServable validates a packed template for recomposition:
// exactly the template question, an authority section made of records the
// composer can re-encode, nothing else.
func nxCutWireServable(body []byte) bool {
	header, ok := wire.ParseHeader(body)
	if !ok || header.QDCount != 1 || header.ANCount != 0 || header.ARCount != 0 {
		return false
	}
	question, ok := wire.ParseQuestion(body, wire.HeaderLen)
	if !ok {
		return false
	}
	off := question.End
	for range int(header.NSCount) {
		rr, ok := wire.ParseRR(body, off)
		if !ok || !wireRecomposable(rr.Type) {
			return false
		}
		off = rr.End
	}
	return off == len(body)
}

// lookupWire is lookup for a wire-born question: the same longest-suffix
// walk over the denied names, probing the hash index and verifying by
// fold comparison. Expired entries are skipped, not pruned — the Msg
// path's lookup owns eviction.
func (c *nxDomainCutCache) lookupWire(name []byte, qclass uint16) (*nxDomainCutEntry, bool) {
	if c == nil || qclass == 0 {
		return nil, false
	}
	now := time.Now()
	var found *nxDomainCutEntry
	c.mu.RLock()
	walkWireSuffixes(name, func(candidate []byte) bool {
		hash, ok := internalcache.KeyWire(candidate, 0, qclass, false)
		if !ok {
			return true
		}
		entry := c.byHash[hash^nxDomainCutHashSalt]
		if entry == nil || entry.qclass != qclass || entry.wireFull == nil ||
			!internalcache.WireNameEqualsPresentation(candidate, entry.deniedName) ||
			!now.Before(entry.expires) {
			return true
		}
		found = entry
		return false
	})
	c.mu.RUnlock()
	return found, found != nil
}

// serveWireInto composes the synthesized descendant NXDOMAIN for a
// wire-born request into dst: the client's question, the proof authority
// re-encoded at the remaining TTL, AD asserted exactly as the Msg path's
// synthesis does. false means it did not fit or a template record broke
// the composer's assumptions; nothing was written.
func (e *nxDomainCutEntry) serveWireInto(
	dst []byte,
	req *middleware.Request,
	do bool,
) ([]byte, bool) {
	remaining := time.Until(e.expires)
	if remaining <= 0 {
		return nil, false
	}
	tmpl := e.wireFull
	if !do {
		// The stripped template was cut behind a SOA question, so it holds
		// no authenticating record at all. A DO=0 question for RRSIG, NSEC
		// or NSEC3 keeps the one type it named (RFC 4035 §3.2.1), which
		// neither template is: the Msg path shapes that answer.
		switch req.Qtype() {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			return nil, false
		}
		tmpl = e.wireStripped
	}
	if tmpl == nil || cap(dst) < wire.HeaderLen {
		return nil, false
	}
	header, ok := wire.ParseHeader(tmpl)
	if !ok {
		return nil, false
	}
	question, ok := wire.ParseQuestion(tmpl, wire.HeaderLen)
	if !ok {
		return nil, false
	}

	body := dst[:wire.HeaderLen]
	copy(body, tmpl[:wire.HeaderLen])
	putUint16(body[4:6], 1)
	putUint16(body[6:8], 0)
	putUint16(body[8:10], header.NSCount)
	putUint16(body[10:12], 0)

	body, ok = appendCapped(body, req.Raw()[wire.HeaderLen:req.WireQuestionEnd()])
	if !ok {
		return nil, false
	}

	ttl := servedSeconds(remaining)
	off := question.End
	for range int(header.NSCount) {
		rr, parsed := wire.ParseRR(tmpl, off)
		if !parsed {
			return nil, false
		}
		body, ok = appendRecomposedRR(body, tmpl, rr, ttl, nil)
		if !ok {
			return nil, false
		}
		off = rr.End
	}

	// The Msg path's synthesis shape: NXDOMAIN, recursion available, a
	// locally validated proof (AD set), never authoritative.
	wire.ApplyReply(body, req.ID(), req.Opcode(), req.RD(), req.CD())
	wire.SetRcode(body, dns.RcodeNameError)
	wire.SetRA(body)
	wire.SetAD(body)
	return body, true
}

func putUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v & 0xFF) //nolint:gosec // masked to one octet
}

// serveCutHitFromWire answers a wire-born descendant of a validated
// RFC 8020 cut from the entry's packed proof template. A false return
// wrote nothing; the Msg path re-runs its ladder.
func (c *Cache) serveCutHitFromWire(
	ctx context.Context,
	ch *middleware.Chain,
	cut *nxDomainCutEntry,
) bool {
	w := ch.Writer
	if w.Internal() {
		return false
	}
	ww, ok := w.(middleware.WireWriter)
	if !ok {
		wireSkipWriter.Inc()
		return false
	}
	capability, ready := ww.WireReady()
	if !ready {
		wireSkipWriter.Inc()
		return false
	}
	leaser, ok := ww.(middleware.WireBodyLeaser)
	if !ok {
		wireSkipWriter.Inc()
		return false
	}

	// The DO test mirrors serveWireInto's, RRSIG exception included, so
	// this precheck never rejects a template the composer would pick.
	tmpl := cut.wireFull
	if !capability.DO && ch.Request.Qtype() != dns.TypeRRSIG {
		tmpl = cut.wireStripped
	}
	if tmpl == nil {
		wireSkipDNSSEC.Inc()
		return false
	}
	qlen := ch.Request.WireQuestionEnd() - wire.HeaderLen
	dst := leaser.BeginWire(len(tmpl)+qlen+wireChaseHeadroom, capability.Reserve)
	if dst == nil {
		wireSkipWriter.Inc()
		return false
	}
	body, built := cut.serveWireInto(dst, ch.Request, capability.DO)
	if !built {
		leaser.AbortWire()
		wireSkipBuild.Inc()
		return false
	}
	if capability.MaxSize > 0 && len(body)+capability.Reserve > capability.MaxSize {
		leaser.AbortWire()
		wireSkipSize.Inc()
		return false
	}

	info := middleware.WireInfo{
		Rcode:             dns.RcodeNameError,
		AuthenticatedData: true,
		HasDNSSEC:         capability.DO && cut.wireDNSSEC,
	}
	switch err := leaser.CommitWire(body, info); {
	case err == nil:
		boundRequestTo(ctx, cut.expires)
		c.metrics.Hit()
		nxDomainCutHits.Inc()
		wireCutServed.Inc()
		ch.Cancel()
		return true
	case errors.Is(err, middleware.ErrWireFallback):
		wireFastFallback.Inc()
		return false
	default:
		boundRequestTo(ctx, cut.expires)
		c.metrics.Hit()
		ch.Cancel()
		return true
	}
}

// serveFailureFromWire synthesizes the RFC 9520 cached-failure SERVFAIL
// straight into the writer's lease: a bare header, the client's question,
// and the EDE the edns layer appends for EDNS clients.
func (c *Cache) serveFailureFromWire(ch *middleware.Chain) bool {
	w := ch.Writer
	if w.Internal() {
		return false
	}
	ww, ok := w.(middleware.WireWriter)
	if !ok {
		wireSkipWriter.Inc()
		return false
	}
	capability, ready := ww.WireReady()
	if !ready {
		wireSkipWriter.Inc()
		return false
	}
	leaser, ok := ww.(middleware.WireBodyLeaser)
	if !ok {
		wireSkipWriter.Inc()
		return false
	}

	req := ch.Request
	qlen := req.WireQuestionEnd() - wire.HeaderLen
	size := wire.HeaderLen + qlen
	// The reserve must carry the EDE this reply commits below: the edns
	// layer's share covers its own options, and a caller-supplied EDE is
	// the caller's bytes to reserve. Leasing without it went unnoticed
	// while a lease exposed the whole slab; a capacity-exact lease turns
	// the shortfall into a reallocation on a path that must not have one.
	const failureEDEReserve = wire.OPTOptionHdrLen + 2 + len(failureCacheEDEText)
	dst := leaser.BeginWire(size, capability.Reserve+failureEDEReserve)
	if dst == nil || cap(dst) < size {
		if dst != nil {
			leaser.AbortWire()
		}
		wireSkipWriter.Inc()
		return false
	}
	body := dst[:wire.HeaderLen]
	for i := range body {
		body[i] = 0
	}
	putUint16(body[4:6], 1)
	body, ok = appendCapped(body, req.Raw()[wire.HeaderLen:req.WireQuestionEnd()])
	if !ok {
		leaser.AbortWire()
		wireSkipBuild.Inc()
		return false
	}
	wire.ApplyReply(body, req.ID(), req.Opcode(), req.RD(), req.CD())
	wire.SetRcode(body, dns.RcodeServerFailure)
	wire.SetRA(body)

	info := middleware.WireInfo{
		Rcode:   dns.RcodeServerFailure,
		HasEDE:  true,
		EDECode: dns.ExtendedErrorCodeCachedError,
		EDEText: failureCacheEDEText,
	}
	switch err := leaser.CommitWire(body, info); {
	case err == nil:
		c.metrics.Hit()
		failureCacheHits.Inc()
		wireFailureServed.Inc()
		ch.Cancel()
		return true
	case errors.Is(err, middleware.ErrWireFallback):
		wireFastFallback.Inc()
		return false
	default:
		c.metrics.Hit()
		ch.Cancel()
		return true
	}
}
