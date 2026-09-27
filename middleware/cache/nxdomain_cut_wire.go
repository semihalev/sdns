package cache

import (
	"context"
	"encoding/binary"
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
// name with a zero qtype, bit-identical whether computed from the
// presentation name (record time) or wire bytes (lookup time).
func nxDomainCutHash(deniedName string, qclass uint16) uint64 {
	q := dns.Question{Name: deniedName, Qtype: 0, Qclass: qclass}
	return internalcache.Key(q, false) ^ nxDomainCutHashSalt
}

// prepareWire packs the cut's serve templates: the proof authority section,
// name-compressed, behind the root as the template question, full and
// DNSSEC-stripped, each with its relocation table. The root keeps every
// pointer inside the authority section, so a hit copies the section as it
// stands and moves its pointers by the length of the client's question. A
// shape that cannot be served that way leaves wireFull nil, and the cut
// serves through the Msg path only.
func (e *nxDomainCutEntry) prepareWire() {
	e.hash = nxDomainCutHash(e.deniedName, e.qclass)

	tmpl := new(dns.Msg)
	tmpl.Question = []dns.Question{{Name: ".", Qtype: dns.TypeSOA, Qclass: e.qclass}}
	tmpl.Ns = e.msg.Ns
	tmpl.Compress = true
	full, err := wire.PackClone(tmpl)
	if err != nil {
		return
	}
	fullReloc, ok := cutRelocationOf(full)
	if !ok {
		return
	}
	e.wireFull, e.wireFullReloc = full, fullReloc

	// The DO=0 body: ClearDNSSEC replaces the section it filters, so the
	// template's own slice is untouched. When nothing is stripped the full
	// body serves both audiences.
	stripped := *tmpl
	dnsutil.ClearDNSSEC(&stripped)
	if len(stripped.Ns) == len(tmpl.Ns) {
		e.wireStripped, e.wireStrippedReloc = full, fullReloc
		return
	}
	e.wireDNSSEC = true
	strippedBody, err := wire.PackClone(&stripped)
	if err != nil {
		return
	}
	strippedReloc, ok := cutRelocationOf(strippedBody)
	if !ok {
		return
	}
	e.wireStripped, e.wireStrippedReloc = strippedBody, strippedReloc
}

// cutRelocation is where a packed cut template holds what a hit rewrites:
// the offsets of its compression pointers, whose targets move with the
// authority section, and of each record's TTL.
type cutRelocation struct {
	ptrs []uint16
	ttls []uint16
}

// bytes is what the table costs the entry.
func (r cutRelocation) bytes() int64 {
	return int64(2 * (len(r.ptrs) + len(r.ttls)))
}

// cutRelocationOf validates a packed template and builds its relocation
// table: exactly one question, an authority section of records whose names
// sit only in owners and SOA and CNAME rdata, every pointer into the
// authority section itself, nothing after it.
func cutRelocationOf(body []byte) (cutRelocation, bool) {
	var r cutRelocation
	header, ok := wire.ParseHeader(body)
	if !ok || header.QDCount != 1 || header.ANCount != 0 || header.ARCount != 0 {
		return r, false
	}
	question, ok := wire.ParseQuestion(body, wire.HeaderLen)
	if !ok {
		return r, false
	}
	authStart := question.End
	off := authStart
	for range int(header.NSCount) {
		rr, parsed := wire.ParseRR(body, off)
		if !parsed || !wireRecomposable(rr.Type) || rr.End > 0xFFFF ||
			!r.notePointer(body, rr.NameOff, authStart) {
			return r, false
		}
		r.ttls = append(r.ttls, uint16(rr.TTLOff)) //nolint:gosec // bounded by the rr.End check
		rdataOff := rr.End - rr.RDLen
		switch rr.Type {
		case dns.TypeCNAME:
			if !r.notePointer(body, rdataOff, authStart) {
				return r, false
			}
		case dns.TypeSOA:
			mnameEnd := wire.SkipName(body, rdataOff)
			if mnameEnd < 0 || !r.notePointer(body, rdataOff, authStart) ||
				!r.notePointer(body, mnameEnd, authStart) {
				return r, false
			}
		}
		off = rr.End
	}
	return r, off == len(body)
}

// notePointer records the pointer the name at off ends in, if it ends in
// one. A pointer out of the authority section refuses the template: the
// question it would point into is the client's at serve time.
func (r *cutRelocation) notePointer(body []byte, off, authStart int) bool {
	for off < len(body) {
		c := int(body[off])
		switch {
		case c == 0:
			return true
		case c&0xC0 == 0xC0:
			if off+1 >= len(body) || int(binary.BigEndian.Uint16(body[off:])&0x3FFF) < authStart {
				return false
			}
			r.ptrs = append(r.ptrs, uint16(off)) //nolint:gosec // within a body under 64 KiB
			return true
		case c&0xC0 != 0:
			return false
		default:
			off += 1 + c
		}
	}
	return false
}

// relocateAuthority appends the template's authority section, from
// authStart, to dst as it stands, moves its pointers with it, and stamps
// every record's TTL. It refuses, writing nothing that counts, when a moved
// pointer would leave what a pointer can reach.
func relocateAuthority(dst, tmpl []byte, authStart int, r cutRelocation, ttl uint32) ([]byte, bool) {
	newStart := len(dst)
	dst, ok := appendCapped(dst, tmpl[authStart:])
	if !ok {
		return nil, false
	}
	shift := newStart - authStart
	for _, p := range r.ptrs {
		at := int(p) + shift
		target := int(binary.BigEndian.Uint16(dst[at:])&0x3FFF) + shift
		if target < newStart || target > 0x3FFF {
			return nil, false
		}
		binary.BigEndian.PutUint16(dst[at:], 0xC000|uint16(target)) //nolint:gosec // bounded by the check above
	}
	for _, p := range r.ttls {
		binary.BigEndian.PutUint32(dst[int(p)+shift:], ttl)
	}
	return dst, true
}

// lookupWire is lookup for a wire-born question: the same longest-suffix
// walk over the denied names, probing the hash index and verifying by
// fold comparison. Expired entries are skipped, not pruned, the Msg
// path's lookup owns eviction.
//
// Only the monotonic deadline is checked here, on the clock read that needs
// no wall time. The wall-clock one is serveWireInto's, which reads both
// clocks once for the TTL it serves: a cut past only that bound declines
// there, and the Msg path's lookup prunes it.
func (c *nxDomainCutCache) lookupWire(name []byte, qclass uint16) (*nxDomainCutEntry, bool) {
	if c == nil || qclass == 0 {
		return nil, false
	}
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
			time.Until(entry.expires.Mono().Until) <= 0 {
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
	remaining, _ := e.expires.Remaining(time.Now())
	if remaining <= 0 {
		return nil, false
	}
	tmpl, reloc := e.wireFull, e.wireFullReloc
	if !do {
		// The stripped template was cut behind a SOA question, so it holds
		// no authenticating record at all. A DO=0 question for RRSIG, NSEC
		// or NSEC3 keeps the one type it named (RFC 4035 §3.2.1), which
		// neither template is: the Msg path shapes that answer.
		switch req.Qtype() {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			return nil, false
		}
		tmpl, reloc = e.wireStripped, e.wireStrippedReloc
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

	// The proof, as packed at record time, moved behind the client's
	// question.
	body, ok = relocateAuthority(body, tmpl, question.End, reloc, servedSeconds(remaining))
	if !ok {
		return nil, false
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

	// The DO test mirrors serveWireInto's, the explicit-question decline
	// included, so this precheck never leases a body the composer would
	// refuse: a DO=0 question for RRSIG, NSEC or NSEC3 is the Msg path's
	// by design, and leasing for it only to abort counted a deliberate
	// fallback as a build failure.
	tmpl := cut.wireFull
	if !capability.DO {
		switch ch.Request.Qtype() {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			wireSkipDNSSEC.Inc()
			return false
		}
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
		boundRequestToLease(ctx, cut.expires)
		c.metrics.Hit()
		nxDomainCutHits.Inc()
		wireCutServed.Inc()
		ch.Cancel()
		return true
	case errors.Is(err, middleware.ErrWireFallback):
		wireFastFallback.Inc()
		return false
	default:
		boundRequestToLease(ctx, cut.expires)
		c.metrics.Hit()
		ch.Cancel()
		return true
	}
}

// serveFailureFromWire synthesizes the RFC 9520 cached-failure SERVFAIL
// straight into the writer's lease: a bare header, the client's question,
// and the hit's EDE the edns layer appends for EDNS clients.
func (c *Cache) serveFailureFromWire(ch *middleware.Chain, hit FailureHit) bool {
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
	edeCode, edeText := hit.cause.ede()
	failureEDEReserve := wire.OPTOptionHdrLen + 2 + len(edeText)
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
		EDECode: edeCode,
		EDEText: edeText,
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
