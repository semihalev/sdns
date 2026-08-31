package cache

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/miekg/dns"
	internalcache "github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/time/rate"
)

// The cache-contained CNAME chase on the wire: an alias entry whose answer
// carries no terminal record is completed by walking the target entries
// directly in the cache and composing one reply into the writer's lease —
// no decoded messages, no sub-pipeline, no allocation. The walk is
// deliberately narrower than the Msg path's chase: every hop must already
// be cached, byte-eligible, NOERROR, free of authority/additional
// baggage, and made of records this composer can re-encode. Anything else
// declines, and the Msg path — which owns loop SERVFAILs, NXDOMAIN
// provenance, validated-proof propagation and upstream-requiring chases —
// answers exactly as before.
//
// One knowing divergence: hop entries served through the composer do not
// tick their own hit/prefetch machinery (the Msg path's chase reaches them
// through the internal sub-pipeline, which does). A hop that expires ages
// out of the walk, the next hit declines to the Msg path, and the ordinary
// chase re-resolves and re-admits it — self-healing at the cost of one
// decoded serve.

const (
	// maxWireChaseHops mirrors the Msg-path chase depth.
	maxWireChaseHops = 10
	// wireChaseHeadroom pads the lease for decompressed owner names and
	// re-encoded CNAME targets: a pointer inflates to at most a full name.
	wireChaseHeadroom = 288
)

// wireChaseSegment is one collected hop: the body chosen for the client's
// DO bit and the facts composition needs from it.
type wireChaseSegment struct {
	entry   *CacheEntry
	body    []byte
	flags   wireServeFlags
	ttl     uint32
	anCount int
	ansOff  int
	ad      bool
}

// serveChaseHit answers a chase-unsafe exact hit from cache-contained
// state. A false return took nothing and wrote nothing — including the
// per-entry rate-limit token: a chase declines routinely (an uncached or
// expired hop, a non-recomposable rrtype, an oversized composition), and
// every decline before the commit must leave the limiter untouched, or
// the Msg path — or the replay after an inline handoff — would charge
// the same question a second time.
func (c *Cache) serveChaseHit(
	ctx context.Context,
	ch *middleware.Chain,
	alias *CacheEntry,
	capability middleware.WireCapability,
	leaser middleware.WireBodyLeaser,
	spent **rate.Limiter,
) bool {
	var segs [maxWireChaseHops]wireChaseSegment
	n, ok := c.collectWireChase(ch.Request, alias, capability.DO, segs[:])
	if !ok {
		wireSkipChase.Inc()
		return false
	}

	// The reply would compose every segment's records, so the gate sees
	// every segment's sidecar, in chain order — the per-segment principle:
	// a whole-chain verdict on the alias would go stale the moment a
	// target entry refreshed under it.
	if g := c.wireHitGate; g != nil {
		var scs [maxWireChaseHops]*middleware.Sidecar
		for i := range n {
			scs[i] = segs[i].entry.sidecar.Load()
		}
		if !g.AllowWireChase(scs[:n]) {
			wireSkipPolicy.Inc()
			return false
		}
	}

	size := wire.HeaderLen + (ch.Request.WireQuestionEnd() - wire.HeaderLen)
	for i := range n {
		size += len(segs[i].body) + segs[i].anCount*wireChaseHeadroom
	}
	dst := leaser.BeginWire(size, capability.Reserve+alias.wireEDEReserve())
	if dst == nil {
		wireSkipWriter.Inc()
		return false
	}

	body, info, built := composeWireChase(dst, ch.Request, alias, segs[:n])
	if !built {
		leaser.AbortWire()
		wireSkipBuild.Inc()
		return false
	}
	if capability.MaxSize > 0 &&
		len(body)+capability.Reserve+alias.wireEDEReserve() > capability.MaxSize {
		leaser.AbortWire()
		wireSkipSize.Inc()
		return false
	}

	// The last gate before the commit: a refusal here drops the query
	// with Msg-path parity (counted as a hit, cancelled), and a granted
	// token is spent on a serve that no longer declines.
	if !c.chargeEntryLimiter(ch, alias, spent) {
		leaser.AbortWire()
		return true
	}

	switch err := leaser.CommitWire(body, info); {
	case err == nil:
		// The reply contains every segment's records, so the request
		// inherits every segment's cache-lifetime bound — the wire twin of
		// the Msg chase's lineage inheritance.
		for i := range n {
			boundRequestToEntryLifetime(ctx, segs[i].entry)
		}
		c.metrics.Hit()
		wireChaseServed.Inc()
		ch.Cancel()
		return true
	case errors.Is(err, middleware.ErrWireFallback):
		wireFastFallback.Inc()
		return false
	default:
		for i := range n {
			boundRequestToEntryLifetime(ctx, segs[i].entry)
		}
		c.metrics.Hit()
		ch.Cancel()
		return true
	}
}

// collectWireChase walks the alias chain through the cache. It fills segs
// in chain order and reports how many it used; false means some hop was
// not cache-contained in composable form.
func (c *Cache) collectWireChase(
	req *middleware.Request,
	alias *CacheEntry,
	do bool,
	segs []wireChaseSegment,
) (int, bool) {
	qtype, qclass, cd := req.Qtype(), req.Qclass(), req.CD()
	now := time.Now()

	var visited [maxWireChaseHops]uint64
	var targetBuf [256]byte

	entry := alias
	n := 0
	for {
		if n >= len(segs) {
			return 0, false
		}
		body, flags := entry.wireBodyFor(do)
		if body == nil {
			return 0, false
		}
		remaining := entry.remaining(now)
		if remaining <= 0 {
			return 0, false
		}
		header, ok := wire.ParseHeader(body)
		if !ok || header.Rcode() != dns.RcodeSuccess ||
			header.QDCount != 1 || header.NSCount != 0 || header.ARCount != 0 {
			return 0, false
		}
		question, ok := wire.ParseQuestion(body, wire.HeaderLen)
		if !ok {
			return 0, false
		}

		// Walk the answers: every record must be one the composer can
		// re-encode, and the chain continues at the last alias.
		off := question.End
		hasQtype, lastCNAMERData := false, -1
		for range int(header.ANCount) {
			rr, ok := wire.ParseRR(body, off)
			if !ok || !wireRecomposable(rr.Type) {
				return 0, false
			}
			if rr.Type == qtype {
				hasQtype = true
			}
			if rr.Type == dns.TypeCNAME {
				lastCNAMERData = rr.End - rr.RDLen
			}
			off = rr.End
		}

		segs[n] = wireChaseSegment{
			entry:   entry,
			body:    body,
			flags:   flags,
			ttl:     uint32(remaining.Seconds()),
			anCount: int(header.ANCount),
			ansOff:  question.End,
			ad:      header.AD(),
		}
		n++

		if hasQtype {
			return n, true
		}
		if lastCNAMERData < 0 {
			// No terminal and no continuation: a shape for the Msg path.
			return 0, false
		}

		target, ok := wire.AppendName(targetBuf[:0], body, lastCNAMERData)
		if !ok {
			return 0, false
		}
		if foldWireNamesEqual(target, req.WireName()) {
			// Msg-path parity: an alias pointing back at the question is a
			// SERVFAIL the ordinary chase produces.
			return 0, false
		}
		key, ok := internalcache.KeyWire(target, qtype, qclass, cd)
		if !ok {
			return 0, false
		}
		for i := range n - 1 {
			if visited[i] == key {
				return 0, false
			}
		}
		visited[n-1] = key

		next := c.checkCache(key)
		if next == nil || next.wireServe&wireEligible == 0 ||
			!entryMatchesWireQuestion(next, target, qtype, qclass, cd) {
			return 0, false
		}
		entry = next
	}
}

// composeWireChase writes the composed reply into dst. Every append is
// capacity-guarded; false means the lease was too small or a segment was
// malformed, and nothing was sent.
func composeWireChase(
	dst []byte,
	req *middleware.Request,
	alias *CacheEntry,
	segs []wireChaseSegment,
) ([]byte, middleware.WireInfo, bool) {
	if cap(dst) < wire.HeaderLen {
		return nil, middleware.WireInfo{}, false
	}
	// Header: the alias entry's stored header supplies the response
	// flags (RA among them), then the reply identity, counts, and the
	// merged AD verdict overwrite their fields.
	body := dst[:wire.HeaderLen]
	copy(body, segs[0].body[:wire.HeaderLen])

	anTotal := 0
	ad := true
	hasDNSSEC := false
	for i := range segs {
		anTotal += segs[i].anCount
		ad = ad && segs[i].ad
		hasDNSSEC = hasDNSSEC || segs[i].flags&wireHasDNSSEC != 0
	}
	binary.BigEndian.PutUint16(body[4:6], 1)
	binary.BigEndian.PutUint16(body[6:8], uint16(anTotal)) //nolint:gosec // bounded by maxWireChaseHops bodies
	binary.BigEndian.PutUint16(body[8:10], 0)
	binary.BigEndian.PutUint16(body[10:12], 0)

	// The client's own question section, spelling included.
	var ok bool
	body, ok = appendCapped(body, req.Raw()[wire.HeaderLen:req.WireQuestionEnd()])
	if !ok {
		return nil, middleware.WireInfo{}, false
	}

	clientName := req.WireName()
	for i := range segs {
		seg := &segs[i]
		off := seg.ansOff
		for range seg.anCount {
			rr, parsed := wire.ParseRR(seg.body, off)
			if !parsed {
				return nil, middleware.WireInfo{}, false
			}
			body, ok = appendRecomposedRR(body, seg.body, rr, seg.ttl, clientName)
			if !ok {
				return nil, middleware.WireInfo{}, false
			}
			off = rr.End
		}
	}

	wire.ApplyReply(body, req.ID(), req.Opcode(), req.RD(), req.CD())
	if !ad {
		wire.ClearAD(body)
	}
	authData := ad
	if req.CD() && authData {
		wire.ClearAD(body)
		authData = false
	}

	info := middleware.WireInfo{
		Rcode:             dns.RcodeSuccess,
		AuthenticatedData: authData,
		HasDNSSEC:         hasDNSSEC && req.Qtype() != dns.TypeRRSIG,
	}
	if alias.ede != nil {
		info.HasEDE = true
		info.EDECode = alias.ede.InfoCode
		info.EDEText = alias.ede.ExtraText
	}
	return body, info, true
}

// appendCapped appends b without ever growing dst's backing array.
func appendCapped(dst, b []byte) ([]byte, bool) {
	if len(dst)+len(b) > cap(dst) {
		return dst, false
	}
	return append(dst, b...), true
}

// foldWireNamesEqual compares two uncompressed wire names under ASCII
// case folding. Length octets are below 'A', so a plain per-byte fold is
// exact.
func foldWireNamesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range b {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
