package cache

import (
	"container/list"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

const (
	maxNXDomainCutProofRRs         = 32
	maxNXDomainCutProofBytes       = 8 << 10
	nxDomainCutBudgetBytesPerEntry = 2 << 10
)

type nxDomainCutID struct {
	deniedName string
	qclass     uint16
}

type nxDomainCutZoneKey struct {
	zone   string
	qclass uint16
}

// nxDomainCutEntry is an immutable, locally validated RFC 8020 cut. It stores
// only the terminal denial proof; CNAME/DNAME records from an outer alias
// response must never leak into a synthesized descendant response. Queue
// pointers are touched only while the cache write lock is held.
type nxDomainCutEntry struct {
	deniedName string
	zone       string
	qclass     uint16
	proofKind  middleware.ValidatedNegativeProofKind
	msg        *dns.Msg
	stored     time.Time
	expires    time.Time
	wireBytes  int64
	id         nxDomainCutID
	zoneKey    nxDomainCutZoneKey
	globalElem *list.Element
	zoneElem   *list.Element

	// Wire-serving state, packed once at record time: the proof authority
	// section behind a template question (the denied name), full and
	// DNSSEC-stripped, plus the canonical hash the wire lookup probes.
	// wireFull == nil means this cut serves through the Msg path only.
	wireFull     []byte
	wireStripped []byte
	wireDNSSEC   bool
	hash         uint64
}

type nxDomainCutZoneState struct {
	fifo      list.List
	wireBytes int64
}

type nxDomainCutCacheConfig struct {
	MaxEntries        int
	MaxEntriesPerZone int
	MaxBytes          int64
	MaxBytesPerZone   int64
	MaxTTL            time.Duration
}

// nxDomainCutCache is deliberately separate from the ordinary answer cache.
// Random names can create many distinct cuts, so the index must have its own
// hard entry and wire-byte bounds and must not evict useful positive answers.
// Each signer zone has independent bounds so one hostile signed zone cannot
// monopolise the complete RFC 8020 index.
type nxDomainCutCache struct {
	mu sync.RWMutex

	entries map[nxDomainCutID]*nxDomainCutEntry
	// byHash is the wire lookup's accelerator: canonical-hash → entry,
	// last write wins. The string map stays the truth, a hash collision
	// fails the fold verification at lookup and simply declines to the
	// Msg path.
	byHash map[uint64]*nxDomainCutEntry
	zones  map[nxDomainCutZoneKey]*nxDomainCutZoneState
	fifo   list.List

	maxEntries        int
	maxEntriesPerZone int
	maxBytes          int64
	maxBytesPerZone   int64
	maxTTL            time.Duration

	totalBytes int64
	stopped    bool
}

func newNXDomainCutCache(size int, maxTTL time.Duration) *nxDomainCutCache {
	if size < 1 {
		size = 1
	}

	perZone := size / 64
	if perZone < 8 {
		perZone = 8
	}
	if perZone > 256 {
		perZone = 256
	}
	if perZone > size {
		perZone = size
	}

	return newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        size,
		MaxEntriesPerZone: perZone,
		MaxBytes:          nxDomainCutDerivedBytes(size),
		MaxBytesPerZone:   nxDomainCutDerivedBytes(perZone),
		MaxTTL:            maxTTL,
	})
}

func newNXDomainCutCacheWithConfig(cfg nxDomainCutCacheConfig) *nxDomainCutCache {
	if cfg.MaxEntries < 1 {
		cfg.MaxEntries = 1
	}
	if cfg.MaxEntriesPerZone < 1 {
		cfg.MaxEntriesPerZone = 1
	}
	if cfg.MaxEntriesPerZone > cfg.MaxEntries {
		cfg.MaxEntriesPerZone = cfg.MaxEntries
	}
	if cfg.MaxBytes < 1 {
		cfg.MaxBytes = nxDomainCutDerivedBytes(cfg.MaxEntries)
	}
	if cfg.MaxBytesPerZone < 1 {
		cfg.MaxBytesPerZone = nxDomainCutDerivedBytes(cfg.MaxEntriesPerZone)
	}
	if cfg.MaxBytesPerZone > cfg.MaxBytes {
		cfg.MaxBytesPerZone = cfg.MaxBytes
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = dnsutil.MaxCacheTTL
	}

	return &nxDomainCutCache{
		entries:           make(map[nxDomainCutID]*nxDomainCutEntry),
		byHash:            make(map[uint64]*nxDomainCutEntry),
		zones:             make(map[nxDomainCutZoneKey]*nxDomainCutZoneState),
		maxEntries:        cfg.MaxEntries,
		maxEntriesPerZone: cfg.MaxEntriesPerZone,
		maxBytes:          cfg.MaxBytes,
		maxBytesPerZone:   cfg.MaxBytesPerZone,
		maxTTL:            cfg.MaxTTL,
	}
}

func nxDomainCutDerivedBytes(entries int) int64 {
	if entries < 1 {
		return maxNXDomainCutProofBytes
	}
	count := int64(entries)
	if count > math.MaxInt64/nxDomainCutBudgetBytesPerEntry {
		return math.MaxInt64
	}
	derived := count * nxDomainCutBudgetBytesPerEntry
	if derived < maxNXDomainCutProofBytes {
		return maxNXDomainCutProofBytes
	}
	return derived
}

// record publishes a cut for the exact locally validated denied name. zone is
// the signer zone selected by the validator; it is used to extract only the
// terminal proof when an outer CNAME/DNAME response contains records from
// multiple zones.
func (c *nxDomainCutCache) record(msg *dns.Msg, deniedName, zone string, cutUntil time.Time) bool {
	if c == nil || msg == nil || msg.Rcode != dns.RcodeNameError ||
		msg.CheckingDisabled {
		return false
	}

	deniedName = dns.CanonicalName(deniedName)
	zone = dns.CanonicalName(zone)
	// The signer-zone apex cannot be absent while its SOA exists. Rejecting
	// this impossible provenance locally prevents it becoming a zone-wide cut.
	if deniedName == "." || deniedName == zone ||
		!dnsname.Sub(zone, deniedName) {
		return false
	}

	proof, soa, ok := nxDomainCutProof(msg, deniedName, zone)
	if !ok {
		return false
	}

	now := time.Now()
	ttl := c.maxTTL
	bound := func(candidate time.Duration) {
		if candidate < ttl {
			ttl = candidate
		}
	}

	// RFC 2308 negative TTL. No configured minimum is applied: a cache floor
	// must never extend an authenticated denial beyond any proof component.
	bound(time.Duration(soa.Hdr.Ttl) * time.Second)
	bound(time.Duration(soa.Minttl) * time.Second)
	for _, rr := range proof.Ns {
		bound(time.Duration(rr.Header().Ttl) * time.Second)
		switch record := rr.(type) {
		case *dns.SOA:
			bound(time.Duration(record.Minttl) * time.Second)
		case *dns.RRSIG:
			bound(time.Duration(record.OrigTtl) * time.Second)
			bound(time.Unix(int64(record.Expiration), 0).Sub(now))
		}
	}
	if !cutUntil.IsZero() {
		bound(cutUntil.Sub(now))
	}
	if ttl <= 0 {
		return false
	}

	entry := &nxDomainCutEntry{
		deniedName: deniedName,
		zone:       zone,
		qclass:     soa.Hdr.Class,
		proofKind:  negativeProofKind(proof.Ns),
		msg:        proof,
		stored:     now,
		expires:    now.Add(ttl),
		wireBytes:  int64(proof.Len()),
	}
	entry.id = nxDomainCutID{deniedName: deniedName, qclass: entry.qclass}
	entry.zoneKey = nxDomainCutZoneKey{zone: zone, qclass: entry.qclass}
	entry.prepareWire()
	// The wire templates are retained alongside the decoded proof, so
	// they are bytes this entry costs. Counting only the proof let a
	// signed zone hold roughly three bodies per entry against a budget
	// that believed it held one, live heap profiles showed the cut
	// cache among the largest resident owners while its accounting said
	// it was well inside its bound. The stripped body only counts when
	// it is its own buffer; for unsigned proofs it aliases the full one.
	entry.wireBytes += int64(len(entry.wireFull))
	if len(entry.wireStripped) > 0 && &entry.wireStripped[0] != &entry.wireFull[0] {
		entry.wireBytes += int64(len(entry.wireStripped))
	}

	// Preserve a current usable cut if its replacement cannot fit even in an
	// otherwise-empty cache or zone.
	if entry.wireBytes > c.maxBytes || entry.wireBytes > c.maxBytesPerZone {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return false
	}
	if previous := c.entries[entry.id]; previous != nil {
		c.removeEntryLocked(previous)
	}

	zoneState := c.zones[entry.zoneKey]
	if zoneState == nil {
		zoneState = new(nxDomainCutZoneState)
		c.zones[entry.zoneKey] = zoneState
	}
	entry.globalElem = c.fifo.PushBack(entry)
	entry.zoneElem = zoneState.fifo.PushBack(entry)
	c.entries[entry.id] = entry
	if entry.wireFull != nil {
		c.byHash[entry.hash] = entry
	}
	c.totalBytes += entry.wireBytes
	zoneState.wireBytes += entry.wireBytes

	// Zone limits must run first. If the global index is already full, a
	// hostile zone refreshing its own full partition must evict one of its own
	// cuts rather than displacing an unrelated healthy zone.
	c.enforceZoneLimitsLocked(entry.zoneKey)
	c.enforceGlobalLimitsLocked()
	return c.entries[entry.id] == entry
}

func negativeProofKind(records []dns.RR) middleware.ValidatedNegativeProofKind {
	for _, rr := range records {
		if _, ok := rr.(*dns.NSEC3); ok {
			return middleware.ValidatedNegativeProofNSEC3
		}
	}
	for _, rr := range records {
		if _, ok := rr.(*dns.NSEC); ok {
			return middleware.ValidatedNegativeProofNSEC
		}
	}
	return middleware.ValidatedNegativeProofUnknown
}

// nxDomainCutProof extracts the SOA and authenticated NSEC/NSEC3 proof RRsets
// belonging to zone. It intentionally discards Answer and Extra: RFC 8020
// descendant replies prove only the terminal denied subtree, not the alias
// chain that happened to discover it.
func nxDomainCutProof(msg *dns.Msg, deniedName, zone string) (*dns.Msg, *dns.SOA, bool) {
	type rrsetKey struct {
		owner  string
		rtype  uint16
		qclass uint16
	}

	if dnsutil.HasNSEC3OptOut(msg.Ns, zone) {
		return nil, nil, false
	}
	useNSEC3 := false
	for _, rr := range msg.Ns {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok || !dnsname.Sub(zone, dns.CanonicalName(nsec3.Hdr.Name)) {
			continue
		}
		useNSEC3 = true
	}

	var soa *dns.SOA
	for _, rr := range msg.Ns {
		record, ok := rr.(*dns.SOA)
		if !ok || !equalNameASCIIFold(dns.CanonicalName(record.Hdr.Name), zone) {
			continue
		}
		soa = record
		break
	}
	if soa == nil || len(msg.Question) != 1 ||
		msg.Question[0].Qclass != soa.Hdr.Class {
		return nil, nil, false
	}

	// Retain complete RRsets only. Provenance proves the original message,
	// but the synthesized response must not copy an unrelated/orphan RRSIG
	// or an NSEC whose NextDomain escaped the validated signer zone.
	retained := make(map[rrsetKey]struct{})
	soaKey := rrsetKey{
		owner:  zone,
		rtype:  dns.TypeSOA,
		qclass: soa.Hdr.Class,
	}
	retained[soaKey] = struct{}{}
	proofKeys := make(map[rrsetKey]struct{})

	for _, rr := range msg.Ns {
		owner := dns.CanonicalName(rr.Header().Name)
		if !dnsname.Sub(zone, owner) || rr.Header().Class != soa.Hdr.Class {
			continue
		}

		var key rrsetKey
		switch record := rr.(type) {
		case *dns.SOA:
			if owner != zone {
				continue
			}
			key = soaKey
		case *dns.NSEC:
			next := dns.CanonicalName(record.NextDomain)
			if useNSEC3 {
				continue
			}
			// Filtering just this RDATA would leave the retained RRSIG
			// covering a different RRset. Fail closed for shared cut
			// admission instead; the exact negative answer remains cached.
			if !dnsname.Sub(zone, next) {
				return nil, nil, false
			}
			key = rrsetKey{owner: owner, rtype: dns.TypeNSEC, qclass: record.Hdr.Class}
			proofKeys[key] = struct{}{}
		case *dns.NSEC3:
			if !useNSEC3 {
				continue
			}
			key = rrsetKey{owner: owner, rtype: dns.TypeNSEC3, qclass: record.Hdr.Class}
			proofKeys[key] = struct{}{}
		default:
			continue
		}
		retained[key] = struct{}{}
	}

	if len(proofKeys) == 0 || !dnsname.Sub(zone, deniedName) {
		return nil, nil, false
	}

	signed := make(map[rrsetKey]struct{})
	for _, rr := range msg.Ns {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.Hdr.Class != soa.Hdr.Class ||
			dns.CanonicalName(sig.SignerName) != zone {
			continue
		}
		key := rrsetKey{
			owner:  dns.CanonicalName(sig.Hdr.Name),
			rtype:  sig.TypeCovered,
			qclass: sig.Hdr.Class,
		}
		if _, ok := retained[key]; ok {
			signed[key] = struct{}{}
		}
	}
	for key := range retained {
		if _, ok := signed[key]; !ok {
			return nil, nil, false
		}
	}

	proof := new(dns.Msg)
	proof.Response = true
	proof.Rcode = dns.RcodeNameError
	proof.RecursionAvailable = true
	proof.AuthenticatedData = true
	proof.Question = []dns.Question{{
		Name:   deniedName,
		Qtype:  dns.TypeA,
		Qclass: soa.Hdr.Class,
	}}
	for _, rr := range msg.Ns {
		key := rrsetKey{
			owner:  dns.CanonicalName(rr.Header().Name),
			rtype:  rr.Header().Rrtype,
			qclass: rr.Header().Class,
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			if dns.CanonicalName(sig.SignerName) != zone {
				continue
			}
			key.rtype = sig.TypeCovered
		}
		if _, ok := retained[key]; ok {
			proof.Ns = append(proof.Ns, dns.Copy(rr))
		}
	}
	// A hostile but legitimately signed zone can pad negative responses with
	// unrelated signed denial RRsets. The ordinary exact response may retain
	// those bytes; duplicating an unbounded proof into every subtree-cut entry
	// would turn the separate cut index into a memory amplifier. Ordinary
	// NSEC/NSEC3 NXDOMAIN proofs fit comfortably inside these conservative
	// limits; oversized inputs simply remain exact-cache-only.
	if len(proof.Ns) > maxNXDomainCutProofRRs ||
		proof.Len() > maxNXDomainCutProofBytes {
		return nil, nil, false
	}

	soaCopy, _ := dns.Copy(soa).(*dns.SOA)
	if soaCopy == nil {
		return nil, nil, false
	}
	return proof, soaCopy, true
}

// lookup returns the closest cached denied ancestor of q. Walking DNS label
// boundaries (rather than using a string suffix) keeps sibling names such as
// notexample.com. isolated from example.com.
func (c *nxDomainCutCache) lookup(q dns.Question) (*nxDomainCutEntry, bool) {
	if c == nil || q.Qclass == 0 {
		return nil, false
	}

	name := dns.CanonicalName(q.Name)
	now := time.Now()
	for offset := range dnsname.Suffixes(name) {
		candidate := name[offset:]
		id := nxDomainCutID{deniedName: candidate, qclass: q.Qclass}

		c.mu.RLock()
		entry := c.entries[id]
		c.mu.RUnlock()
		if entry == nil {
			continue
		}
		if !now.Before(entry.expires) {
			c.mu.Lock()
			c.removeEntryLocked(entry)
			c.mu.Unlock()
			continue
		}
		return entry, true
	}
	return nil, false
}

func (e *nxDomainCutEntry) response(req *dns.Msg) *dns.Msg {
	if e == nil || req == nil || len(req.Question) == 0 || req.CheckingDisabled {
		return nil
	}
	now := time.Now()
	remaining := e.expires.Sub(now)
	if remaining <= 0 {
		return nil
	}

	resp := e.msg.Copy()
	resp.SetReply(req)
	resp.Rcode = dns.RcodeNameError
	resp.Authoritative = false
	resp.RecursionAvailable = true
	resp.AuthenticatedData = true
	resp.CheckingDisabled = false
	resp.Answer = nil
	resp.Extra = nil

	ttl := servedSeconds(remaining)
	for _, rr := range resp.Ns {
		rr.Header().Ttl = ttl
	}

	// The DO=0 shape is ClearDNSSEC's, the same as the exact-entry serve's:
	// the one authenticating type the question named stays, every other
	// goes (RFC 4035 §3.2.1). The wire template declines these questions
	// and lands here for exactly this.
	if opt := req.IsEdns0(); opt == nil || !opt.Do() {
		resp = dnsutil.ClearDNSSEC(resp)
	}
	return resp
}

// purge removes every cut that currently covers q. Without this, an explicit
// operator purge of a descendant would immediately be hidden again by its
// cached denied ancestor.
func (c *nxDomainCutCache) purge(q dns.Question) {
	if c == nil {
		return
	}
	name := dns.CanonicalName(q.Name)
	c.mu.Lock()
	defer c.mu.Unlock()
	for offset := range dnsname.Suffixes(name) {
		candidate := name[offset:]
		id := nxDomainCutID{deniedName: candidate, qclass: q.Qclass}
		if entry := c.entries[id]; entry != nil {
			c.removeEntryLocked(entry)
		}
	}
}

func (c *nxDomainCutCache) removeEntryLocked(entry *nxDomainCutEntry) {
	if entry == nil || c.entries[entry.id] != entry {
		return
	}
	delete(c.entries, entry.id)
	if c.byHash[entry.hash] == entry {
		delete(c.byHash, entry.hash)
	}
	if entry.globalElem != nil {
		c.fifo.Remove(entry.globalElem)
		entry.globalElem = nil
	}
	c.totalBytes -= entry.wireBytes
	if c.totalBytes < 0 {
		c.totalBytes = 0
	}

	zoneState := c.zones[entry.zoneKey]
	if zoneState == nil {
		return
	}
	if entry.zoneElem != nil {
		zoneState.fifo.Remove(entry.zoneElem)
		entry.zoneElem = nil
	}
	zoneState.wireBytes -= entry.wireBytes
	if zoneState.wireBytes < 0 {
		zoneState.wireBytes = 0
	}
	if zoneState.fifo.Len() == 0 {
		delete(c.zones, entry.zoneKey)
	}
}

func (c *nxDomainCutCache) enforceZoneLimitsLocked(key nxDomainCutZoneKey) {
	for {
		zoneState := c.zones[key]
		if zoneState == nil ||
			(zoneState.fifo.Len() <= c.maxEntriesPerZone &&
				zoneState.wireBytes <= c.maxBytesPerZone) {
			return
		}
		element := zoneState.fifo.Front()
		if element == nil {
			delete(c.zones, key)
			return
		}
		entry, _ := element.Value.(*nxDomainCutEntry)
		if entry == nil {
			zoneState.fifo.Remove(element)
			continue
		}
		c.removeEntryLocked(entry)
	}
}

func (c *nxDomainCutCache) enforceGlobalLimitsLocked() {
	for len(c.entries) > c.maxEntries || c.totalBytes > c.maxBytes {
		element := c.fifo.Front()
		if element == nil {
			return
		}
		entry, _ := element.Value.(*nxDomainCutEntry)
		if entry == nil {
			c.fifo.Remove(element)
			continue
		}
		c.removeEntryLocked(entry)
	}
}

func (c *nxDomainCutCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	length := len(c.entries)
	c.mu.RUnlock()
	return length
}

func (c *nxDomainCutCache) stop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.stopped = true
	c.entries = make(map[nxDomainCutID]*nxDomainCutEntry)
	c.zones = make(map[nxDomainCutZoneKey]*nxDomainCutZoneState)
	c.fifo.Init()
	c.totalBytes = 0
	c.mu.Unlock()
}
