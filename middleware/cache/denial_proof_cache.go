package cache

import (
	"bytes"
	"container/list"
	"encoding/base32"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

const (
	maxDenialProofBundleRRs   = 32
	maxDenialProofBundleBytes = 8 << 10
	maxDenialProofTTL         = 3 * time.Hour
	maxDenialProofNSEC3Groups = 2
)

type denialProofKind uint8

const (
	denialProofSOA denialProofKind = iota + 1
	denialProofNSEC
	denialProofNSEC3
)

type denialProofZoneKey struct {
	zone   string
	qclass uint16
}

type denialProofNSEC3Params struct {
	hash       uint8
	iterations uint16
	salt       string
}

type denialProofNSEC3ConflictKey struct {
	zone   denialProofZoneKey
	params denialProofNSEC3Params
}

type denialProofID struct {
	zone       string
	owner      string
	salt       string
	qclass     uint16
	iterations uint16
	kind       denialProofKind
	hash       uint8
}

// denialProofEntry is immutable after publication. The queue element is
// touched only while the cache write lock is held and is never observed by
// readers.
type denialProofEntry struct {
	id         denialProofID
	zoneKey    denialProofZoneKey
	params     denialProofNSEC3Params
	ownerHash  string
	ownerOrder denialProofNameOrder
	data       []dns.RR
	// preparedNSEC mirrors data for an NSEC set, with each record's owner
	// and next-domain names already canonical. Canonicalizing is a pure
	// function of records that never change while cached, so it is paid for
	// here — once per admission — instead of on every lookup that consults
	// this zone. Empty for SOA and NSEC3 sets.
	preparedNSEC []dnssec.PreparedNSEC
	records      []dns.RR
	expires      time.Time
	wireBytes    int64
	sequence     uint64
	queue        *list.Element
}

// denialProofZoneSnapshot is published copy-on-write. Readers may retain a
// pointer after dropping the cache lock; writers therefore never mutate its
// maps or slices.
type denialProofZoneSnapshot struct {
	soa  *denialProofEntry
	nsec []*denialProofEntry
	// nsecPrepared is nsec's canonicalized records, flattened in the same
	// order. Readers treat it as immutable, as they do the rest of the
	// snapshot.
	nsecPrepared []dnssec.PreparedNSEC
	nsec3        map[denialProofNSEC3Params][]*denialProofEntry
	nsec3Order   []denialProofNSEC3Params
	wireBytes    int64
}

type denialProofCacheConfig struct {
	MaxEntries        int
	MaxEntriesPerZone int
	MaxBytes          int64
	MaxBytesPerZone   int64
	MaxTTL            time.Duration
	Now               func() time.Time
}

// denialProofCache is a bounded, validation-provenance-only RFC 8198 proof
// index. It deliberately does not share eviction state with the ordinary
// answer caches: random denial owners must not displace useful answers.
//
// Hits never mutate cache state. Admission, expiry replacement, purge, and
// FIFO eviction publish fresh per-zone snapshots.
type denialProofCache struct {
	mu sync.RWMutex

	zoneIndex map[denialProofZoneKey]*denialProofZoneSnapshot
	// zoneEntries is the writer's own index of what each zone holds. It is
	// never published, so it can be mutated in place: a snapshot used to
	// carry this map too, which meant admitting or evicting one entry
	// copied the entire zone.
	zoneEntries map[denialProofZoneKey]map[denialProofID]*denialProofEntry
	byID        map[denialProofID]*denialProofEntry
	fifo        list.List

	maxEntries        int
	maxEntriesPerZone int
	maxBytes          int64
	maxBytesPerZone   int64
	maxTTL            time.Duration
	now               func() time.Time

	totalBytes int64
	sequence   uint64
	stopped    bool

	// A locally validated tuple that presents two different RDATA values at
	// one owner hash is ambiguous until both observations expire. Tombstones
	// preserve that fact after the retained ring is removed. The map is
	// bounded by maxEntries; if it fills, one global expiry backstop keeps
	// new NSEC3 admission and synthesis fail-open without unbounded memory.
	nsec3Conflicts             map[denialProofNSEC3ConflictKey]time.Time
	nsec3ConflictOverflowUntil time.Time
}

func newDenialProofCache(size int, maxTTL time.Duration) *denialProofCache {
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

	return newDenialProofCacheWithConfig(denialProofCacheConfig{
		MaxEntries:        size,
		MaxEntriesPerZone: perZone,
		MaxBytes:          denialProofDerivedBytes(size),
		MaxBytesPerZone:   denialProofDerivedBytes(perZone),
		MaxTTL:            maxTTL,
	})
}

func newDenialProofCacheWithConfig(cfg denialProofCacheConfig) *denialProofCache {
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
		cfg.MaxBytes = denialProofDerivedBytes(cfg.MaxEntries)
	}
	if cfg.MaxBytesPerZone < 1 {
		cfg.MaxBytesPerZone = denialProofDerivedBytes(cfg.MaxEntriesPerZone)
	}
	if cfg.MaxBytesPerZone > cfg.MaxBytes {
		cfg.MaxBytesPerZone = cfg.MaxBytes
	}
	if cfg.MaxTTL <= 0 || cfg.MaxTTL > maxDenialProofTTL {
		cfg.MaxTTL = maxDenialProofTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &denialProofCache{
		zoneIndex:         make(map[denialProofZoneKey]*denialProofZoneSnapshot),
		zoneEntries:       make(map[denialProofZoneKey]map[denialProofID]*denialProofEntry),
		byID:              make(map[denialProofID]*denialProofEntry),
		maxEntries:        cfg.MaxEntries,
		maxEntriesPerZone: cfg.MaxEntriesPerZone,
		maxBytes:          cfg.MaxBytes,
		maxBytesPerZone:   cfg.MaxBytesPerZone,
		maxTTL:            cfg.MaxTTL,
		now:               cfg.Now,
		nsec3Conflicts:    make(map[denialProofNSEC3ConflictKey]time.Time),
	}
}

func denialProofDerivedBytes(entries int) int64 {
	if entries < 1 {
		return maxDenialProofBundleBytes
	}
	if int64(entries) > math.MaxInt64/maxDenialProofBundleBytes {
		return math.MaxInt64
	}
	return int64(entries) * maxDenialProofBundleBytes
}

type denialProofRRSetKey struct {
	owner  string
	qclass uint16
	kind   denialProofKind
}

type denialProofRRSet struct {
	key        denialProofRRSetKey
	ownerOrder denialProofNameOrder
	params     denialProofNSEC3Params
	ownerHash  string
	next       string
	flags      uint8
	types      []uint16
	data       []dns.RR
	sigs       []dns.RR
}

// record accepts only a terminal response whose denial semantics and
// signatures were already validated locally. Wire AD is intentionally not a
// trust signal; callers must gate this method with resolver-local provenance.
func (c *denialProofCache) record(
	msg *dns.Msg,
	zone string,
	cutUntil time.Time,
) bool {
	return c.recordWithKind(msg, zone, 0, cutUntil)
}

// recordWithKind additionally binds admission to the resolver-authenticated
// denial family. The comparison happens after extract has canonicalized the
// signer zone and discarded out-of-zone records; checking the raw authority
// section would let unrelated records either cause false misses or select a
// family the retained proof did not use.
func (c *denialProofCache) recordWithKind(
	msg *dns.Msg,
	zone string,
	expected denialProofKind,
	cutUntil time.Time,
) bool {
	if c == nil {
		return false
	}
	now := c.now()
	entries, ok := c.extract(msg, zone, cutUntil, now)
	if !ok {
		return false
	}
	if expected != 0 {
		if expected != denialProofNSEC && expected != denialProofNSEC3 {
			return false
		}
		for _, entry := range entries {
			if entry.id.kind != denialProofSOA && entry.id.kind != expected {
				return false
			}
		}
	}

	var batchBytes int64
	for _, entry := range entries {
		batchBytes += entry.wireBytes
	}
	if len(entries) > c.maxEntries ||
		len(entries) > c.maxEntriesPerZone ||
		batchBytes > c.maxBytes ||
		batchBytes > c.maxBytesPerZone {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return false
	}

	for _, entry := range entries {
		if entry.id.kind == denialProofNSEC3 &&
			c.nsec3ConflictActiveLocked(
				denialProofNSEC3ConflictKey{
					zone:   entry.zoneKey,
					params: entry.params,
				},
				now,
			) {
			return false
		}
	}

	// A second locally validated RRset at the same tuple+owner hash with
	// different NSEC3 semantics is a detectable collision/chain ambiguity.
	// Never choose "latest wins": invalidate the complete parameter ring and
	// quarantine it through both observations' lifetimes so a third response
	// cannot immediately repopulate the detected-ambiguous tuple.
	for _, entry := range entries {
		if entry.id.kind != denialProofNSEC3 {
			continue
		}
		previous := c.byID[entry.id]
		if previous == nil || !now.Before(previous.expires) ||
			denialProofNSEC3EntriesEquivalent(previous, entry) {
			continue
		}
		snapshot := c.zoneIndex[entry.zoneKey]
		if snapshot != nil {
			conflicted := append(
				[]*denialProofEntry(nil),
				snapshot.nsec3[entry.params]...,
			)
			for _, retained := range conflicted {
				c.removeEntryLocked(retained)
			}
		}
		expires := entry.expires
		if previous.expires.After(expires) {
			expires = previous.expires
		}
		c.recordNSEC3ConflictLocked(
			denialProofNSEC3ConflictKey{
				zone:   entry.zoneKey,
				params: entry.params,
			},
			expires,
			now,
		)
		return false
	}

	for _, entry := range entries {
		if previous := c.byID[entry.id]; previous != nil {
			c.removeEntryLocked(previous)
		}
		c.sequence++
		entry.sequence = c.sequence
		entry.queue = c.fifo.PushBack(entry)
		c.byID[entry.id] = entry
		c.totalBytes += entry.wireBytes

		c.zoneEntriesLocked(entry.zoneKey)[entry.id] = entry
		c.publishZoneLocked(entry.zoneKey)
	}

	c.enforceNSEC3GroupLimitLocked(entries[0].zoneKey)
	c.enforceZoneLimitsLocked(entries[0].zoneKey)
	c.enforceGlobalLimitsLocked()
	return true
}

func (c *denialProofCache) pruneNSEC3ConflictsLocked(now time.Time) {
	for key, expires := range c.nsec3Conflicts {
		if !now.Before(expires) {
			delete(c.nsec3Conflicts, key)
		}
	}
	if !now.Before(c.nsec3ConflictOverflowUntil) {
		c.nsec3ConflictOverflowUntil = time.Time{}
	}
}

func (c *denialProofCache) nsec3ConflictActiveLocked(
	key denialProofNSEC3ConflictKey,
	now time.Time,
) bool {
	if now.Before(c.nsec3ConflictOverflowUntil) {
		return true
	}
	return now.Before(c.nsec3Conflicts[key])
}

func (c *denialProofCache) recordNSEC3ConflictLocked(
	key denialProofNSEC3ConflictKey,
	expires time.Time,
	now time.Time,
) {
	if !now.Before(expires) {
		return
	}
	if previous, exists := c.nsec3Conflicts[key]; exists {
		if now.Before(previous) {
			if expires.After(previous) {
				c.nsec3Conflicts[key] = expires
			}
			return
		}
		delete(c.nsec3Conflicts, key)
	}
	// Expiry pruning is O(number of tombstones), so keep it off the normal
	// admission path and pay that scan only when the bounded map is full.
	if len(c.nsec3Conflicts) >= c.maxEntries {
		c.pruneNSEC3ConflictsLocked(now)
	}
	if len(c.nsec3Conflicts) < c.maxEntries {
		c.nsec3Conflicts[key] = expires
		return
	}
	if expires.After(c.nsec3ConflictOverflowUntil) {
		c.nsec3ConflictOverflowUntil = expires
	}
}

func denialProofNSEC3EntriesEquivalent(a, b *denialProofEntry) bool {
	if a == nil || b == nil ||
		a.id.kind != denialProofNSEC3 ||
		b.id.kind != denialProofNSEC3 ||
		a.params != b.params ||
		a.ownerHash != b.ownerHash ||
		len(a.data) == 0 ||
		len(b.data) == 0 {
		return false
	}
	left, leftOK := a.data[0].(*dns.NSEC3)
	right, rightOK := b.data[0].(*dns.NSEC3)
	if !leftOK || !rightOK || left == nil || right == nil {
		return false
	}
	return left.Flags == right.Flags &&
		strings.EqualFold(left.NextDomain, right.NextDomain) &&
		denialProofTypeBitmapsEqual(left.TypeBitMap, right.TypeBitMap)
}

func (c *denialProofCache) extract(
	msg *dns.Msg,
	zone string,
	cutUntil time.Time,
	now time.Time,
) ([]*denialProofEntry, bool) {
	if msg == nil || len(msg.Question) != 1 || msg.CheckingDisabled ||
		len(msg.Answer) != 0 ||
		(msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeSuccess) {
		return nil, false
	}

	zone = dns.CanonicalName(zone)
	q := msg.Question[0]
	qname := dns.CanonicalName(q.Name)
	if _, valid := dns.IsDomainName(zone); !valid {
		return nil, false
	}
	if _, valid := dns.IsDomainName(qname); !valid {
		return nil, false
	}
	if q.Qclass == 0 || q.Qclass == dns.ClassANY || q.Qclass == dns.ClassNONE ||
		!dns.IsSubDomain(zone, qname) {
		return nil, false
	}

	sets := make(map[denialProofRRSetKey]*denialProofRRSet)
	soaKey := denialProofRRSetKey{
		owner:  zone,
		qclass: q.Qclass,
		kind:   denialProofSOA,
	}
	sawNSEC, sawNSEC3 := false, false
	var nsec3Parameters *denialProofNSEC3Params

	for _, rr := range msg.Ns {
		if rr == nil || rr.Header() == nil || rr.Header().Class != q.Qclass {
			continue
		}
		owner := dns.CanonicalName(rr.Header().Name)
		if _, valid := dns.IsDomainName(owner); !valid {
			return nil, false
		}

		switch record := rr.(type) {
		case *dns.SOA:
			if record == nil || record.Hdr.Rrtype != dns.TypeSOA || owner != zone {
				continue
			}
			set := sets[soaKey]
			if set == nil {
				set = &denialProofRRSet{
					key:        soaKey,
					ownerOrder: denialProofNameOrderFor(zone),
				}
				sets[soaKey] = set
			}
			// RFC 1035 defines one SOA at an apex. Multiple SOA RDATA
			// values are not a proof bundle this cache can safely replay.
			if len(set.data) != 0 {
				return nil, false
			}
			set.data = append(set.data, rr)

		case *dns.NSEC:
			if record == nil || record.Hdr.Rrtype != dns.TypeNSEC ||
				!dns.IsSubDomain(zone, owner) {
				continue
			}
			next := dns.CanonicalName(record.NextDomain)
			if _, valid := dns.IsDomainName(next); !valid ||
				!dns.IsSubDomain(zone, next) {
				return nil, false
			}
			sawNSEC = true
			key := denialProofRRSetKey{
				owner:  owner,
				qclass: q.Qclass,
				kind:   denialProofNSEC,
			}
			set := sets[key]
			if set == nil {
				set = &denialProofRRSet{
					key:        key,
					ownerOrder: denialProofNameOrderFor(owner),
					next:       next,
					types:      append([]uint16(nil), record.TypeBitMap...),
				}
				sets[key] = set
			} else if set.next != next ||
				!denialProofTypeBitmapsEqual(set.types, record.TypeBitMap) {
				return nil, false
			}
			set.data = append(set.data, rr)

		case *dns.NSEC3:
			if record == nil || record.Hdr.Rrtype != dns.TypeNSEC3 ||
				!dns.IsSubDomain(zone, owner) {
				continue
			}
			params, ownerHash, nextHash, valid := denialProofNSEC3Identity(record, zone)
			if !valid {
				return nil, false
			}
			if nsec3Parameters == nil {
				parameters := params
				nsec3Parameters = &parameters
			} else if *nsec3Parameters != params {
				return nil, false
			}
			sawNSEC3 = true
			key := denialProofRRSetKey{
				owner:  owner,
				qclass: q.Qclass,
				kind:   denialProofNSEC3,
			}
			set := sets[key]
			if set == nil {
				set = &denialProofRRSet{
					key:        key,
					ownerOrder: denialProofNameOrderFor(owner),
					params:     params,
					ownerHash:  ownerHash,
					next:       nextHash,
					flags:      record.Flags,
					types:      append([]uint16(nil), record.TypeBitMap...),
				}
				sets[key] = set
			} else if set.params != params ||
				set.ownerHash != ownerHash ||
				set.next != nextHash ||
				set.flags != record.Flags ||
				!denialProofTypeBitmapsEqual(set.types, record.TypeBitMap) {
				return nil, false
			}
			set.data = append(set.data, rr)
		}
	}

	if sawNSEC == sawNSEC3 {
		// Reject both an empty denial and a bundle that mixes denial
		// mechanisms. The resolver provenance selects exactly one chain.
		return nil, false
	}
	soaSet := sets[soaKey]
	if soaSet == nil || len(soaSet.data) != 1 {
		return nil, false
	}

	for _, rr := range msg.Ns {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig == nil ||
			sig.Hdr.Rrtype != dns.TypeRRSIG ||
			sig.Hdr.Class != q.Qclass ||
			dns.CanonicalName(sig.SignerName) != zone {
			continue
		}
		owner := dns.CanonicalName(sig.Hdr.Name)
		if _, valid := dns.IsDomainName(owner); !valid ||
			!dns.IsSubDomain(zone, owner) {
			continue
		}

		var kind denialProofKind
		switch sig.TypeCovered {
		case dns.TypeSOA:
			kind = denialProofSOA
		case dns.TypeNSEC:
			if !sawNSEC {
				continue
			}
			kind = denialProofNSEC
		case dns.TypeNSEC3:
			if !sawNSEC3 {
				continue
			}
			kind = denialProofNSEC3
		default:
			continue
		}
		key := denialProofRRSetKey{owner: owner, qclass: q.Qclass, kind: kind}
		if set := sets[key]; set != nil {
			set.sigs = append(set.sigs, rr)
		}
	}

	proofSets := make([]*denialProofRRSet, 0, len(sets)-1)
	for key, set := range sets {
		if len(set.data) == 0 || len(set.sigs) == 0 {
			return nil, false
		}
		if key.kind != denialProofSOA {
			proofSets = append(proofSets, set)
		}
	}
	if len(proofSets) == 0 {
		return nil, false
	}
	sort.Slice(proofSets, func(i, j int) bool {
		if proofSets[i].key.kind != proofSets[j].key.kind {
			return proofSets[i].key.kind < proofSets[j].key.kind
		}
		return proofSets[i].ownerOrder.compare(proofSets[j].ownerOrder) < 0
	})

	retained := make([]dns.RR, 0, maxDenialProofBundleRRs)
	retained = append(retained, soaSet.data...)
	retained = append(retained, soaSet.sigs...)
	for _, set := range proofSets {
		retained = append(retained, set.data...)
		retained = append(retained, set.sigs...)
	}
	if len(retained) > maxDenialProofBundleRRs {
		return nil, false
	}
	bundle := new(dns.Msg)
	bundle.Ns = retained
	if bundle.Len() > maxDenialProofBundleBytes {
		return nil, false
	}

	commonRecords := make([]dns.RR, 0, len(soaSet.data)+len(soaSet.sigs))
	commonRecords = append(commonRecords, soaSet.data...)
	commonRecords = append(commonRecords, soaSet.sigs...)
	commonExpiry, ok := denialProofExpiry(now, c.maxTTL, cutUntil, commonRecords)
	if !ok {
		return nil, false
	}

	zoneKey := denialProofZoneKey{zone: zone, qclass: q.Qclass}
	result := make([]*denialProofEntry, 0, 1+len(proofSets))
	soaEntry, ok := newDenialProofEntry(
		soaSet,
		zoneKey,
		now,
		commonExpiry,
	)
	if !ok {
		return nil, false
	}
	result = append(result, soaEntry)

	for _, set := range proofSets {
		lifetimeRecords := make(
			[]dns.RR,
			0,
			len(commonRecords)+len(set.data)+len(set.sigs),
		)
		lifetimeRecords = append(lifetimeRecords, commonRecords...)
		lifetimeRecords = append(lifetimeRecords, set.data...)
		lifetimeRecords = append(lifetimeRecords, set.sigs...)
		expiry, valid := denialProofExpiry(
			now,
			c.maxTTL,
			cutUntil,
			lifetimeRecords,
		)
		if !valid {
			return nil, false
		}
		entry, valid := newDenialProofEntry(set, zoneKey, now, expiry)
		if !valid {
			return nil, false
		}
		result = append(result, entry)
	}
	return result, true
}

func newDenialProofEntry(
	set *denialProofRRSet,
	zoneKey denialProofZoneKey,
	now time.Time,
	expires time.Time,
) (*denialProofEntry, bool) {
	if set == nil || len(set.data) == 0 || len(set.sigs) == 0 ||
		!now.Before(expires) {
		return nil, false
	}

	data := make([]dns.RR, 0, len(set.data))
	records := make([]dns.RR, 0, len(set.data)+len(set.sigs))
	var prepared []dnssec.PreparedNSEC
	if set.key.kind == denialProofNSEC {
		prepared = make([]dnssec.PreparedNSEC, 0, len(set.data))
	}
	var wireBytes int64
	for _, rr := range set.data {
		copied := dns.Copy(rr)
		if copied == nil {
			return nil, false
		}
		if prepared != nil {
			nsec, ok := copied.(*dns.NSEC)
			if !ok {
				return nil, false
			}
			// A record whose names cannot be canonicalized could never
			// produce an aggressive answer, so there is nothing to gain by
			// holding it: refusing it here leaves the lookup falling back to
			// ordinary resolution, exactly as an evaluation failure would.
			candidate, err := dnssec.PrepareAggressiveNSEC(nsec)
			if err != nil {
				return nil, false
			}
			prepared = append(prepared, candidate)
		}
		data = append(data, copied)
		records = append(records, copied)
		wireBytes += int64(dns.Len(copied))
	}
	for _, rr := range set.sigs {
		copied := dns.Copy(rr)
		if copied == nil {
			return nil, false
		}
		records = append(records, copied)
		wireBytes += int64(dns.Len(copied))
	}

	id := denialProofID{
		zone:       zoneKey.zone,
		owner:      set.key.owner,
		salt:       set.params.salt,
		qclass:     zoneKey.qclass,
		iterations: set.params.iterations,
		kind:       set.key.kind,
		hash:       set.params.hash,
	}
	return &denialProofEntry{
		id:           id,
		zoneKey:      zoneKey,
		params:       set.params,
		ownerHash:    set.ownerHash,
		ownerOrder:   set.ownerOrder,
		data:         data,
		preparedNSEC: prepared,
		records:      records,
		expires:      expires,
		wireBytes:    wireBytes,
	}, true
}

func denialProofExpiry(
	now time.Time,
	maxTTL time.Duration,
	cutUntil time.Time,
	records []dns.RR,
) (time.Time, bool) {
	if maxTTL <= 0 || maxTTL > maxDenialProofTTL {
		maxTTL = maxDenialProofTTL
	}
	ttl := maxTTL
	bound := func(candidate time.Duration) {
		if candidate < ttl {
			ttl = candidate
		}
	}

	if !cutUntil.IsZero() {
		bound(cutUntil.Sub(now))
	}
	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			return time.Time{}, false
		}
		bound(time.Duration(rr.Header().Ttl) * time.Second)
		switch record := rr.(type) {
		case *dns.SOA:
			bound(time.Duration(record.Minttl) * time.Second)
		case *dns.RRSIG:
			bound(time.Duration(record.OrigTtl) * time.Second)
			bound(time.Unix(int64(record.Expiration), 0).Sub(now))
		}
	}
	if ttl <= 0 {
		return time.Time{}, false
	}
	return now.Add(ttl), true
}

var denialProofBase32Hex = base32.HexEncoding.WithPadding(base32.NoPadding)

func denialProofNSEC3Identity(
	record *dns.NSEC3,
	zone string,
) (denialProofNSEC3Params, string, string, bool) {
	if !dnssec.AggressiveNSEC3Usable(record) {
		return denialProofNSEC3Params{}, "", "", false
	}
	owner := dns.CanonicalName(record.Hdr.Name)
	ownerLabels := dns.SplitDomainName(owner)
	zoneLabels := dns.SplitDomainName(zone)
	if len(ownerLabels) != len(zoneLabels)+1 ||
		!dns.IsSubDomain(zone, owner) {
		return denialProofNSEC3Params{}, "", "", false
	}

	ownerHash, ok := denialProofCanonicalNSEC3Hash(ownerLabels[0])
	if !ok {
		return denialProofNSEC3Params{}, "", "", false
	}
	nextHash, ok := denialProofCanonicalNSEC3Hash(record.NextDomain)
	if !ok {
		return denialProofNSEC3Params{}, "", "", false
	}
	saltBytes, err := hex.DecodeString(record.Salt)
	if err != nil || len(saltBytes) != int(record.SaltLength) ||
		record.HashLength != 20 {
		return denialProofNSEC3Params{}, "", "", false
	}

	params := denialProofNSEC3Params{
		hash:       record.Hash,
		iterations: record.Iterations,
		salt:       strings.ToUpper(record.Salt),
	}
	return params, ownerHash, nextHash, true
}

func denialProofCanonicalNSEC3Hash(value string) (string, bool) {
	if len(value) != 32 {
		return "", false
	}
	value = strings.ToUpper(value)
	for i := range len(value) {
		octet := value[i]
		if (octet < '0' || octet > '9') &&
			(octet < 'A' || octet > 'V') {
			return "", false
		}
	}
	decoded, err := denialProofBase32Hex.DecodeString(value)
	if err != nil || len(decoded) != 20 {
		return "", false
	}
	return value, true
}

func denialProofTypeBitmapsEqual(a, b []uint16) bool {
	aSet := make(map[uint16]struct{}, len(a))
	bSet := make(map[uint16]struct{}, len(b))
	for _, rrtype := range a {
		aSet[rrtype] = struct{}{}
	}
	for _, rrtype := range b {
		bSet[rrtype] = struct{}{}
	}
	if len(aSet) != len(bSet) {
		return false
	}
	for rrtype := range aSet {
		if _, ok := bSet[rrtype]; !ok {
			return false
		}
	}
	return true
}

// zoneEntriesLocked returns the writer's index for a zone, creating it on
// first use. It is not published, so callers add to and delete from it
// directly; publishZoneLocked then derives a fresh read-only snapshot from
// whatever it holds.
func (c *denialProofCache) zoneEntriesLocked(
	key denialProofZoneKey,
) map[denialProofID]*denialProofEntry {
	entries := c.zoneEntries[key]
	if entries == nil {
		entries = make(map[denialProofID]*denialProofEntry)
		c.zoneEntries[key] = entries
	}
	return entries
}

// publishZoneLocked rebuilds the read-only view readers see. Readers keep a
// pointer to it without holding the lock, so it is replaced rather than
// edited — but only the derived views need copying, not the writer's index
// of the zone.
func (c *denialProofCache) publishZoneLocked(key denialProofZoneKey) {
	entries := c.zoneEntries[key]
	if len(entries) == 0 {
		delete(c.zoneIndex, key)
		delete(c.zoneEntries, key)
		return
	}
	snapshot := &denialProofZoneSnapshot{
		nsec3: make(map[denialProofNSEC3Params][]*denialProofEntry),
	}
	groupSequence := make(map[denialProofNSEC3Params]uint64)
	for _, entry := range entries {
		snapshot.wireBytes += entry.wireBytes
		switch entry.id.kind {
		case denialProofSOA:
			snapshot.soa = entry
		case denialProofNSEC:
			snapshot.nsec = append(snapshot.nsec, entry)
		case denialProofNSEC3:
			snapshot.nsec3[entry.params] = append(
				snapshot.nsec3[entry.params],
				entry,
			)
			if entry.sequence > groupSequence[entry.params] {
				groupSequence[entry.params] = entry.sequence
			}
		}
	}
	sort.Slice(snapshot.nsec, func(i, j int) bool {
		compared := snapshot.nsec[i].ownerOrder.compare(snapshot.nsec[j].ownerOrder)
		if compared != 0 {
			return compared < 0
		}
		return snapshot.nsec[i].sequence < snapshot.nsec[j].sequence
	})
	// The flat prepared form is what the reader actually evaluates, and it
	// only changes when the zone's NSEC set does. Building it here means a
	// lookup that finds nothing expired evaluates the published slice as it
	// stands, instead of concatenating it again on every query.
	for _, entry := range snapshot.nsec {
		snapshot.nsecPrepared = append(
			snapshot.nsecPrepared,
			entry.preparedNSEC...,
		)
	}
	snapshot.nsec3Order = make(
		[]denialProofNSEC3Params,
		0,
		len(snapshot.nsec3),
	)
	for params, group := range snapshot.nsec3 {
		sort.Slice(group, func(i, j int) bool {
			if group[i].ownerHash != group[j].ownerHash {
				return group[i].ownerHash < group[j].ownerHash
			}
			return group[i].sequence < group[j].sequence
		})
		snapshot.nsec3Order = append(snapshot.nsec3Order, params)
	}
	sort.Slice(snapshot.nsec3Order, func(i, j int) bool {
		left, right := snapshot.nsec3Order[i], snapshot.nsec3Order[j]
		if groupSequence[left] != groupSequence[right] {
			return groupSequence[left] > groupSequence[right]
		}
		if left.hash != right.hash {
			return left.hash < right.hash
		}
		if left.iterations != right.iterations {
			return left.iterations < right.iterations
		}
		return left.salt < right.salt
	})
	c.zoneIndex[key] = snapshot
}

// denialProofNameOrder is a name's canonical comparison form, derived exactly
// once per admitted RRset. Snapshot republication sorts on every admission and
// eviction; deriving wire labels inside the comparator instead made that sort
// the process's dominant allocation site (84% of all allocated bytes on a
// DNSBL-heavy resolver).
type denialProofNameOrder struct {
	// labels are the lowercased wire labels; nil when the name cannot be
	// packed, in which case fallback carries the comparison identity.
	labels   [][]byte
	fallback string
}

// denialProofNameOrderFor expects name in dns.CanonicalName form, which every
// admission-path owner already is.
func denialProofNameOrderFor(name string) denialProofNameOrder {
	labels, ok := denialProofCanonicalWireLabels(name)
	if !ok {
		return denialProofNameOrder{fallback: name}
	}
	return denialProofNameOrder{labels: labels, fallback: name}
}

// compare is the RFC 4034 §6.1 canonical name ordering. The unpackable-name
// fallback compares the canonical presentation forms, preserving the previous
// comparator's behaviour.
func (a denialProofNameOrder) compare(b denialProofNameOrder) int {
	if a.labels == nil || b.labels == nil {
		return strings.Compare(a.fallback, b.fallback)
	}
	i, j := len(a.labels)-1, len(b.labels)-1
	for i >= 0 && j >= 0 {
		if compared := bytes.Compare(a.labels[i], b.labels[j]); compared != 0 {
			return compared
		}
		i--
		j--
	}
	switch {
	case len(a.labels) < len(b.labels):
		return -1
	case len(a.labels) > len(b.labels):
		return 1
	default:
		return 0
	}
}

func denialProofCanonicalWireLabels(name string) ([][]byte, bool) {
	wire := make([]byte, 255)
	end, err := dns.PackDomainName(dns.Fqdn(name), wire, 0, nil, false)
	if err != nil || end == 0 || end > len(wire) {
		return nil, false
	}
	wire = wire[:end]

	labels := make([][]byte, 0, 8)
	for offset := 0; ; {
		if offset >= len(wire) {
			return nil, false
		}
		length := int(wire[offset])
		offset++
		if length == 0 {
			return labels, offset == len(wire)
		}
		if length > 63 || offset+length > len(wire) {
			return nil, false
		}
		label := wire[offset : offset+length]
		for i, octet := range label {
			if octet >= 'A' && octet <= 'Z' {
				label[i] = octet + ('a' - 'A')
			}
		}
		labels = append(labels, label)
		offset += length
	}
}

func (c *denialProofCache) removeEntryLocked(entry *denialProofEntry) {
	if entry == nil || c.byID[entry.id] != entry {
		return
	}
	delete(c.byID, entry.id)
	if entry.queue != nil {
		c.fifo.Remove(entry.queue)
	}
	c.totalBytes -= entry.wireBytes
	if c.totalBytes < 0 {
		c.totalBytes = 0
	}

	delete(c.zoneEntries[entry.zoneKey], entry.id)
	c.publishZoneLocked(entry.zoneKey)
}

func (c *denialProofCache) enforceNSEC3GroupLimitLocked(
	key denialProofZoneKey,
) {
	for {
		snapshot := c.zoneIndex[key]
		if snapshot == nil ||
			len(snapshot.nsec3Order) <= maxDenialProofNSEC3Groups {
			return
		}
		oldest := snapshot.nsec3Order[len(snapshot.nsec3Order)-1]
		group := append([]*denialProofEntry(nil), snapshot.nsec3[oldest]...)
		for _, entry := range group {
			c.removeEntryLocked(entry)
		}
	}
}

func (c *denialProofCache) enforceZoneLimitsLocked(key denialProofZoneKey) {
	for {
		snapshot := c.zoneIndex[key]
		if snapshot == nil ||
			(len(c.zoneEntries[key]) <= c.maxEntriesPerZone &&
				snapshot.wireBytes <= c.maxBytesPerZone) {
			return
		}

		var oldest *denialProofEntry
		for element := c.fifo.Front(); element != nil; element = element.Next() {
			entry, _ := element.Value.(*denialProofEntry)
			if entry != nil && entry.zoneKey == key {
				oldest = entry
				break
			}
		}
		if oldest == nil {
			return
		}
		c.removeEntryLocked(oldest)
	}
}

func (c *denialProofCache) enforceGlobalLimitsLocked() {
	for len(c.byID) > c.maxEntries || c.totalBytes > c.maxBytes {
		element := c.fifo.Front()
		if element == nil {
			return
		}
		entry, _ := element.Value.(*denialProofEntry)
		if entry == nil {
			c.fifo.Remove(element)
			continue
		}
		c.removeEntryLocked(entry)
	}
}

type denialProofCandidate struct {
	zone     denialProofZoneKey
	snapshot *denialProofZoneSnapshot
}

// Lookup synthesizes a negative response only when the DNSSEC evaluator can
// prove the exact question from one immutable, unexpired zone snapshot.
// Every error is a cache miss: aggressive caching is never authoritative over
// ordinary resolution.
func (c *denialProofCache) Lookup(
	req *dns.Msg,
	work dnssec.NSEC3Work,
) (*dns.Msg, bool) {
	response, _, _, ok := c.lookupWithMeta(req, work)
	return response, ok
}

// lookupWithMeta retains the selected denial mechanism and signer zone after
// response shaping. This is required for DO=0 hits, where the wire response
// correctly strips NSEC/NSEC3 records and therefore cannot be inspected to
// recover safe resolver-local provenance.
func (c *denialProofCache) lookupWithMeta(
	req *dns.Msg,
	work dnssec.NSEC3Work,
) (*dns.Msg, denialProofKind, string, bool) {
	if c == nil || req == nil || len(req.Question) != 1 ||
		req.CheckingDisabled {
		return nil, 0, "", false
	}
	q := req.Question[0]
	qname := dns.CanonicalName(q.Name)
	if _, valid := dns.IsDomainName(qname); !valid ||
		q.Qclass == 0 || q.Qclass == dns.ClassANY || q.Qclass == dns.ClassNONE {
		return nil, 0, "", false
	}

	c.mu.RLock()
	if c.stopped {
		c.mu.RUnlock()
		return nil, 0, "", false
	}
	candidates := make([]denialProofCandidate, 0, len(dns.Split(qname))+1)
	for _, zone := range denialProofAncestors(qname) {
		key := denialProofZoneKey{zone: zone, qclass: q.Qclass}
		if snapshot := c.zoneIndex[key]; snapshot != nil {
			candidates = append(candidates, denialProofCandidate{
				zone:     key,
				snapshot: snapshot,
			})
		}
	}
	c.mu.RUnlock()

	now := c.now()
	for _, candidate := range candidates {
		result, entries, ok := denialProofEvaluate(
			q,
			candidate.zone,
			candidate.snapshot,
			now,
			work,
		)
		if !ok {
			continue
		}

		// Re-check conflict quarantine after evaluation. A writer may have
		// detected an owner collision after this lookup captured its immutable
		// snapshot; holding RLock through response shaping linearizes either
		// the synthesis or the conflict invalidation, never both.
		c.mu.RLock()
		if c.stopped ||
			c.nsec3SelectionConflictedLocked(entries, now) {
			c.mu.RUnlock()
			continue
		}
		response := denialProofResponse(req, result, entries, candidate.snapshot.soa, now)
		if response == nil || len(entries) == 0 {
			c.mu.RUnlock()
			continue
		}
		kind := entries[0].id.kind
		if kind != denialProofNSEC && kind != denialProofNSEC3 {
			c.mu.RUnlock()
			continue
		}
		homogeneous := true
		for _, entry := range entries[1:] {
			if entry.id.kind != kind {
				homogeneous = false
				break
			}
		}
		if homogeneous {
			c.mu.RUnlock()
			return response, kind, candidate.zone.zone, true
		}
		c.mu.RUnlock()
	}
	return nil, 0, "", false
}

func (c *denialProofCache) nsec3SelectionConflictedLocked(
	entries []*denialProofEntry,
	now time.Time,
) bool {
	for _, entry := range entries {
		if entry == nil || entry.id.kind != denialProofNSEC3 {
			continue
		}
		if c.nsec3ConflictActiveLocked(
			denialProofNSEC3ConflictKey{
				zone:   entry.zoneKey,
				params: entry.params,
			},
			now,
		) {
			return true
		}
	}
	return false
}

func denialProofAncestors(name string) []string {
	if name == "." {
		return []string{"."}
	}
	offsets := dns.Split(name)
	result := make([]string, 0, len(offsets)+1)
	for _, offset := range offsets {
		result = append(result, name[offset:])
	}
	result = append(result, ".")
	return result
}

func denialProofEvaluate(
	q dns.Question,
	zone denialProofZoneKey,
	snapshot *denialProofZoneSnapshot,
	now time.Time,
	work dnssec.NSEC3Work,
) (dnssec.AggressiveNegativeResult, []*denialProofEntry, bool) {
	if snapshot == nil || snapshot.soa == nil ||
		!now.Before(snapshot.soa.expires) {
		return dnssec.AggressiveNegativeResult{}, nil, false
	}

	nsecEntries, nsecPrepared := denialProofLivePreparedNSEC(
		snapshot.nsec,
		snapshot.nsecPrepared,
		now,
	)
	if len(nsecPrepared) != 0 {
		result, err := dnssec.EvaluateAggressiveNSECPrepared(q, zone.zone, nsecPrepared)
		if err == nil {
			entries, selected := denialProofSelectedEntries(result.Proof, nsecEntries)
			if selected {
				return result, entries, true
			}
		}
	}

	for _, params := range snapshot.nsec3Order {
		group := snapshot.nsec3[params]
		entries, records := denialProofLiveRecords(group, now)
		if len(records) == 0 {
			continue
		}
		result, err := dnssec.EvaluateAggressiveNSEC3(q, zone.zone, records, work)
		if err != nil {
			if dnssec.IsWorkError(err) {
				return dnssec.AggressiveNegativeResult{}, nil, false
			}
			continue
		}
		selectedEntries, selected := denialProofSelectedEntries(result.Proof, entries)
		if selected {
			return result, selectedEntries, true
		}
	}
	return dnssec.AggressiveNegativeResult{}, nil, false
}

// denialProofLivePreparedNSEC collects a zone's unexpired NSEC entries along
// with their canonicalized records. Admission refuses an NSEC entry whose
// names it cannot canonicalize, so every live entry here carries a prepared
// form covering exactly its own records.
//
// The common case is that nothing in the zone has expired since it was
// published, and then both results are the published slices themselves. Only
// an actual expiry pays for a filtered copy.
func denialProofLivePreparedNSEC(
	entries []*denialProofEntry,
	published []dnssec.PreparedNSEC,
	now time.Time,
) ([]*denialProofEntry, []dnssec.PreparedNSEC) {
	expired := false
	for _, entry := range entries {
		if entry == nil || !now.Before(entry.expires) {
			expired = true
			break
		}
	}
	if !expired {
		return entries, published
	}

	live := make([]*denialProofEntry, 0, len(entries))
	prepared := make([]dnssec.PreparedNSEC, 0, len(published))
	for _, entry := range entries {
		if entry == nil || !now.Before(entry.expires) {
			continue
		}
		live = append(live, entry)
		prepared = append(prepared, entry.preparedNSEC...)
	}
	return live, prepared
}

func denialProofLiveRecords(
	entries []*denialProofEntry,
	now time.Time,
) ([]*denialProofEntry, []dns.RR) {
	live := make([]*denialProofEntry, 0, len(entries))
	records := make([]dns.RR, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || !now.Before(entry.expires) {
			continue
		}
		live = append(live, entry)
		records = append(records, entry.data...)
	}
	return live, records
}

func denialProofSelectedEntries(
	proof []dns.RR,
	entries []*denialProofEntry,
) ([]*denialProofEntry, bool) {
	if len(proof) == 0 {
		return nil, false
	}
	owners := make(map[dns.RR]*denialProofEntry)
	for _, entry := range entries {
		for _, rr := range entry.data {
			owners[rr] = entry
		}
	}

	selected := make([]*denialProofEntry, 0, len(proof))
	seen := make(map[denialProofID]struct{}, len(proof))
	for _, rr := range proof {
		entry := owners[rr]
		if entry == nil {
			return nil, false
		}
		if _, duplicate := seen[entry.id]; duplicate {
			continue
		}
		seen[entry.id] = struct{}{}
		selected = append(selected, entry)
	}
	return selected, len(selected) != 0
}

func denialProofResponse(
	req *dns.Msg,
	result dnssec.AggressiveNegativeResult,
	proofEntries []*denialProofEntry,
	soa *denialProofEntry,
	now time.Time,
) *dns.Msg {
	if req == nil || soa == nil || !now.Before(soa.expires) ||
		(result.Rcode != dns.RcodeNameError && result.Rcode != dns.RcodeSuccess) ||
		len(proofEntries) == 0 {
		return nil
	}

	expires := soa.expires
	for _, entry := range proofEntries {
		if entry == nil || !now.Before(entry.expires) {
			return nil
		}
		if entry.expires.Before(expires) {
			expires = entry.expires
		}
	}
	remaining := expires.Sub(now)
	if remaining <= 0 {
		return nil
	}

	response := new(dns.Msg)
	response.SetReply(req)
	response.Rcode = result.Rcode
	response.Authoritative = false
	response.RecursionAvailable = true
	response.AuthenticatedData = true
	response.CheckingDisabled = false
	response.Truncated = false
	response.Answer = nil
	response.Extra = nil

	response.Ns = make([]dns.RR, 0, len(soa.records)+len(result.Proof)*2)
	for _, rr := range soa.records {
		response.Ns = append(response.Ns, dns.Copy(rr))
	}
	for _, entry := range proofEntries {
		for _, rr := range entry.records {
			response.Ns = append(response.Ns, dns.Copy(rr))
		}
	}

	ttl := uint32(remaining / time.Second) //nolint:gosec // lifetime is positive and capped at three hours
	for _, rr := range response.Ns {
		rr.Header().Ttl = ttl
	}
	if opt := req.IsEdns0(); opt == nil || !opt.Do() {
		kept := response.Ns[:0]
		for _, rr := range response.Ns {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				continue
			default:
				kept = append(kept, rr)
			}
		}
		response.Ns = kept
	}
	return response
}

// purge removes denial RRsets from every cached signer-zone shard that is an
// ancestor of q. It deliberately does not hash NSEC3 names: an administrative
// purge must not bypass the optional lookup's hash budget and shared
// non-blocking crypto gate. The retained SOA cannot synthesize on its own and
// may be reused by a later locally validated admission.
func (c *denialProofCache) purge(q dns.Question) {
	if c == nil {
		return
	}
	q.Name = dns.CanonicalName(q.Name)
	if _, valid := dns.IsDomainName(q.Name); !valid ||
		q.Qclass == 0 || q.Qclass == dns.ClassANY || q.Qclass == dns.ClassNONE {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	// Administrative purge is an explicit recovery boundary. The overflow
	// backstop cannot identify its originating tuple, so clear it globally;
	// keyed tombstones below are removed only for the requested ancestors.
	c.nsec3ConflictOverflowUntil = time.Time{}
	for _, zone := range denialProofAncestors(q.Name) {
		key := denialProofZoneKey{zone: zone, qclass: q.Qclass}
		for conflict := range c.nsec3Conflicts {
			if conflict.zone == key {
				delete(c.nsec3Conflicts, conflict)
			}
		}
		snapshot := c.zoneIndex[key]
		if snapshot == nil {
			continue
		}
		zoneEntries := c.zoneEntries[key]
		entries := make([]*denialProofEntry, 0, len(zoneEntries))
		for _, entry := range zoneEntries {
			if entry.id.kind != denialProofSOA {
				entries = append(entries, entry)
			}
		}
		for _, entry := range entries {
			c.removeEntryLocked(entry)
		}
	}
}

func (c *denialProofCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	length := len(c.byID)
	c.mu.RUnlock()
	return length
}

func (c *denialProofCache) zones() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	length := len(c.zoneIndex)
	c.mu.RUnlock()
	return length
}

func (c *denialProofCache) bytes() int64 {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	bytes := c.totalBytes
	c.mu.RUnlock()
	return bytes
}

func (c *denialProofCache) stop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.stopped = true
	c.zoneIndex = make(map[denialProofZoneKey]*denialProofZoneSnapshot)
	c.zoneEntries = make(map[denialProofZoneKey]map[denialProofID]*denialProofEntry)
	c.byID = make(map[denialProofID]*denialProofEntry)
	c.nsec3Conflicts = make(map[denialProofNSEC3ConflictKey]time.Time)
	c.nsec3ConflictOverflowUntil = time.Time{}
	c.fifo.Init()
	c.totalBytes = 0
	c.mu.Unlock()
}
