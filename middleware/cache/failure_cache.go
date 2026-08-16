package cache

import (
	"errors"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	internalcache "github.com/semihalev/sdns/internal/cache"
)

const (
	// DefaultFailureCacheSize bounds retained exact and zone failure states.
	DefaultFailureCacheSize = 4096
	// DefaultFailureInitialTTL is the first cached-failure backoff interval.
	DefaultFailureInitialTTL = 5 * time.Second
	// DefaultFailureMaxTTL caps cached-failure backoff.
	DefaultFailureMaxTTL = 5 * time.Minute

	failureQuestionHashSalt = uint64(0x53a9_27c4_d881_6e0b)
	failureZoneHashSalt     = uint64(0xb9e3_14f7_2ca5_80d6)
	failureCacheEDEText     = "Cached recursion failure"
)

var (
	errFailureCacheSize       = errors.New("failure cache size must be positive")
	errFailureCacheInitialTTL = errors.New("failure cache initial TTL must be at least one second")
	errFailureCacheMaxTTL     = errors.New("failure cache max TTL must be at least the initial TTL")
	errFailureCacheTTLCeiling = errors.New("failure cache max TTL must not exceed five minutes")
)

// FailureProvenance identifies the failure class that admitted an entry.
// Admission policy belongs to the caller; the cache only retains the value for
// observability and for consumers that need to distinguish failure sources.
type FailureProvenance string

// FailureKind identifies whether a hit is question-specific or zone-wide.
type FailureKind uint8

const (
	// FailureKindQuestion is an exact QNAME/QTYPE/QCLASS+CD+ECS failure.
	FailureKindQuestion FailureKind = iota + 1
	// FailureKindZone is an authority-zone reachability failure.
	FailureKindZone
)

// FailureQuestionKey isolates failures by the complete DNS question, CD bit,
// and ECS audience. Invalid and /0 scopes are the shared global audience.
type FailureQuestionKey struct {
	Question dns.Question
	CD       bool
	Scope    netip.Prefix
}

// FailureZoneKey identifies a zone-wide reachability failure. Transport
// reachability is independent of the client's CD bit and ECS audience.
type FailureZoneKey struct {
	Zone   string
	Qclass uint16
}

// FailureCacheConfig configures the bounded failure cache. Zero TTL values use
// DefaultFailureInitialTTL and DefaultFailureMaxTTL. Now is injectable for
// deterministic tests; nil uses time.Now.
type FailureCacheConfig struct {
	Size       int
	InitialTTL time.Duration
	MaxTTL     time.Duration
	Now        func() time.Time
}

// FailureHit is an immutable snapshot of an active cached failure.
type FailureHit struct {
	Kind       FailureKind
	Provenance FailureProvenance
	Streak     uint32
	RetryAfter time.Time
	Question   FailureQuestionKey
	Zone       FailureZoneKey
}

// Response builds a clean SERVFAIL response for a cached failure. EDE 13 is
// emitted only when the client sent EDNS, and no client EDNS options are copied.
func (h FailureHit) Response(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	if req != nil {
		resp.SetReply(req)
	} else {
		resp.Response = true
	}
	resp.Rcode = dns.RcodeServerFailure
	resp.RecursionAvailable = true
	resp.AuthenticatedData = false
	resp.Authoritative = false
	resp.Truncated = false
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil

	if req == nil {
		return resp
	}
	reqOPT := req.IsEdns0()
	if reqOPT == nil {
		return resp
	}

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(reqOPT.UDPSize())
	opt.SetDo(reqOPT.Do())
	opt.Option = []dns.EDNS0{&dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeCachedError,
		ExtraText: failureCacheEDEText,
	}}
	resp.Extra = []dns.RR{opt}
	return resp
}

type failureEntry struct {
	kind       FailureKind
	provenance FailureProvenance
	streak     uint32
	retryAfter time.Time
	question   FailureQuestionKey
	zone       FailureZoneKey
}

func (e *failureEntry) hit() FailureHit {
	return FailureHit{
		Kind:       e.kind,
		Provenance: e.provenance,
		Streak:     e.streak,
		RetryAfter: e.retryAfter,
		Question:   e.question,
		Zone:       e.zone,
	}
}

// FailureCache is a bounded, concurrent cache of recursive-resolution
// failures. Expired entries remain as backoff history but are not cache hits.
type FailureCache struct {
	entries    *internalcache.Cache
	initialTTL time.Duration
	maxTTL     time.Duration
	now        func() time.Time
}

// NewFailureCache constructs a bounded failure cache.
func NewFailureCache(cfg FailureCacheConfig) (*FailureCache, error) {
	if cfg.Size <= 0 {
		return nil, errFailureCacheSize
	}
	if cfg.InitialTTL == 0 {
		cfg.InitialTTL = DefaultFailureInitialTTL
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = DefaultFailureMaxTTL
	}
	if cfg.InitialTTL < time.Second {
		return nil, errFailureCacheInitialTTL
	}
	if cfg.MaxTTL < cfg.InitialTTL {
		return nil, errFailureCacheMaxTTL
	}
	if cfg.MaxTTL > DefaultFailureMaxTTL {
		return nil, errFailureCacheTTLCeiling
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &FailureCache{
		entries:    internalcache.New(cfg.Size),
		initialTTL: cfg.InitialTTL,
		maxTTL:     cfg.MaxTTL,
		now:        cfg.Now,
	}, nil
}

// Lookup returns an active exact failure, or otherwise the closest active
// ancestor-zone failure. Expired state is retained for Record and RetryKey but
// never returned as a hit.
func (c *FailureCache) Lookup(key FailureQuestionKey) (FailureHit, bool) {
	if c.entries.Len() == 0 {
		return FailureHit{}, false
	}

	key = normalizeFailureQuestionKey(key)
	now := c.now()

	if entry, ok := c.loadQuestion(key); ok && now.Before(entry.retryAfter) {
		return entry.hit(), true
	}

	var hit FailureHit
	found := false
	walkFailureZones(key.Question.Name, func(zone string) bool {
		entry, ok := c.loadZone(FailureZoneKey{Zone: zone, Qclass: key.Question.Qclass})
		if !ok || !now.Before(entry.retryAfter) {
			return true
		}
		hit = entry.hit()
		found = true
		return false
	})
	return hit, found
}

// LookupWire is Lookup for a wire-born question without an ECS scope: the
// same exact-question probe and ancestor-zone walk, keyed through the
// canonical wire hashes (bit-identical to the presentation ones) and
// verified by fold comparison — no strings, no allocation. Scoped entries
// never match: the wire path carries no client scope, and scope is part
// of both the hash and the verification.
func (c *FailureCache) LookupWire(name []byte, qtype, qclass uint16, cd bool) (FailureHit, bool) {
	if c == nil || c.entries.Len() == 0 {
		return FailureHit{}, false
	}
	now := c.now()

	if hash, ok := internalcache.KeyWire(name, qtype, qclass, cd); ok {
		if entry, ok := c.loadEntry(hash ^ failureQuestionHashSalt); ok &&
			entry.kind == FailureKindQuestion &&
			!entry.question.Scope.IsValid() &&
			entry.question.Question.Qtype == qtype &&
			entry.question.Question.Qclass == qclass &&
			entry.question.CD == cd &&
			internalcache.WireNameEqualsPresentation(name, entry.question.Question.Name) &&
			now.Before(entry.retryAfter) {
			return entry.hit(), true
		}
	}

	var hit FailureHit
	found := false
	walkWireSuffixes(name, func(zone []byte) bool {
		hash, ok := internalcache.KeyWire(zone, dns.TypeSOA, qclass, false)
		if !ok {
			return true
		}
		entry, ok := c.loadEntry(hash ^ failureZoneHashSalt)
		if !ok || entry.kind != FailureKindZone ||
			entry.zone.Qclass != qclass ||
			!internalcache.WireNameEqualsPresentation(zone, entry.zone.Zone) ||
			!now.Before(entry.retryAfter) {
			return true
		}
		hit = entry.hit()
		found = true
		return false
	})
	return hit, found
}

// walkWireSuffixes calls visit for every suffix of the uncompressed wire
// name, from the full name down to the root, mirroring walkFailureZones.
func walkWireSuffixes(name []byte, visit func(zone []byte) bool) {
	off := 0
	for {
		if off >= len(name) || !visit(name[off:]) {
			return
		}
		c := int(name[off])
		if c == 0 || c > 63 || off+1+c > len(name) {
			return
		}
		off += 1 + c
	}
}

// RetryKey returns a stable singleflight key for a matching expired failure
// generation. An active exact or ancestor-zone state returns false because it
// should be consumed through Lookup instead. Closest-zone history takes
// precedence over exact history so different random QNAMEs below a failed
// authority converge on one probe generation.
func (c *FailureCache) RetryKey(key FailureQuestionKey) (uint64, bool) {
	if c.entries.Len() == 0 {
		return 0, false
	}

	key = normalizeFailureQuestionKey(key)
	now := c.now()

	var (
		exactExpired    uint64
		hasExactExpired bool
	)
	if entry, hash, ok := c.loadQuestionWithHash(key); ok {
		if now.Before(entry.retryAfter) {
			return 0, false
		}
		exactExpired = hash
		hasExactExpired = true
	}

	var (
		closestZoneExpired    uint64
		hasClosestZoneExpired bool
		activeZone            bool
	)
	walkFailureZones(key.Question.Name, func(zone string) bool {
		zoneKey := FailureZoneKey{Zone: zone, Qclass: key.Question.Qclass}
		entry, hash, ok := c.loadZoneWithHash(zoneKey)
		if !ok {
			return true
		}
		if now.Before(entry.retryAfter) {
			activeZone = true
			return false
		}
		if !hasClosestZoneExpired {
			closestZoneExpired = hash
			hasClosestZoneExpired = true
		}
		return true
	})
	if activeZone {
		return 0, false
	}
	if hasClosestZoneExpired {
		return closestZoneExpired, true
	}
	if hasExactExpired {
		return exactExpired, true
	}
	return 0, false
}

// RecordQuestion records an exact failure. Repeated calls during an active
// generation are idempotent. After expiry, concurrent recorders advance the
// streak exactly once.
func (c *FailureCache) RecordQuestion(key FailureQuestionKey, provenance FailureProvenance) FailureHit {
	key = normalizeFailureQuestionKey(key)
	hash := failureQuestionHash(key)
	return c.record(hash, &failureEntry{
		kind:       FailureKindQuestion,
		provenance: provenance,
		question:   key,
	})
}

// RecordZone records a zone-wide reachability failure. Repeated calls during
// an active generation are idempotent. Zone failures are not partitioned by CD
// or ECS because authority transport reachability is shared.
func (c *FailureCache) RecordZone(key FailureZoneKey, provenance FailureProvenance) FailureHit {
	key = normalizeFailureZoneKey(key)
	hash := failureZoneHash(key)
	return c.record(hash, &failureEntry{
		kind:       FailureKindZone,
		provenance: provenance,
		zone:       key,
	})
}

// ResetQuestion deletes exact history when the full key still matches.
func (c *FailureCache) ResetQuestion(key FailureQuestionKey) bool {
	key = normalizeFailureQuestionKey(key)
	hash := failureQuestionHash(key)
	for {
		entry, ok := c.loadEntry(hash)
		if !ok || entry.kind != FailureKindQuestion || !failureQuestionKeysEqual(entry.question, key) {
			return false
		}
		if c.entries.CompareAndDelete(hash, entry) {
			return true
		}
	}
}

// ResetZone deletes zone history when the full key still matches.
func (c *FailureCache) ResetZone(key FailureZoneKey) bool {
	key = normalizeFailureZoneKey(key)
	hash := failureZoneHash(key)
	for {
		entry, ok := c.loadEntry(hash)
		if !ok || entry.kind != FailureKindZone || !failureZoneKeysEqual(entry.zone, key) {
			return false
		}
		if c.entries.CompareAndDelete(hash, entry) {
			return true
		}
	}
}

// ResetMatching removes exact history and every ancestor-zone history covered
// by a fresh useful response. Recovery deliberately deletes the streak: RFC
// 9520 backoff applies to persistent failures, so a later independent failure
// starts a new episode at the initial interval. Retaining an expired streak
// here would also keep healthy descendants in the retry-generation path.
// It returns the number of states deleted.
func (c *FailureCache) ResetMatching(key FailureQuestionKey) int {
	if c.entries.Len() == 0 {
		return 0
	}
	key = normalizeFailureQuestionKey(key)
	removed := 0
	if c.ResetQuestion(key) {
		removed++
	}
	walkFailureZones(key.Question.Name, func(zone string) bool {
		if c.ResetZone(FailureZoneKey{Zone: zone, Qclass: key.Question.Qclass}) {
			removed++
		}
		return true
	})
	return removed
}

// PurgeQuestion removes every CD/ECS variant of an exact question and a
// zone-wide state whose owner is the purged name. Purge is an explicit,
// infrequent operator action, so a bounded O(n) scan avoids maintaining a
// second attacker-influenced index.
func (c *FailureCache) PurgeQuestion(q dns.Question) int {
	q.Name = dns.CanonicalName(q.Name)
	type located struct {
		hash  uint64
		entry *failureEntry
	}
	var matches []located
	c.entries.ForEach(func(hash uint64, value any) bool {
		entry, ok := value.(*failureEntry)
		if !ok || entry == nil {
			return true
		}
		switch entry.kind {
		case FailureKindQuestion:
			eq := entry.question.Question
			if eq.Name == q.Name && eq.Qtype == q.Qtype && eq.Qclass == q.Qclass {
				matches = append(matches, located{hash: hash, entry: entry})
			}
		case FailureKindZone:
			if entry.zone.Zone == q.Name && entry.zone.Qclass == q.Qclass {
				matches = append(matches, located{hash: hash, entry: entry})
			}
		}
		return true
	})

	removed := 0
	for _, match := range matches {
		if c.entries.CompareAndDelete(match.hash, match.entry) {
			removed++
		}
	}
	return removed
}

// Len returns the number of retained active and expired states.
func (c *FailureCache) Len() int {
	return c.entries.Len()
}

// Stop releases resources owned by the backing cache.
func (c *FailureCache) Stop() {
	c.entries.Stop()
}

func (c *FailureCache) record(hash uint64, candidate *failureEntry) FailureHit {
	now := c.now()
	for {
		current, ok := c.loadEntry(hash)
		if !ok || !failureEntriesSameKey(current, candidate) {
			first := *candidate
			first.streak = 1
			first.retryAfter = now.Add(c.initialTTL)
			c.entries.Add(hash, &first)
			return first.hit()
		}
		if now.Before(current.retryAfter) {
			return current.hit()
		}

		next := *current
		if now.Sub(current.retryAfter) >= c.maxTTL {
			next.streak = 1
		} else if next.streak < ^uint32(0) {
			next.streak++
		}
		next.provenance = candidate.provenance
		next.retryAfter = now.Add(c.backoff(next.streak))
		if c.entries.CompareAndSwap(hash, current, &next) {
			return next.hit()
		}
	}
}

func (c *FailureCache) backoff(streak uint32) time.Duration {
	ttl := c.initialTTL
	for generation := uint32(1); generation < streak && ttl < c.maxTTL; generation++ {
		if ttl > c.maxTTL/2 {
			return c.maxTTL
		}
		ttl *= 2
	}
	if ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

func (c *FailureCache) loadQuestion(key FailureQuestionKey) (*failureEntry, bool) {
	entry, _, ok := c.loadQuestionWithHash(key)
	return entry, ok
}

func (c *FailureCache) loadQuestionWithHash(key FailureQuestionKey) (*failureEntry, uint64, bool) {
	hash := failureQuestionHash(key)
	entry, ok := c.loadEntry(hash)
	if !ok || entry.kind != FailureKindQuestion || !failureQuestionKeysEqual(entry.question, key) {
		return nil, 0, false
	}
	return entry, hash, true
}

func (c *FailureCache) loadZone(key FailureZoneKey) (*failureEntry, bool) {
	entry, _, ok := c.loadZoneWithHash(key)
	return entry, ok
}

func (c *FailureCache) loadZoneWithHash(key FailureZoneKey) (*failureEntry, uint64, bool) {
	key = normalizeFailureZoneKey(key)
	hash := failureZoneHash(key)
	entry, ok := c.loadEntry(hash)
	if !ok || entry.kind != FailureKindZone || !failureZoneKeysEqual(entry.zone, key) {
		return nil, 0, false
	}
	return entry, hash, true
}

func (c *FailureCache) loadEntry(hash uint64) (*failureEntry, bool) {
	value, ok := c.entries.Get(hash)
	if !ok {
		return nil, false
	}
	entry, ok := value.(*failureEntry)
	return entry, ok
}

func normalizeFailureQuestionKey(key FailureQuestionKey) FailureQuestionKey {
	key.Question.Name = dns.CanonicalName(key.Question.Name)
	key.Scope = normalizeKeyScope(key.Scope)
	return key
}

func normalizeFailureZoneKey(key FailureZoneKey) FailureZoneKey {
	key.Zone = dns.CanonicalName(key.Zone)
	return key
}

func failureQuestionHash(key FailureQuestionKey) uint64 {
	if key.Scope.IsValid() {
		return internalcache.KeyWithPrefix(key.Question, key.CD, key.Scope) ^ failureQuestionHashSalt
	}
	return internalcache.Key(key.Question, key.CD) ^ failureQuestionHashSalt
}

func failureZoneHash(key FailureZoneKey) uint64 {
	q := dns.Question{Name: key.Zone, Qtype: dns.TypeSOA, Qclass: key.Qclass}
	return internalcache.Key(q, false) ^ failureZoneHashSalt
}

func failureEntriesSameKey(a, b *failureEntry) bool {
	if a == nil || b == nil || a.kind != b.kind {
		return false
	}
	switch a.kind {
	case FailureKindQuestion:
		return failureQuestionKeysEqual(a.question, b.question)
	case FailureKindZone:
		return failureZoneKeysEqual(a.zone, b.zone)
	default:
		return false
	}
}

func failureQuestionKeysEqual(a, b FailureQuestionKey) bool {
	return a.Question.Name == b.Question.Name &&
		a.Question.Qtype == b.Question.Qtype &&
		a.Question.Qclass == b.Question.Qclass &&
		a.CD == b.CD &&
		a.Scope == b.Scope
}

func failureZoneKeysEqual(a, b FailureZoneKey) bool {
	return a.Zone == b.Zone && a.Qclass == b.Qclass
}

func walkFailureZones(name string, visit func(zone string) bool) {
	zone := dns.CanonicalName(name)
	for {
		if !visit(zone) || zone == "." {
			return
		}
		next, end := dns.NextLabel(zone, 0)
		if end {
			zone = "."
			continue
		}
		zone = zone[next:]
	}
}
