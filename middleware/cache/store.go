package cache

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

// Store is the cache backing for the cache middleware. The answer and failure
// sub-caches are constructed by Cache.New and shared with Store; Store owns
// the separately bounded RFC 8020 cut index. It centralises classification,
// keying, and TTL handling so callers outside ServeDNS (resolver sub-queries,
// queryer-driven prefetch, future API purge wiring) don't need to understand
// the wire-write rules in ResponseWriter.WriteMsg.
//
// SetFromResponse keys on the caller-supplied keyCD rather than on
// resp.CheckingDisabled to make the keying contract explicit at every
// call site — Forwarder and Resolver both temporarily mutate CD on
// the upstream request, and silent reliance on resp.CheckingDisabled
// is the kind of thing that splits CD=1 and CD=0 lookups across
// stale entries when a future change forgets to restore.
type Store struct {
	positive     *PositiveCache
	negative     *NegativeCache
	failure      *FailureCache
	nxDomainCuts *nxDomainCutCache
	denialProofs *denialProofCache
	// Wired once at startup through the owning Cache. Resolver-private
	// Store.Get calls then share the same non-blocking NSEC3 gate as client
	// lookups; standalone Store users safely miss NSEC3 when it is nil.
	dnssecCryptoLimiter middleware.DNSSECCryptoLimiter
	// sharedDenialDisabled is set only by the owning Cache when local DNSSEC
	// validation cannot establish provenance (DNSSEC off or forwarding).
	// The zero value intentionally permits standalone Store tests/users.
	sharedDenialDisabled bool
	// rfc8198Disabled is the operator kill switch for aggressive NSEC/NSEC3
	// admission and synthesis. Keep it separate from sharedDenialDisabled:
	// RFC 8020 subtree cuts remain available when only RFC 8198 is disabled.
	rfc8198Disabled bool
	// failureCacheDisabled is the RFC 9520 operational rollback switch.
	// The bounded cache remains allocated so the surrounding Cache and Store
	// keep one stable shape, but no shared failure state is read or written.
	failureCacheDisabled bool
	cfg                  CacheConfig

	// sidecarEvaluator, when wired, is called once per admitted entry with
	// that entry's own stored message; its result is stamped as the
	// entry's sidecar before publication. Every admission door funnels
	// through a stamp — the seam's contract is that no entry reaches the
	// positive cache unevaluated while an evaluator is wired. Written once
	// at Setup, before the pipeline publishes; nil costs one field check.
	sidecarEvaluator middleware.SidecarEvaluator
}

// SetSidecarEvaluator wires the admission half of the sidecar seam. Call
// before the store serves traffic; the field is not synchronized.
func (s *Store) SetSidecarEvaluator(ev middleware.SidecarEvaluator) {
	s.sidecarEvaluator = ev
}

// stampSidecar evaluates msg — the entry's own stored records — and
// stamps the result. Pre-publication entries are stamped with a plain
// store; nothing else can hold them yet.
func (s *Store) stampSidecar(e *CacheEntry, msg *dns.Msg) {
	if e == nil || s.sidecarEvaluator == nil {
		return
	}
	e.sidecar.Store(s.sidecarEvaluator(msg))
}

// NewStore returns a Store backed by the supplied sub-caches. The
// caches are shared with the surrounding *Cache; this constructor
// does not allocate them.
func NewStore(positive *PositiveCache, negative *NegativeCache, cfg CacheConfig, failures ...*FailureCache) *Store {
	var failure *FailureCache
	if len(failures) > 0 {
		failure = failures[0]
	}
	if failure == nil {
		failure, _ = NewFailureCache(FailureCacheConfig{
			Size:       DefaultFailureCacheSize,
			InitialTTL: DefaultFailureInitialTTL,
			MaxTTL:     DefaultFailureMaxTTL,
		})
	}

	// Keep RFC 8020 state separately bounded so attacker-chosen denied names
	// cannot evict ordinary positive answers. Sixteenth-of-cache is enough to
	// retain useful subtree cuts while adding at most 6.25% to the configured
	// answer-cache cardinality.
	cutSize := cfg.Size / 16
	if cutSize < 1 {
		cutSize = 1
	}
	cutMaxTTL := cfg.NegativeTTL
	if cutMaxTTL <= 0 {
		cutMaxTTL = cfg.MaxTTL
	}
	if cfg.MaxTTL > 0 && cutMaxTTL > cfg.MaxTTL {
		cutMaxTTL = cfg.MaxTTL
	}

	// RFC 8198 proof material has its own cardinality and byte bounds so
	// attacker-chosen denial owners cannot evict ordinary answers. Production
	// cache sizes are validated to at least 1024; the small floor keeps direct
	// Store users useful without preallocating any entries.
	proofSize := cfg.Size / 32
	if proofSize < 64 {
		proofSize = 64
	}
	proofMaxTTL := cfg.NegativeTTL
	if proofMaxTTL <= 0 {
		proofMaxTTL = cfg.MaxTTL
	}
	if cfg.MaxTTL > 0 && proofMaxTTL > cfg.MaxTTL {
		proofMaxTTL = cfg.MaxTTL
	}

	return &Store{
		positive:     positive,
		negative:     negative,
		failure:      failure,
		nxDomainCuts: newNXDomainCutCache(cutSize, cutMaxTTL),
		denialProofs: newDenialProofCache(proofSize, proofMaxTTL),
		cfg:          cfg,
	}
}

// Lookup returns the cache entry for req without materialising a
// response. Used by callers that need to inspect TTL or prefetch
// flags before deciding whether to consume the entry.
func (s *Store) Lookup(req *dns.Msg) (*CacheEntry, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}
	want := CacheKey{Question: req.Question[0], CD: req.CheckingDisabled}
	return s.LookupByKeyVerified(want.Hash(), want)
}

// LookupByKey is the pre-keyed form of Lookup, used by hot paths
// inside the cache middleware that already computed the key.
//
// Callers MUST verify the returned entry against the preimage they keyed
// with (use LookupByKeyVerified, or entryMatchesKey / entryMatchesWire):
// the map key is a non-cryptographic 64-bit xxhash of that preimage, so a
// hash collision would otherwise serve one query's answer to another.
func (s *Store) LookupByKey(key uint64) (*CacheEntry, bool) {
	var (
		entry *CacheEntry
		ok    bool
	)
	if s.cfg.ServeStale {
		entry, ok = s.positive.retained(key)
	} else {
		entry, ok = s.positive.Get(key)
	}
	if ok {
		return entry, true
	}
	if entry, ok := s.negative.Get(key); ok {
		return entry, true
	}
	return nil, false
}

// LookupByKeyVerified is LookupByKey plus a full-key check: it confirms the
// stored entry was admitted under exactly the preimage want describes before
// returning it. Without this, two distinct preimages that collide under
// xxhash64 would silently serve each other's answers — and because qnames
// are attacker-chosen, a collision can be searched for offline and used to
// poison the cache.
func (s *Store) LookupByKeyVerified(key uint64, want CacheKey) (*CacheEntry, bool) {
	entry, ok := s.LookupByKey(key)
	if !ok || !entryMatchesKey(entry, want) {
		return nil, false
	}
	return entry, true
}

// lookupRetainedPositiveVerified is the serve-stale view of the positive
// cache. It deliberately bypasses freshness cleanup but still verifies the
// complete key preimage; policy and response shaping remain the caller's job.
func (s *Store) lookupRetainedPositiveVerified(key uint64, want CacheKey) (*CacheEntry, bool) {
	entry, ok := s.positive.retained(key)
	if !ok || !entryMatchesKey(entry, want) {
		return nil, false
	}
	return entry, true
}

// entryMatchesKey is the Msg-path collision verifier: the shared preimage
// check plus the qname in presentation form.
func entryMatchesKey(entry *CacheEntry, want CacheKey) bool {
	return entryMatchesPreimage(entry, want.Question.Qtype, want.Question.Qclass, want.CD, want.Scope) &&
		equalNameASCIIFold(entry.question.Name, want.Question.Name)
}

// entryMatchesWireQuestion is the wire-path collision verifier: the same
// preimage check, with the qname compared straight off the wire so a hit
// never builds a presentation name. Byte serving covers shared entries
// only, hence the shared scope.
func entryMatchesWireQuestion(entry *CacheEntry, wireName []byte, qtype, qclass uint16, cd bool) bool {
	return entryMatchesPreimage(entry, qtype, qclass, cd, netip.Prefix{}) &&
		cache.WireNameEqualsPresentation(wireName, entry.question.Name)
}

// entryMatchesPreimage compares every dimension the cache key is built from
// except the qname, which each path compares in the form it already holds.
// Both verifiers route through here so neither can quietly stop checking a
// dimension the other still does: a 64-bit hash match is not evidence that
// the entry belongs to this question, this CD partition, or this ECS
// audience — only the preimage is.
func entryMatchesPreimage(entry *CacheEntry, qtype, qclass uint16, cd bool, scope netip.Prefix) bool {
	if entry == nil || entry.question.Name == "" {
		return false
	}
	eq := entry.question
	return eq.Qtype == qtype && eq.Qclass == qclass &&
		entry.cd == cd && entry.scope == normalizeKeyScope(scope)
}

// equalNameASCIIFold reports whether two DNS names are equal under
// ASCII-only case folding — exactly the normalization the cache key uses
// (internal/cache.Key lowercases A–Z and nothing else). strings.EqualFold
// would be broader (full Unicode case folding), so two names the key hash
// treats as distinct could compare equal here and weaken the collision
// check; matching the hash's folding keeps the verification exact.
func equalNameASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Get returns a materialised cached response for req. Reply
// header/ID/CD/AD interaction is handled by CacheEntry.ToMsg, which
// needs req for SetReply.
func (s *Store) Get(req *dns.Msg) (*dns.Msg, bool) {
	return s.GetWithContext(context.Background(), req)
}

// GetWithContext is Get with request-tree policy and NSEC3 memo propagation.
// Resolver-private DS/DNSKEY lookups manufacture fresh messages, so the
// context marker is what preserves an outer client's CD/ECS isolation.
func (s *Store) GetWithContext(ctx context.Context, req *dns.Msg) (*dns.Msg, bool) {
	if req == nil {
		return nil, false
	}
	// Answers handed out here are consumed by the resolver — DS and DNSKEY
	// lookups above all. Only denial shapes bind the request tree to their
	// lifetime: a delegation held insecure by a cached DS denial must not
	// outlive the proof that said so. A positive consult is a validation
	// input, not part of the answer's lineage — folding its remaining life
	// into the tree collapsed every fresh answer's served TTL to the oldest
	// key consulted on the walk, and signature validity already bounds
	// validated answers at admission.
	entry, ok := s.Lookup(req)
	if ok {
		msg := entry.ToMsg(req)
		if msg != nil {
			if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) == 0 {
				boundRequestToEntryLifetime(ctx, entry)
			}
			return msg, true
		}
	}

	requestTreeBypassesDenial := req.CheckingDisabled ||
		hasEDNSClientSubnet(req) ||
		middleware.HasClientECS(ctx) ||
		sharedDenialBypass(ctx)
	if !requestTreeBypassesDenial {
		if cut, ok := s.LookupNXDomainCut(req); ok {
			if msg := cut.response(req); msg != nil {
				boundRequestTo(ctx, cut.expires)
				nxDomainCutHits.Inc()
				return msg, true
			}
		}
		if !s.rfc8198Disabled {
			if msg, kind, _, expires, ok := s.lookupDenialProofWithExpiry(
				req,
				newDenialProofWork(ctx, s.dnssecCryptoLimiter),
			); ok {
				boundRequestTo(ctx, expires)
				observeAggressiveNegativeHit(kind, msg.Rcode)
				return msg, true
			}
		}
	}

	// Get is also used by resolver-private subqueries, which deliberately do
	// not inherit the client's ECS audience. Keep RFC 9520 failure lookup
	// unscoped here; request paths carrying ECS call LookupFailure directly
	// with their explicit audience.
	if hit, ok := s.LookupFailure(req, netip.Prefix{}); ok {
		failureCacheHits.Inc()
		return hit.Response(req), true
	}
	return nil, false
}

// LookupNXDomainCut returns the closest locally validated RFC 8020 cut that
// covers req. CD=1 is always a miss: checking-disabled clients explicitly
// bypass locally synthesized authenticated denial state.
func (s *Store) LookupNXDomainCut(req *dns.Msg) (*nxDomainCutEntry, bool) {
	if s == nil || s.nxDomainCuts == nil || req == nil ||
		s.sharedDenialDisabled ||
		len(req.Question) == 0 || req.CheckingDisabled {
		return nil, false
	}
	return s.nxDomainCuts.lookup(req.Question[0])
}

// LookupNXDomainCutWire is LookupNXDomainCut for a wire-born question:
// same store, same walk, no decoded message. CD gating is the caller's —
// the wire path mirrors the Msg entry's bypass conditions inline.
func (s *Store) LookupNXDomainCutWire(name []byte, qclass uint16) (*nxDomainCutEntry, bool) {
	if s == nil || s.nxDomainCuts == nil || s.sharedDenialDisabled {
		return nil, false
	}
	return s.nxDomainCuts.lookupWire(name, qclass)
}

// LookupFailureWire is LookupFailure for a wire-born question without an
// ECS scope.
func (s *Store) LookupFailureWire(name []byte, qtype, qclass uint16, cd bool) (FailureHit, bool) {
	if s == nil || s.failureCacheDisabled || s.failure == nil {
		return FailureHit{}, false
	}
	return s.failure.LookupWire(name, qtype, qclass, cd)
}

// sharedDenialImpossible reports that no RFC 8198 evaluation can ever
// run in this process — construction-time configuration. With denial
// impossible on every path, a zone-kind failure hit cannot be shadowed
// by synthesis, so the wire gate may serve it without a witness.
func (s *Store) sharedDenialImpossible() bool {
	return s == nil || s.rfc8198Disabled || s.sharedDenialDisabled || s.denialProofs == nil
}

// RecordNXDomainCut stores a locally validated terminal NXDOMAIN proof.
// deniedName is the exact authoritative query cycle that returned NXDOMAIN;
// it must never be inferred from the SOA owner.
func (s *Store) RecordNXDomainCut(
	proof *dns.Msg,
	deniedName string,
	zone string,
	cutUntil time.Time,
) bool {
	if s == nil || s.nxDomainCuts == nil || s.sharedDenialDisabled {
		return false
	}
	return s.nxDomainCuts.record(proof, deniedName, zone, cutUntil)
}

// LookupDenialProof evaluates the bounded RFC 8198 proof index for req.
// The returned kind and signer zone describe the exact proof family selected
// by the evaluator, including when a DO=0 response omits DNSSEC records.
func (s *Store) LookupDenialProof(
	req *dns.Msg,
	work dnssec.NSEC3Work,
) (*dns.Msg, middleware.ValidatedNegativeProofKind, string, bool) {
	msg, kind, zone, _, ok := s.lookupDenialProofWithExpiry(req, work)
	return msg, kind, zone, ok
}

// lookupDenialProofWithExpiry is LookupDenialProof plus the instant past which
// the synthesized answer must not be used: the earliest expiry among the SOA
// and the proof records it was built from. Anything derived from the answer
// inherits that bound. Kept separate so the exported signature above stays as
// callers outside this repository have it.
func (s *Store) lookupDenialProofWithExpiry(
	req *dns.Msg,
	work dnssec.NSEC3Work,
) (*dns.Msg, middleware.ValidatedNegativeProofKind, string, time.Time, bool) {
	if s == nil || s.denialProofs == nil ||
		s.sharedDenialDisabled || s.rfc8198Disabled {
		return nil, middleware.ValidatedNegativeProofUnknown, "", time.Time{}, false
	}
	msg, kind, zone, expires, ok := s.denialProofs.lookupWithMeta(req, work)
	if !ok {
		return nil, middleware.ValidatedNegativeProofUnknown, "", time.Time{}, false
	}
	switch kind {
	case denialProofNSEC:
		return msg, middleware.ValidatedNegativeProofNSEC, zone, expires, true
	case denialProofNSEC3:
		return msg, middleware.ValidatedNegativeProofNSEC3, zone, expires, true
	default:
		return nil, middleware.ValidatedNegativeProofUnknown, "", time.Time{}, false
	}
}

// RecordDenialProof stores complete signed SOA and NSEC/NSEC3 RRsets from an
// exact locally validated terminal proof. kind is checked against the retained
// mechanism so provenance cannot be reinterpreted by a later cache layer.
func (s *Store) RecordDenialProof(
	proof *dns.Msg,
	zone string,
	kind middleware.ValidatedNegativeProofKind,
	cutUntil time.Time,
) bool {
	if s == nil || s.denialProofs == nil || proof == nil ||
		s.sharedDenialDisabled || s.rfc8198Disabled {
		return false
	}
	var expected denialProofKind
	switch kind {
	case middleware.ValidatedNegativeProofNSEC:
		expected = denialProofNSEC
	case middleware.ValidatedNegativeProofNSEC3:
		expected = denialProofNSEC3
	default:
		return false
	}
	return s.denialProofs.recordWithKind(proof, zone, expected, cutUntil)
}

// LookupFailure returns an active exact or closest-ancestor RFC 9520 failure.
func (s *Store) LookupFailure(req *dns.Msg, scope netip.Prefix) (FailureHit, bool) {
	if s.failureCacheDisabled || s.failure == nil || req == nil || len(req.Question) == 0 {
		return FailureHit{}, false
	}
	return s.failure.Lookup(FailureQuestionKey{
		Question: req.Question[0],
		CD:       req.CheckingDisabled,
		Scope:    scope,
	})
}

// FailureRetryKey returns the retained failure generation used to coalesce the
// first retry after a backoff expires. Different random QNAMEs below the same
// failed zone therefore elect only one probe leader.
func (s *Store) FailureRetryKey(req *dns.Msg, scope netip.Prefix) (uint64, bool) {
	if s.failureCacheDisabled || s.failure == nil || req == nil || len(req.Question) == 0 {
		return 0, false
	}
	return s.failure.RetryKey(FailureQuestionKey{
		Question: req.Question[0],
		CD:       req.CheckingDisabled,
		Scope:    scope,
	})
}

// RecordFailure records a question-specific terminal resolution failure.
// witness must be the miss witness captured at the moment the recording
// request's denial rung ran and missed (Cache.ServeDNS stashes it on the
// response writer), and nil from every path that never ran the rung — a
// CD or client-ECS tree that bypassed it, a compatibility Set, a scoped
// insert. A witness fabricated later would assert a miss nobody
// established at a moment nobody checked.
func (s *Store) RecordFailure(req *dns.Msg, scope netip.Prefix, provenance FailureProvenance, witness []denialWitnessPair) {
	if s.failureCacheDisabled || s.failure == nil || req == nil || len(req.Question) == 0 {
		return
	}
	s.recordFailureQuestion(req.Question[0], req.CheckingDisabled, scope, provenance, witness)
}

func (s *Store) recordFailureQuestion(q dns.Question, cd bool, scope netip.Prefix, provenance FailureProvenance, witness []denialWitnessPair) {
	if s.failureCacheDisabled || s.failure == nil {
		return
	}
	if cd {
		// A CD entry serves CD lookups, which skip the gate entirely; a
		// witness here could only ever mislead.
		witness = nil
	}
	s.failure.RecordQuestion(FailureQuestionKey{
		Question: q,
		CD:       cd,
		Scope:    scope,
	}, provenance, witness)
}

// failureMissWitness captures the denial-zone state a failing question
// saw (denial_proof_witness.go). With RFC 8198 handling disabled the
// witness is moot — the wire gate treats disabled the same way.
func (s *Store) failureMissWitness(qname string, qclass uint16) []denialWitnessPair {
	if s == nil || s.rfc8198Disabled || s.sharedDenialDisabled || s.denialProofs == nil {
		return nil
	}
	return s.denialProofs.missWitness(dns.CanonicalName(qname), qclass)
}

// DenialMissHoldsWire reports whether a failure entry's record-time
// proof that aggressive denial does not apply is still valid for this
// wire-born name — the condition under which the wire path may serve
// the failure without materializing.
func (s *Store) DenialMissHoldsWire(name []byte, qclass uint16, hit FailureHit) bool {
	if s == nil || s.rfc8198Disabled || s.sharedDenialDisabled || s.denialProofs == nil {
		return true
	}
	return s.denialProofs.missWitnessHoldsWire(name, qclass, hit.witness)
}

// RecordZoneFailure implements middleware.ResolutionFailureStore. Zone-wide
// reachability failures are deliberately independent of CD and ECS.
func (s *Store) RecordZoneFailure(q dns.Question, zone string) {
	if s.failureCacheDisabled || s.failure == nil || zone == "" {
		return
	}
	// Zone-kind hits answer descendant names the recording question never
	// proved anything about, so they are excluded from witness serving
	// (cache.go's gate) and carry none.
	s.failure.RecordZone(FailureZoneKey{
		Zone:   zone,
		Qclass: q.Qclass,
	}, FailureProvenance("authority"), nil)
}

// ClearZoneFailure removes authority reachability history after the resolver
// receives a useful response from that same zone. Local/static cache writers
// never call this, so a hosts-file answer cannot falsely mark an upstream zone
// as recovered.
func (s *Store) ClearZoneFailure(q dns.Question, zone string) {
	if s.failureCacheDisabled || s.failure == nil || zone == "" {
		return
	}
	s.failure.ResetZone(FailureZoneKey{Zone: zone, Qclass: q.Qclass})
}

func (s *Store) resetQuestionFailure(q dns.Question, cd bool, scope netip.Prefix) {
	if s.failureCacheDisabled || s.failure == nil {
		return
	}
	s.failure.ResetQuestion(FailureQuestionKey{
		Question: q,
		CD:       cd,
		Scope:    scope,
	})
}

func (s *Store) resetMatchingFailures(q dns.Question, cd bool, scope netip.Prefix) {
	if s.failureCacheDisabled || s.failure == nil {
		return
	}
	s.failure.ResetMatching(FailureQuestionKey{
		Question: q,
		CD:       cd,
		Scope:    scope,
	})
}

// SetFromResponse classifies resp (answer / NXDOMAIN+NODATA /
// resolution failure) and stores it under (resp.Question[0], keyCD). CHAOS
// signalling responses are skipped, matching ResponseWriter.WriteMsg.
// cutUntil bounds the entry to the delegation cut that produced it; zero
// means unbounded. This compatibility entry point has no lineage identity.
func (s *Store) SetFromResponse(resp *dns.Msg, keyCD bool, cutUntil time.Time) {
	s.SetFromResponseWithCut(resp, keyCD, cutUntil, 0)
}

// SetFromResponseWithCut is SetFromResponse plus the delegation identity that
// supplied cutUntil, retained for the optional Phase-3 generation design.
func (s *Store) SetFromResponseWithCut(resp *dns.Msg, keyCD bool, cutUntil time.Time, cutKey uint64) {
	if len(resp.Question) == 0 {
		return
	}
	q := resp.Question[0]
	if (debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO) ||
		(q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL) {
		return
	}
	s.setFromResponseWithKey(
		CacheKey{Question: q, CD: keyCD}.Hash(),
		resp,
		netip.Prefix{},
		cutUntil,
		cutKey,
		keyCD,
	)
}

// SetFromResponseWithKey is the pre-keyed form of SetFromResponse,
// used by ResponseWriter.WriteMsg, which has the key already.
func (s *Store) SetFromResponseWithKey(key uint64, resp *dns.Msg, cutUntil time.Time, cutKey uint64) {
	s.setFromResponseWithKey(key, resp, netip.Prefix{}, cutUntil, cutKey, resp.CheckingDisabled)
}

// SetFromResponseScoped is SetFromResponseWithKey for entries that
// were keyed under an ECS scope (RFC 7871 §7.1.2). scope must be the
// prefix key was computed from: the entry carries it, and the hit-path
// verifier compares the two so a colliding key cannot cross ECS
// audiences. The entry's PrefetchEligible is false — the prefetch worker
// has no client IP to derive ECS from, so refreshing a scoped entry would
// lose its scope and store the wrong-audience answer.
func (s *Store) SetFromResponseScoped(key uint64, resp *dns.Msg, scope netip.Prefix, cutUntil time.Time, cutKey uint64) {
	s.setFromResponseWithKey(key, resp, scope, cutUntil, cutKey, resp.CheckingDisabled)
}

func (s *Store) setFromResponseWithKey(key uint64, resp *dns.Msg, scope netip.Prefix, cutUntil time.Time, cutKey uint64, keyCD bool) {
	mt, _ := dnsutil.ClassifyResponse(resp, time.Now().UTC())
	filtered := filterCacheableAnswer(resp)
	msgTTL := dnsutil.CalculateCacheTTL(filtered, mt)

	scope = normalizeKeyScope(scope)
	scoped := scope.IsValid()

	// Scoped (ECS) entries get an additional cap: geo answers go
	// stale faster than the resolver's normal MaxTTL would allow,
	// and a misconfigured upstream sending a huge TTL on a /24
	// answer shouldn't pin that audience-specific entry for hours.
	// Zero ECSMaxTTL leaves scoped writes uncapped (operator opted
	// in to long-lived scoped entries).
	capTTL := func(ttl time.Duration) time.Duration {
		if scoped && s.cfg.ECSMaxTTL > 0 && ttl > s.cfg.ECSMaxTTL {
			return s.cfg.ECSMaxTTL
		}
		return ttl
	}

	newEntry := func(msg *dns.Msg, ttl time.Duration) *CacheEntry {
		var e *CacheEntry
		if scoped {
			e = NewScopedCacheEntry(msg, ttl, s.cfg.RateLimit, scope)
		} else {
			e = NewCacheEntryWithKey(msg, ttl, s.cfg.RateLimit, key)
		}
		if e == nil {
			// Unpackable response: never cacheable, callers skip the write.
			return nil
		}
		if scoped {
			e.rateLimKey = key
		}
		// The entry's identity is the key's, not the message's: callers
		// name the CD partition they keyed with, and a hit is verified
		// against that. resp.CheckingDisabled is the same bit on every
		// in-tree path, but an entry filed under a CD the response no
		// longer carries would be unreachable rather than merely misfiled.
		e.cd = keyCD
		e.cutUntil = cutUntil
		e.cutKey = cutKey
		s.stampSidecar(e, msg)
		return e
	}

	switch mt {
	case dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeNXDomain, dnsutil.TypeNoRecords:
		// A denial the zone granted no lifetime is not cacheable at all (RFC
		// 2308 §5). Admitting it with a zero TTL would occupy a slot that
		// every later read has to discard, and the entry could never be
		// served — the guard cannot fire for a positive answer, which always
		// arrives on its own floor.
		ttl := capTTL(s.positive.ttl.Bound(msgTTL))
		if ttl > 0 {
			if entry := newEntry(filtered, ttl); entry != nil {
				s.positive.Set(key, entry)
			}
		}
		// A scoped write has no source prefix here (only its already-hashed
		// cache key), so it must not reset the unrelated global failure
		// audience. Cache.ResponseWriter owns scoped failure reset because it
		// still has the concrete client prefix.
		if !scoped {
			s.resetQuestionFailure(resp.Question[0], keyCD, netip.Prefix{})
		}
	case dnsutil.TypeServerFailure:
		// Resolution failures normally bypass this path in ResponseWriter.
		// If a pre-keyed scoped caller reaches it, do not misfile that
		// audience-specific failure as a global one without its prefix.
		if !scoped {
			s.recordFailureQuestion(resp.Question[0], keyCD, netip.Prefix{}, FailureProvenance("response"), nil)
		}
	}
}

// ReplaceIfCurrent stores resp under key only if expected is still
// the live entry for that key — the pointer-CAS late-write guard for
// asynchronous refreshes (GHSA-mqfw-f48p-2vc8). A prefetch captures
// the entry that claimed it; by the time its refresh returns, newer
// state (a withdrawal NXDOMAIN, a re-delegated answer) may have
// replaced that entry, and the stale result must be dropped, not
// stored. Returns whether the replacement happened.
//
// Two deliberate asymmetries:
//   - A SERVFAIL refresh never displaces a positive entry: it only
//     CASes into the negative cache, so a transient upstream failure
//     can't evict a still-valid answer. Production Cache SERVFAILs use
//     FailureCache; this branch preserves the exported Store/NegativeCache
//     contract for programmatic callers and manually seeded legacy entries.
//   - The CAS stays within one sub-cache. A negative entry refreshing
//     to a positive answer is dropped rather than promoted — the two
//     caches can't be swapped atomically, and the negative entry's
//     short TTL re-resolves naturally.
func (s *Store) ReplaceIfCurrent(key uint64, expected *CacheEntry, resp *dns.Msg, cutUntil time.Time, cutKey uint64) bool {
	if expected == nil || len(resp.Question) == 0 {
		return false
	}

	mt, _ := dnsutil.ClassifyResponse(resp, time.Now().UTC())
	filtered := filterCacheableAnswer(resp)
	msgTTL := dnsutil.CalculateCacheTTL(filtered, mt)

	// A replacement takes over the key expected occupies, so it inherits
	// that key's CD partition and ECS scope. A refresh that carried the
	// response's own CD bit instead would be verified against the key it
	// was stored under and silently declined on every later hit.
	inherit := func(entry *CacheEntry) *CacheEntry {
		if entry == nil {
			return nil
		}
		entry.cd = expected.cd
		entry.scope = expected.scope
		entry.cutUntil = cutUntil
		entry.cutKey = cutKey
		s.stampSidecar(entry, filtered)
		return entry
	}

	switch mt {
	case dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeNXDomain, dnsutil.TypeNoRecords:
		// A refresh that comes back as a denial with no zone-granted lifetime
		// is dropped rather than stored. The entry it would have replaced
		// keeps its own remaining TTL and re-resolves when that runs out.
		ttl := s.positive.ttl.Bound(msgTTL)
		if ttl <= 0 {
			return false
		}
		entry := inherit(NewCacheEntryWithKey(filtered, ttl, s.cfg.RateLimit, key))
		if entry == nil {
			return false
		}
		return s.positive.cache.CompareAndSwap(key, expected, entry)
	case dnsutil.TypeServerFailure:
		entry := inherit(NewCacheEntryWithKey(filtered, s.negative.ttl.Calculate(msgTTL), s.cfg.RateLimit, key))
		if entry == nil {
			return false
		}
		return s.negative.cache.CompareAndSwap(key, expected, entry)
	}
	return false
}

// SetEntryWithKey replaces a stored entry directly. Used by
// Cache.Set's compatibility path where a caller already constructed
// the CacheEntry (e.g. prefetch worker writing back a response with
// adjusted origTTL).
func (s *Store) SetEntryWithKey(key uint64, entry *CacheEntry, mt dnsutil.ResponseType) {
	switch mt {
	case dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeNXDomain, dnsutil.TypeNoRecords:
		if entry == nil {
			return
		}
		s.positive.Set(key, entry)
		if entry.question.Name != "" {
			s.resetQuestionFailure(entry.question, entry.cd, netip.Prefix{})
		}
	case dnsutil.TypeServerFailure:
		if entry != nil && entry.question.Name != "" {
			s.recordFailureQuestion(entry.question, entry.cd, netip.Prefix{}, FailureProvenance("response"), nil)
		}
	}
}

// Purge removes both CD=true and CD=false entries for q from
// positive and negative caches, including ECS-scoped entries.
//
// Scoped entries don't have a deterministic key the caller could
// reproduce without enumerating every (qname, scope) the cache
// has ever seen — there's no per-qname index. We sweep them with
// ForEach: collect matching keys in one pass (snapshotting the
// per-segment locks individually), then Remove outside the
// iteration to avoid mutate-during-iterate hazards.
//
// O(n) on the cache size; Purge is rare (explicit operator API
// call) so the linear scan is acceptable. If purge becomes
// hot, a per-qname index would lift this back to O(matches).
func (s *Store) Purge(q dns.Question) {
	if !s.failureCacheDisabled && s.failure != nil {
		s.failure.PurgeQuestion(q)
	}
	if s.nxDomainCuts != nil {
		s.nxDomainCuts.purge(q)
	}
	if s.denialProofs != nil {
		s.denialProofs.purge(q)
	}
	for _, cd := range []bool{false, true} {
		key := CacheKey{Question: q, CD: cd}.Hash()
		s.positive.Remove(key)
		s.negative.Remove(key)
	}

	type located struct {
		positive bool
		key      uint64
	}
	var hits []located
	s.ForEach(func(positive bool, key uint64, e *CacheEntry) bool {
		if e == nil || !e.scoped() || e.question.Name == "" {
			return true
		}
		eq := e.question
		// DNS names compare case-insensitively (RFC 4343). The
		// unscoped purge path is already case-insensitive — its
		// key derives from internal/cache.Key which lowercases the
		// name during hashing. The scoped sweep enumerates raw
		// stored Questions, so the comparison has to match the
		// hash's semantics or an entry cached for EXAMPLE.COM.
		// would survive a purge of example.com.
		if eq.Qtype == q.Qtype && eq.Qclass == q.Qclass && strings.EqualFold(eq.Name, q.Name) {
			hits = append(hits, located{positive: positive, key: key})
		}
		return true
	})
	for _, h := range hits {
		if h.positive {
			s.positive.Remove(h.key)
		} else {
			s.negative.Remove(h.key)
		}
	}
}

// PositiveLen returns the number of entries in the positive cache.
func (s *Store) PositiveLen() int { return s.positive.Len() }

// NegativeLen returns the number of entries in the negative cache.
func (s *Store) NegativeLen() int { return s.negative.Len() }

// FailureLen returns retained active and expired RFC 9520 failure states.
func (s *Store) FailureLen() int {
	if s == nil || s.failureCacheDisabled || s.failure == nil {
		return 0
	}
	return s.failure.Len()
}

// NXDomainCutLen returns retained locally validated RFC 8020 cuts.
func (s *Store) NXDomainCutLen() int { return s.nxDomainCuts.len() }

// DenialProofLen returns retained SOA and denial RRset entries.
func (s *Store) DenialProofLen() int { return s.denialProofs.len() }

// DenialProofZones returns the number of signer-zone shards.
func (s *Store) DenialProofZones() int { return s.denialProofs.zones() }

// DenialProofBytes returns the retained DNS wire bytes.
func (s *Store) DenialProofBytes() int64 { return s.denialProofs.bytes() }

// Stop releases background resources owned by Store-only sub-caches.
func (s *Store) Stop() {
	if s != nil {
		s.nxDomainCuts.stop()
		s.denialProofs.stop()
	}
}

// ForEach iterates over positive then negative entries. Returning
// false from fn stops iteration. Iteration is not atomic with
// concurrent updates.
func (s *Store) ForEach(fn func(positive bool, key uint64, entry *CacheEntry) bool) {
	keepGoing := true
	for i, sub := range []*cache.Cache{s.positive.cache, s.negative.cache} {
		sub.ForEach(func(key uint64, value any) bool {
			if keepGoing {
				if entry, ok := value.(*CacheEntry); ok && entry != nil {
					keepGoing = fn(i == 0, key, entry)
				}
			}
			return keepGoing
		})
	}
}
