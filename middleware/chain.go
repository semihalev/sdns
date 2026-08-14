package middleware

import (
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/wire"
)

// ResponseMeta carries resolver-produced metadata about a response
// that the wire format cannot express — today the delegation-cut
// deadline that bounds how long the answer may be cached
// (GHSA-mqfw-f48p-2vc8, answer-cache ghost).
//
// One ResponseMeta spans a whole client request tree: the first
// middleware that needs it establishes it in ctx (usually pointing at
// its Chain's pooled Meta field) and every nested sub-pipeline reuses
// the ctx one, so deadlines observed anywhere in the tree accumulate
// into the same place. Folding is min-only (BoundCut), which makes
// cross-leg sharing safe: the worst case is an answer cached slightly
// shorter than its own cut allowed, never longer.
type responseCut struct {
	deadline time.Time
	key      uint64
}

// cachedFailureResponseSet tracks the exact response pointers currently being
// emitted from the RFC 9520 failure cache. Pointer identity is deliberate: a
// request tree can produce other SERVFAIL responses concurrently, and a
// request-wide boolean would let one cached response misclassify another.
type cachedFailureResponseSet struct {
	mu       sync.RWMutex
	messages map[*dns.Msg]uint32
}

// ValidatedDenial is resolver-authenticated NXDOMAIN provenance. It is carried
// out of band because neither RcodeNameError nor the AD bit proves that this
// resolver validated the denial itself.
//
// Values are copied into ResponseMeta and never mutated there. DeniedName is
// the name proven not to exist; Zone is the signed zone that supplied the
// proof.
type ValidatedDenial struct {
	DeniedName string
	Zone       string
	// Proof is the original response whose denial proof the resolver
	// authenticated. Middleware may propagate the provenance to a replacement
	// response, but consumers must derive cached proof material from this
	// source rather than from the replacement's possibly rewritten sections.
	Proof *dns.Msg
}

// ValidatedNegativeProofKind identifies the denial mechanism the resolver
// authenticated. Keeping this in the provenance prevents a later cache layer
// from combining NSEC and NSEC3 records, or choosing a different NSEC3 chain
// than the one whose semantics were checked.
type ValidatedNegativeProofKind uint8

const (
	ValidatedNegativeProofUnknown ValidatedNegativeProofKind = iota
	ValidatedNegativeProofNSEC
	ValidatedNegativeProofNSEC3
)

// ValidatedNegativeProof is resolver-authenticated NXDOMAIN or NODATA
// provenance. Subject is the exact terminal (or QNAME-minimized) name whose
// denial semantics were checked; Zone is the validated signer zone. Proof is
// the original terminal response, never an outer alias response assembled
// later in the request tree.
//
// The zero/Unknown Kind exists only so the older ValidatedDenial compatibility
// API can preserve its source contract. RFC 8198 admission requires an
// explicit NSEC or NSEC3 kind.
type ValidatedNegativeProof struct {
	Subject string
	Zone    string
	Kind    ValidatedNegativeProofKind
	Proof   *dns.Msg
	// Aggressive is true only when the stricter RFC 8198 evaluator
	// classified this exact response with the same RCODE. Exact DNSSEC
	// validation can legitimately succeed while aggressive reuse is forbidden
	// (notably NSEC3 Opt-Out); consumers publishing shared proof state must
	// require this bit in addition to local provenance.
	Aggressive bool
}

// validatedNegativeProofResponseSet binds locally validated negative
// provenance to the exact response identity that may publish it. Pointer
// identity is deliberate: dns.Msg is mutable, and a copy or independently
// produced negative response has not inherited the proof merely because its
// wire-visible fields happen to match.
type validatedNegativeProofResponseSet struct {
	mu       sync.RWMutex
	messages map[*dns.Msg]validatedNegativeProofRecord
}

type validatedNegativeProofRecord struct {
	negative    ValidatedNegativeProof
	fingerprint [sha256.Size]byte
}

// requestLedgers is one request tree's shared state, held apart from the
// metas that reach it.
//
// A ResponseMeta is pooled and reused by the next request, so its address is
// not an identity: a sub-query that outlives its request would otherwise read
// whatever the next one put in the same struct. This is allocated per request
// generation and captured by the root and every fork under it, so a reset
// root drops only its own reference and the forks that came before keep the
// state they belong to.
type requestLedgers struct {
	// work is the request-tree recursion ledger. Reset detaches the pointer
	// without mutating the ledger so resolver goroutines that briefly outlive
	// a pooled Chain keep charging their original request.
	work atomic.Pointer[RecursionWorkLedger]

	// guard is the RFC 9520 request-tree retry guard, ready to use as soon as
	// this value exists. It has storage here rather than being a second
	// object per request.
	//
	// There is no flag for whether it was established: every path that can
	// create these ledgers establishes the guard first — the queryer, the
	// cache, the resolver, the forwarder and failover all do — so inside a
	// request tree the distinction cannot arise. Outside one there is no
	// meta at all, and the callers that are meant to skip accounting still
	// find nothing.
	guard ResolutionAttemptGuard

	// cachedFailures is a pointer-identity set of failure cache responses
	// currently crossing outer response-writer wrappers.
	cachedFailures atomic.Pointer[cachedFailureResponseSet]

	// validatedNegativeProofs is immutable, exact-response NXDOMAIN or NODATA
	// provenance produced by this resolver.
	validatedNegativeProofs atomic.Pointer[validatedNegativeProofResponseSet]
}

type ResponseMeta struct {
	// cut is the earliest deadline observed for the request tree, guarded by
	// its own mutex. Resolver work can fan out into concurrent NS-address
	// sub-queries that share the request context, so a plain time.Time here
	// races even though every update is min-only.
	//
	// The value is held inline rather than behind an atomic pointer: every
	// cache hit now folds its own lifetime in, so a publish that allocated
	// an immutable deadline per call would put an allocation on the hottest
	// path in the server. The critical section is two comparisons.
	cutMu sync.Mutex
	cut   responseCut

	// ledgers is this request tree's shared state. A root creates it on first
	// use and drops it on Reset; a fork captures the same one at construction
	// and keeps it for as long as it lives, which is what stops a fork from
	// following a pooled root into the next request.
	ledgers atomic.Pointer[requestLedgers]

	// workPolicy is immutable after a Chain is constructed. It lets the
	// server's request context create the ledger only when real recursive work
	// begins while preserving the outer pipeline's first-policy precedence.
	// Standalone ResponseMeta values leave it zero.
	workPolicy RecursionWorkPolicy
}

// ledgerHost returns this meta's request-tree state, or nil when the request
// has established none. Readers take this one.
//
// Every operation snapshots the host once and works on that value: a root
// being reset concurrently must not leave a single operation reading one
// generation and writing another.
func (m *ResponseMeta) ledgerHost() *requestLedgers {
	if m == nil {
		return nil
	}
	return m.ledgers.Load()
}

// ensureLedgerHost is ledgerHost for the operations that establish state,
// creating the request tree's ledgers on first use.
//
// It retries rather than reading back after a lost race: a Reset landing
// between the losing exchange and the read would return nil to a caller that
// is about to establish state in it.
func (m *ResponseMeta) ensureLedgerHost() *requestLedgers {
	if m == nil {
		return nil
	}
	for {
		if host := m.ledgers.Load(); host != nil {
			return host
		}
		host := new(requestLedgers)
		if m.ledgers.CompareAndSwap(nil, host) {
			return host
		}
	}
}

// ForkCut returns a meta that shares this one's request-tree state — work
// ledger, retry guard, failure and proof provenance — but accumulates its own
// delegation-cut deadline.
//
// A sub-query's answer is cached under its own key, so it must be bounded by
// its own lineage and not by whatever asked for it: a nearly expired alias
// would otherwise store a freshly resolved target with seconds of life. The
// deriving request still inherits the sub-query's bound, by folding the fork's
// deadline back in once the sub-query has returned — the composed answer does
// contain the sub-query's records.
func (m *ResponseMeta) ForkCut() *ResponseMeta {
	if m == nil {
		return nil
	}
	// Established here rather than read: a fork is the moment the tree needs
	// a stable host, and a child that captured a nil one would build its own
	// and record where the tree cannot see it.
	child := &ResponseMeta{workPolicy: m.workPolicy}
	child.ledgers.Store(m.ensureLedgerHost())
	return child
}

// (*ResponseMeta).BoundCut folds a delegation-cut deadline into the
// meta, keeping the earliest. Nil-safe and zero-ignoring so resolver
// call sites can invoke it unconditionally.
func (m *ResponseMeta) BoundCut(deadline time.Time) {
	m.BoundCutFor(deadline, 0)
}

// BoundCutFor folds a delegation-cut deadline and its cache identity into the
// response metadata. The identity travels with the winning (earliest)
// deadline as one immutable atomic value, ready for the optional generation
// checks described by the Ghost/Phoenix durable design.
func (m *ResponseMeta) BoundCutFor(deadline time.Time, key uint64) {
	if m == nil || deadline.IsZero() {
		return
	}

	m.cutMu.Lock()
	if m.cut.deadline.IsZero() || deadline.Before(m.cut.deadline) {
		m.cut = responseCut{deadline: deadline, key: key}
	}
	m.cutMu.Unlock()
}

// Cut returns the earliest delegation-cut deadline observed for the request
// tree and the delegation-cache key that supplied it. A zero deadline means
// unbounded; in that case the key is also zero.
func (m *ResponseMeta) Cut() (time.Time, uint64) {
	if m == nil {
		return time.Time{}, 0
	}
	m.cutMu.Lock()
	deadline, key := m.cut.deadline, m.cut.key
	m.cutMu.Unlock()
	return deadline, key
}

// CutUntil returns the earliest delegation-cut deadline observed for the
// request tree. Zero means unbounded.
func (m *ResponseMeta) CutUntil() time.Time {
	deadline, _ := m.Cut()
	return deadline
}

// CutKey returns the delegation-cache key associated with CutUntil. It is
// meaningful only when CutUntil is non-zero.
func (m *ResponseMeta) CutKey() uint64 {
	_, key := m.Cut()
	return key
}

// Reset clears request metadata before a pooled Chain is reused.
// Store(nil) is safe even if the ResponseMeta has previously been used; do
// not replace the struct by assignment because atomic values must not be
// copied after first use.
func (m *ResponseMeta) Reset() {
	if m != nil {
		m.cutMu.Lock()
		m.cut = responseCut{}
		m.cutMu.Unlock()
		// Dropping the reference is the whole of it: the next request gets a
		// new one on first use, and anything still holding this one — a
		// resolver goroutine outliving the pooled Chain, a sub-query's fork —
		// keeps the request it belongs to rather than following this struct
		// into the next.
		m.ledgers.Store(nil)
	}
}

// MarkCachedFailureResponse marks msg as a response currently being emitted
// from the RFC 9520 failure cache and returns an idempotent release function.
// Callers must keep the mark only around the synchronous WriteMsg call.
func (m *ResponseMeta) MarkCachedFailureResponse(msg *dns.Msg) func() {
	if m == nil || msg == nil {
		return func() {}
	}

	host := m.ensureLedgerHost()
	markers := host.cachedFailures.Load()
	if markers == nil {
		candidate := &cachedFailureResponseSet{messages: make(map[*dns.Msg]uint32)}
		if host.cachedFailures.CompareAndSwap(nil, candidate) {
			markers = candidate
		} else {
			markers = host.cachedFailures.Load()
		}
	}

	markers.mu.Lock()
	markers.messages[msg]++
	markers.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			markers.mu.Lock()
			switch markers.messages[msg] {
			case 0, 1:
				delete(markers.messages, msg)
			default:
				markers.messages[msg]--
			}
			markers.mu.Unlock()
		})
	}
}

// IsCachedFailureResponse reports whether msg is the exact response currently
// being emitted from the RFC 9520 failure cache for this request tree.
func (m *ResponseMeta) IsCachedFailureResponse(msg *dns.Msg) bool {
	if m == nil || msg == nil {
		return false
	}
	host := m.ledgerHost()
	if host == nil {
		return false
	}
	markers := host.cachedFailures.Load()
	if markers == nil {
		return false
	}

	markers.mu.RLock()
	marked := markers.messages[msg] > 0
	markers.mu.RUnlock()
	return marked
}

func (m *ResponseMeta) markValidatedNegativeProofResponse(
	msg, proof *dns.Msg,
	negative ValidatedNegativeProof,
) bool {
	if m == nil || msg == nil || proof == nil ||
		msg.Rcode != proof.Rcode ||
		(proof.Rcode != dns.RcodeNameError &&
			(proof.Rcode != dns.RcodeSuccess || len(proof.Answer) != 0)) ||
		negative.Subject == "" || negative.Zone == "" {
		return false
	}
	fingerprint, ok := validatedNegativeProofFingerprint(proof)
	if !ok {
		return false
	}

	// Store canonical values so later consumers can use the provenance as a
	// stable DNS identity without depending on a caller's presentation case.
	negative.Subject = dns.CanonicalName(negative.Subject)
	negative.Zone = dns.CanonicalName(negative.Zone)
	negative.Proof = proof

	host := m.ensureLedgerHost()
	negatives := host.validatedNegativeProofs.Load()
	if negatives == nil {
		candidate := &validatedNegativeProofResponseSet{
			messages: make(map[*dns.Msg]validatedNegativeProofRecord),
		}
		if host.validatedNegativeProofs.CompareAndSwap(nil, candidate) {
			negatives = candidate
		} else {
			negatives = host.validatedNegativeProofs.Load()
		}
	}

	negatives.mu.Lock()
	existingRecord, exists := negatives.messages[msg]
	existing := existingRecord.negative
	if !exists {
		negatives.messages[msg] = validatedNegativeProofRecord{
			negative:    negative,
			fingerprint: fingerprint,
		}
	} else if existing.Kind == ValidatedNegativeProofUnknown &&
		negative.Kind != ValidatedNegativeProofUnknown &&
		existing.Subject == negative.Subject &&
		existing.Zone == negative.Zone &&
		existing.Proof == negative.Proof &&
		existingRecord.fingerprint == fingerprint {
		// Source-compatible legacy callers can mark NXDOMAIN before a newer
		// resolver supplies the explicit proof family. Permit only this
		// monotonic Unknown→typed refinement; subject, signer, and exact proof
		// identity remain immutable.
		negatives.messages[msg] = validatedNegativeProofRecord{
			negative:    negative,
			fingerprint: fingerprint,
		}
		existing = negative
	}
	negatives.mu.Unlock()
	return !exists || existing == negative
}

func (m *ResponseMeta) validatedNegativeProofForResponse(
	msg *dns.Msg,
) (ValidatedNegativeProof, bool) {
	if m == nil || msg == nil {
		return ValidatedNegativeProof{}, false
	}
	host := m.ledgerHost()
	if host == nil {
		return ValidatedNegativeProof{}, false
	}
	negatives := host.validatedNegativeProofs.Load()
	if negatives == nil {
		return ValidatedNegativeProof{}, false
	}

	negatives.mu.RLock()
	record, ok := negatives.messages[msg]
	negatives.mu.RUnlock()
	if !ok || record.negative.Proof == nil ||
		msg.Rcode != record.negative.Proof.Rcode ||
		(record.negative.Proof.Rcode != dns.RcodeNameError &&
			(record.negative.Proof.Rcode != dns.RcodeSuccess ||
				len(record.negative.Proof.Answer) != 0)) {
		return ValidatedNegativeProof{}, false
	}
	fingerprint, valid := validatedNegativeProofFingerprint(record.negative.Proof)
	if !valid || fingerprint != record.fingerprint {
		return ValidatedNegativeProof{}, false
	}
	return record.negative, true
}

// validatedNegativeProofFingerprint seals the locally validated proof
// material against in-place downstream mutation while preserving exact
// response identity. Header fields that response writers legitimately reshape
// (ID, RD/RA/AD, EDNS) and the presentation Question are intentionally outside
// the seal; RCODE and the complete authority section are inside it. The
// terminal Answer shape is checked separately above.
func validatedNegativeProofFingerprint(proof *dns.Msg) ([sha256.Size]byte, bool) {
	if proof == nil {
		return [sha256.Size]byte{}, false
	}
	sealed := new(dns.Msg)
	sealed.Rcode = proof.Rcode
	sealed.Ns = proof.Ns

	// The packed form exists only to be hashed, so it is hashed where it
	// lies — in the packer's pooled buffer — instead of allocated, summed
	// and dropped. An authority section the pooled buffer cannot hold takes
	// the library, exactly as before.
	var sum [sha256.Size]byte
	handled, err := wire.TryPack(sealed, func(body []byte) error {
		sum = sha256.Sum256(body)
		return nil
	})
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	if !handled {
		packed, packErr := sealed.Pack()
		if packErr != nil {
			return [sha256.Size]byte{}, false
		}
		sum = sha256.Sum256(packed)
	}
	return sum, true
}

// EnsureResolutionAttemptGuard returns the request tree's retry guard,
// installing one on first use.
func (m *ResponseMeta) EnsureResolutionAttemptGuard() *ResolutionAttemptGuard {
	if m == nil {
		return nil
	}
	host := m.ensureLedgerHost()
	return &host.guard
}

// ResolutionAttemptGuard returns the request tree's retry guard, if present.
func (m *ResponseMeta) ResolutionAttemptGuard() *ResolutionAttemptGuard {
	host := m.ledgerHost()
	if host == nil {
		return nil
	}
	return &host.guard
}

// ensureRecursionWork returns the request tree's ledger, installing one with
// policy when this is the first recursive work in the tree. Creation stays
// behind the context-aware EnsureRecursionWork API so a lazy request owner's
// completion tombstone can linearize against the first install.
func (m *ResponseMeta) ensureRecursionWork(policy RecursionWorkPolicy) *RecursionWorkLedger {
	if m == nil {
		return nil
	}
	if m.workPolicy.Enabled() {
		policy = m.workPolicy
	}
	if !policy.Enabled() {
		return nil
	}
	host := m.ensureLedgerHost()
	if ledger := host.work.Load(); ledger != nil {
		return ledger
	}

	ledger := NewRecursionWorkLedger(policy)
	if host.work.CompareAndSwap(nil, ledger) {
		return ledger
	}
	return host.work.Load()
}

// RecursionWork returns the request tree's ledger, if accounting is active.
func (m *ResponseMeta) RecursionWork() *RecursionWorkLedger {
	host := m.ledgerHost()
	if host == nil {
		return nil
	}
	return host.work.Load()
}

// responseMetaKey tags ctx with the active *ResponseMeta. Sentinel
// pointer keeps ctx.Value comparisons alloc-free.
type responseMetaKeyType struct{}

var responseMetaKey = &responseMetaKeyType{}

// WithResponseMeta returns a derived ctx carrying m as the request
// tree's response metadata sink.
func WithResponseMeta(ctx context.Context, m *ResponseMeta) context.Context {
	return context.WithValue(ctx, responseMetaKey, m)
}

// forkedCutContext carries a sub-query's meta inside the context value itself.
// Forking a meta and then wrapping the context in a value node is two
// allocations on a path that runs once per chase hop; holding the meta here
// makes it one.
type forkedCutContext struct {
	context.Context
	meta ResponseMeta
	// guard is the request tree's retry guard, carried here because the
	// first thing a sub-query does is pin it: a scope that did not offer it
	// would be followed immediately by another context wrapper holding the
	// same value.
	guard *ResolutionAttemptGuard
}

func (c *forkedCutContext) Value(key any) any {
	switch key {
	case responseMetaKey:
		return &c.meta
	case resolutionAttemptContextKey:
		if c.guard != nil {
			return c.guard
		}
	}
	return c.Context.Value(key)
}

// WithForkedCut returns ctx carrying a meta that keeps its own
// delegation-cut deadline while sharing the request tree's state, and that
// meta. See ForkCut for what the separation is for.
//
// The returned meta is nil, and ctx unchanged, when ctx carries no meta to
// fork from — a caller with nothing to separate needs no scope.
func WithForkedCut(ctx context.Context) (context.Context, *ResponseMeta) {
	parent := ResponseMetaFrom(ctx)
	if parent == nil {
		return ctx, nil
	}
	host := parent.ensureLedgerHost()

	// The tree's own guard, unless one is already anchored — a detached or
	// custom context can carry a guard this meta does not own, and shadowing
	// it would silently move that sub-query's accounting somewhere else. The
	// anchor is read through the same selection helper as every other guard
	// consumer, so a pinned anchor counts too.
	guard := &host.guard
	if anchored := resolutionAttemptGuardAnchored(ctx); anchored != nil {
		guard = anchored
	}

	forked := &forkedCutContext{Context: ctx, guard: guard}
	forked.meta.ledgers.Store(host)
	forked.meta.workPolicy = parent.workPolicy
	return forked, &forked.meta
}

func withResponseMeta(ctx context.Context, m *ResponseMeta) (context.Context, bool) {
	if contextutil.TrySetValueProvider(ctx, m) {
		return ctx, true
	}
	return context.WithValue(ctx, responseMetaKey, m), false
}

// ContextValue lets the root Chain expose its pooled ResponseMeta through a
// dedicated lazy server request context without another context.WithValue
// allocation. Exported WithResponseMeta retains normal derived-context
// isolation.
func (m *ResponseMeta) ContextValue(key any) (any, bool) {
	if key == responseMetaKey {
		return m, true
	}
	return nil, false
}

// ResponseMetaFrom returns the ctx's response metadata sink, or nil
// when none was established (background/priming work).
func ResponseMetaFrom(ctx context.Context) *ResponseMeta {
	m, _ := ctx.Value(responseMetaKey).(*ResponseMeta)
	return m
}

// MarkValidatedDenialResponse attaches explicit, resolver-local validation
// provenance to an exact NXDOMAIN response. It intentionally does not inspect
// or trust the response's AD bit.
func MarkValidatedDenialResponse(ctx context.Context, msg *dns.Msg, denial ValidatedDenial) {
	if meta := ResponseMetaFrom(ctx); meta != nil {
		_ = meta.markValidatedNegativeProofResponse(msg, msg, ValidatedNegativeProof{
			Subject: denial.DeniedName,
			Zone:    denial.Zone,
			Kind:    ValidatedNegativeProofUnknown,
		})
	}
}

// ValidatedDenialForResponse returns resolver-local validation provenance for
// this exact NXDOMAIN response. A copied or independently constructed message
// never inherits the mark.
func ValidatedDenialForResponse(ctx context.Context, msg *dns.Msg) (ValidatedDenial, bool) {
	if meta := ResponseMetaFrom(ctx); meta != nil {
		negative, ok := meta.validatedNegativeProofForResponse(msg)
		if ok && msg != nil && msg.Rcode == dns.RcodeNameError &&
			negative.Proof != nil && negative.Proof.Rcode == dns.RcodeNameError {
			return ValidatedDenial{
				DeniedName: negative.Subject,
				Zone:       negative.Zone,
				Proof:      negative.Proof,
			}, true
		}
	}
	return ValidatedDenial{}, false
}

// MarkValidatedNegativeProofResponse attaches explicit resolver-local
// validation provenance to an exact NXDOMAIN or terminal NODATA response. The
// caller-supplied Proof pointer is intentionally ignored: a fresh mark always
// originates at msg, and only explicit propagation may retain an older
// terminal proof identity.
func MarkValidatedNegativeProofResponse(
	ctx context.Context,
	msg *dns.Msg,
	negative ValidatedNegativeProof,
) {
	if negative.Kind != ValidatedNegativeProofNSEC &&
		negative.Kind != ValidatedNegativeProofNSEC3 {
		return
	}
	if meta := ResponseMetaFrom(ctx); meta != nil {
		_ = meta.markValidatedNegativeProofResponse(msg, msg, negative)
	}
}

// ValidatedNegativeProofForResponse returns resolver-local validation
// provenance for this exact NXDOMAIN or NODATA response. AD alone, a message
// copy, or an independently produced negative response never inherits it.
func ValidatedNegativeProofForResponse(
	ctx context.Context,
	msg *dns.Msg,
) (ValidatedNegativeProof, bool) {
	if meta := ResponseMetaFrom(ctx); meta != nil {
		return meta.validatedNegativeProofForResponse(msg)
	}
	return ValidatedNegativeProof{}, false
}

// PropagateValidatedDenialResponse copies exact-response provenance from one
// NXDOMAIN response identity to another. This is the only supported way for a
// middleware that replaces a response object to preserve validated denial
// metadata; ordinary dns.Msg copying does not do so.
func PropagateValidatedDenialResponse(ctx context.Context, from, to *dns.Msg) bool {
	negative, ok := ValidatedNegativeProofForResponse(ctx, from)
	if !ok || to == nil || to.Rcode != dns.RcodeNameError {
		return false
	}
	meta := ResponseMetaFrom(ctx)
	if meta == nil {
		return false
	}
	return meta.markValidatedNegativeProofResponse(to, negative.Proof, negative)
}

// PropagateValidatedNegativeProofResponse preserves the exact terminal proof
// when a middleware builds a replacement negative response (for example an
// outer CNAME/DNAME response). Ordinary dns.Msg copying is deliberately not a
// trust-propagation operation.
func PropagateValidatedNegativeProofResponse(ctx context.Context, from, to *dns.Msg) bool {
	negative, ok := ValidatedNegativeProofForResponse(ctx, from)
	if !ok || to == nil || to.Rcode != from.Rcode {
		return false
	}
	meta := ResponseMetaFrom(ctx)
	if meta == nil {
		return false
	}
	return meta.markValidatedNegativeProofResponse(to, negative.Proof, negative)
}

// Chain carries per-request state through the middleware pipeline.
// Instances are reused via a sync.Pool: NewChain allocates the fixed
// pipeline reference, Reset rebinds the per-request writer + request.
type Chain struct {
	Writer  ResponseWriter
	Request *Request

	// reqStorage backs message-born requests (Reset) so rebinding a pooled
	// chain allocates nothing. Wire-born requests (ResetWire) live in
	// transport-job storage instead.
	reqStorage Request

	// Meta is the pooled backing storage for the request's
	// ResponseMeta. The first middleware that needs a meta sink and
	// finds none in ctx establishes &Meta via WithResponseMeta;
	// nested pipelines then reuse the ctx pointer rather than their
	// own chain's field.
	Meta ResponseMeta

	handlers []Handler
	pos      int // index of the next handler to run
	count    int // handlers remaining; goes to 0 on Cancel

	workPolicy RecursionWorkPolicy

	// detachCleanup closes a wire-born request's post-materialization
	// lifecycle — the recursion-work completion boundary and the detached
	// lazy deadline. Established by Materialize, run exactly once after the
	// serve completes (PutChain, or the next rebind as a backstop).
	detachCleanup func()
}

// NewChain returns a Chain bound to the given handler pipeline. The slice
// is captured by reference and must not be mutated by the caller after
// this call.
func NewChain(handlers []Handler) *Chain {
	return newChain(handlers, RecursionWorkPolicy{})
}

func newChain(handlers []Handler, workPolicy RecursionWorkPolicy) *Chain {
	ch := &Chain{
		Writer:     &responseWriter{},
		handlers:   handlers,
		count:      len(handlers),
		workPolicy: workPolicy,
	}
	ch.Meta.workPolicy = workPolicy
	return ch
}

// Next invokes the next handler in the chain. Each handler is responsible
// for calling Next to continue, or Cancel/CancelWithRcode to stop.
func (ch *Chain) Next(ctx context.Context) {
	if ch.count == 0 {
		return
	}

	// The first chain in a client request owns ResponseMeta and the work
	// ledger's completion boundary. Nested Queryer pipelines inherit both
	// pointers, so retries and child lookups cannot reset their budgets.
	if ch.pos == 0 {
		// While the request is wire-born and undecoded the recursion-work
		// owner is deliberately NOT established here: a served hit performs
		// no recursive work, and the ledger lifecycle for a miss begins
		// whole on the detached context at materialization — never split
		// between the recycled job carrier and a later context.
		wireOnly := ch.Request != nil && ch.Request.decoded() == nil
		meta := ResponseMetaFrom(ctx)
		ownsMeta := meta == nil
		lazyOwner := false
		if meta == nil {
			meta = &ch.Meta
			var lazyMeta bool
			ctx, lazyMeta = withResponseMeta(ctx, meta)
			if !wireOnly && lazyMeta && beginLazyRecursionWorkOwner(ctx) {
				lazyOwner = true
				// The server request context owns exact request-lifetime
				// state. Delay ledger creation until real recursive work and
				// close the pin before pooled metadata can be reused.
				defer func() {
					if finished := finishLazyRecursionWork(ctx, meta); finished != nil {
						logRecursionWorkExhaustion(finished, ch.Request.Msg())
					}
				}()
			}
		}
		if !wireOnly && ch.workPolicy.Enabled() {
			switch {
			case ownsMeta && lazyOwner:
				// The deferred owner above publishes a ledger only if work
				// later materializes one.
			case !ownsMeta && RecursionWorkRootOwned(ctx) && meta.workPolicy.Enabled():
				// A nested pipeline inherits an active outer policy and
				// completion boundary without materializing it early.
			default:
				hadLedger := RecursionWorkFrom(ctx) != nil
				var ledger *RecursionWorkLedger
				ctx, ledger = EnsureRecursionWork(ctx, ch.workPolicy)
				if !hadLedger && ledger != nil {
					defer func() {
						ledger.finish()
						logRecursionWorkExhaustion(ledger, ch.Request.Msg())
					}()
				}
			}
		}
	}

	h := ch.handlers[ch.pos]
	ch.pos++
	ch.count--

	// A wire-born request that decoded through Request.Msg carries no
	// detached context yet: the handler that decoded it may still be
	// holding the job carrier. Downstream handlers must not — the carrier
	// is recycled with the job and cannot host request-tree state — so the
	// transition completes here, once, before the next handler runs.
	// Chain.Materialize callers already own theirs and skip this.
	if ch.detachCleanup == nil && ch.Request != nil &&
		ch.Request.decoded() != nil && ch.Request.wireBorn() {
		ctx, ch.detachCleanup = ch.detachStrictContext(ctx)
	}

	h.ServeDNS(ctx, ch)
}

// Materialize returns the decoded request, decoding a wire-born request on
// first call. That first decode is the one-way transition off the strict
// path: the remaining handlers must run on the returned context — a fresh
// lazy deadline parented on a stable context (never the recycled job
// carrier), carrying the ECS marker, the same ResponseMeta, and a fresh
// recursion-work completion boundary whose lifecycle the chain closes when
// the serve completes. A nil message means the packet failed decoding; the
// chain is canceled and the caller must stop without calling Next.
func (ch *Chain) Materialize(ctx context.Context) (context.Context, *dns.Msg) {
	// decoded, not Msg: the probe must not be the thing that decodes, or
	// the transition below would be skipped for the request it just built.
	if ch.Request == nil {
		return ctx, nil
	}
	m := ch.Request.decoded()
	if m == nil {
		if m = ch.Request.materialize(); m == nil {
			ch.Cancel()
			return ctx, nil
		}
	}
	// A request decoded earlier through Request.Msg reaches here without a
	// detached context; it gets one now, so the caller's own downstream
	// work never rides the job carrier either.
	if ch.detachCleanup == nil && ch.Request.wireBorn() {
		ctx, ch.detachCleanup = ch.detachStrictContext(ctx)
	}
	return ctx, m
}

// finishDetach runs a pending strict-detach cleanup exactly once.
func (ch *Chain) finishDetach() {
	if ch.detachCleanup != nil {
		ch.detachCleanup()
		ch.detachCleanup = nil
	}
}

// Cancel stops the chain without writing a response. Subsequent Next
// calls become no-ops.
func (ch *Chain) Cancel() {
	ch.count = 0
}

// CancelWithRcode writes a reply with the given rcode and stops the
// chain. do controls the DO bit in the response's OPT record.
func (ch *Chain) CancelWithRcode(rcode int, do bool) {
	req := ch.Request.Msg()
	if req == nil {
		// The rcode reply needs the decoded form, but it is terminal — no
		// handler runs after it — so no detached context is established.
		if req = ch.Request.materialize(); req == nil {
			ch.count = 0
			return
		}
	}
	m := new(dns.Msg)
	m.Extra = req.Extra
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	m.RecursionDesired = true

	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(do)
	}

	_ = ch.Writer.WriteMsg(m)
	ch.count = 0
}

// Reset rebinds the chain to a fresh writer + decoded request for pool
// reuse. The internal sub-pipeline, DoH/DoQ and embedders enter here; the
// server's raw ingress enters through ResetWire.
func (ch *Chain) Reset(w Transport, r *dns.Msg) {
	ch.finishDetach()
	ch.rebindWriter(w)
	ch.reqStorage.SetMsg(r)
	ch.Request = &ch.reqStorage
	ch.Meta.Reset()
	ch.pos = 0
	ch.count = len(ch.handlers)
}

// rebindWriter points the chain's pooled base writer at the next
// transport. A chain whose Writer was replaced by a custom implementation
// (tests do this) gets a fresh base writer rather than a silent no-op on
// the foreign one.
func (ch *Chain) rebindWriter(w Transport) {
	base, ok := ch.Writer.(*responseWriter)
	if !ok {
		base = &responseWriter{}
		ch.Writer = base
	}
	base.Reset(w)
}

// ResetWire rebinds the chain to a wire-born request living in transport
// job storage. No decoded message exists until a handler materializes one.
func (ch *Chain) ResetWire(w Transport, r *Request) {
	ch.finishDetach()
	ch.rebindWriter(w)
	ch.Request = r
	ch.Meta.Reset()
	ch.pos = 0
	ch.count = len(ch.handlers)
}

// AllowDirectPack declares that the transport beneath this chain's writer is
// an SDNS-owned UDP, TCP or DoT sink whose Write sends raw wire bytes
// unchanged, so WriteMsg may pack in pooled storage and skip the library's
// per-message allocations.
//
// It is a declaration with one intended caller — the server's owned-listener
// ingress, immediately after Reset — never an inference from address types
// or proto strings, which plugin writers can share without sharing the
// byte-sink property. Reset clears it, so a pooled chain cannot carry the
// capability to the next request. A chain whose writer was replaced by a
// custom ResponseWriter implementation is left alone.
func (ch *Chain) AllowDirectPack() {
	if w, ok := ch.Writer.(*responseWriter); ok {
		w.directPack = true
	}
}

// detachStrictContext builds the context the post-materialization chain
// runs on: a fresh lazy deadline parented on a stable context — never the
// recycled job carrier — carrying the deadline as a scalar copy, the ECS
// marker re-pinned, the same ResponseMeta re-provided, and a fresh
// recursion-work completion boundary. The returned cleanup runs once the
// serve completes: it closes the work ledger's lifecycle and releases the
// deadline context, mirroring what the chain entry does for ordinary
// requests at pos==0.
func (ch *Chain) detachStrictContext(ctx context.Context) (context.Context, func()) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	real := contextutil.WithLazyDeadline(context.Background(), deadline)
	var detached context.Context = real
	if HasClientECS(ctx) {
		detached = MarkClientECS(detached)
	}

	cleanup := func() { real.Cancel() }
	if meta := ResponseMetaFrom(ctx); meta != nil {
		var lazyMeta bool
		detached, lazyMeta = withResponseMeta(detached, meta)
		if lazyMeta && beginLazyRecursionWorkOwner(detached) {
			captured := detached
			cleanup = func() {
				if finished := finishLazyRecursionWork(captured, meta); finished != nil {
					logRecursionWorkExhaustion(finished, ch.Request.Msg())
				}
				real.Cancel()
			}
		}
	}
	return detached, cleanup
}
