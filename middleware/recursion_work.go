package middleware

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/metric"
)

// RecursionWorkMode controls whether request-tree work limits are disabled,
// observed without changing behaviour, or enforced.
type RecursionWorkMode uint8

const (
	RecursionWorkOff RecursionWorkMode = iota
	RecursionWorkShadow
	RecursionWorkEnforce
)

// RecursionWorkKind identifies a separately bounded kind of recursive work.
type RecursionWorkKind uint8

const (
	RecursionWorkOutboundQuery RecursionWorkKind = iota
	RecursionWorkInternalQuery
	RecursionWorkDNSKEYCandidate
	RecursionWorkRRsetSignature
	RecursionWorkSignature
	RecursionWorkDSDigest
	RecursionWorkNSEC3Hash
	RecursionWorkConcurrentCrypto
)

func (k RecursionWorkKind) isDNSSEC() bool {
	switch k {
	case RecursionWorkDNSKEYCandidate,
		RecursionWorkRRsetSignature,
		RecursionWorkSignature,
		RecursionWorkDSDigest,
		RecursionWorkNSEC3Hash,
		RecursionWorkConcurrentCrypto:
		return true
	default:
		return false
	}
}

const (
	// RecursionWorkEDEText is deliberately stable because it is returned to
	// clients as RFC 8914 Extended DNS Error text in enforce mode.
	RecursionWorkEDEText = "Recursion work budget exceeded"

	// RecursionWorkEDECode deliberately uses RFC 8914's finalized catch-all
	// code. The more specific "Unable to Conform to Policy" registry entry
	// still references an Internet-Draft, so it is not part of this wire
	// contract.
	RecursionWorkEDECode = dns.ExtendedErrorCodeOther

	// DNSSECWorkEDEText and DNSSECWorkEDECode distinguish validation-work
	// exhaustion from network fan-out on the wire.
	DNSSECWorkEDEText = "DNSSEC validation work budget exceeded"
	DNSSECWorkEDECode = dns.ExtendedErrorCodeDNSSECIndeterminate
)

const (
	outboundExhausted uint32 = 1 << iota
	internalExhausted
	dnskeyCandidateExhausted
	rrsetSignatureExhausted
	signatureExhausted
	dsDigestExhausted
	nsec3HashExhausted
	concurrentCryptoExhausted
)

// ErrRecursionWorkLimit is the sentinel carried by a
// RecursionWorkLimitError.
var ErrRecursionWorkLimit = errors.New("recursion work limit exceeded")

// RecursionWorkPolicy is immutable after a ledger is created.
type RecursionWorkPolicy struct {
	Mode                    RecursionWorkMode
	MaxOutboundQueries      uint32
	MaxInternalQueries      uint32
	MaxDNSKEYCandidates     uint32
	MaxRRsetSignatureChecks uint32
	MaxSignatureChecks      uint32
	MaxDSDigests            uint32
	MaxNSEC3Hashes          uint32
	MaxConcurrentCrypto     uint32
}

// Enabled reports whether the policy should create and account a ledger.
func (p RecursionWorkPolicy) Enabled() bool {
	return p.Mode == RecursionWorkShadow || p.Mode == RecursionWorkEnforce
}

// RecursionWorkLimitError reports which dimension rejected more work.
// Error deliberately remains stable on the wire; Kind and Limit are
// available to logs and tests without leaking policy details to clients.
type RecursionWorkLimitError struct {
	Kind  RecursionWorkKind
	Limit uint32
}

func (e *RecursionWorkLimitError) Error() string {
	if e != nil && e.Kind.isDNSSEC() {
		return DNSSECWorkEDEText
	}
	return RecursionWorkEDEText
}

func (e *RecursionWorkLimitError) Unwrap() error { return ErrRecursionWorkLimit }

// EDECode maps network-work enforcement to RFC 8914's finalized catch-all
// code and DNSSEC-work enforcement to DNSSEC Indeterminate.
func (e *RecursionWorkLimitError) EDECode() uint16 {
	if e != nil && e.Kind.isDNSSEC() {
		return DNSSECWorkEDECode
	}
	return RecursionWorkEDECode
}

// RecursionWorkSnapshot is a race-safe point-in-time ledger view.
type RecursionWorkSnapshot struct {
	Mode                          RecursionWorkMode
	OutboundQueries               uint32
	InternalQueries               uint32
	SignatureChecks               uint32
	DSDigests                     uint32
	NSEC3Hashes                   uint32
	OutboundExhausted             bool
	InternalExhausted             bool
	DNSKEYCandidatesExhausted     bool
	RRsetSignatureChecksExhausted bool
	SignatureChecksExhausted      bool
	DSDigestsExhausted            bool
	NSEC3HashesExhausted          bool
	ConcurrentCryptoExhausted     bool
	MaxOutboundQueries            uint32
	MaxInternalQueries            uint32
	MaxDNSKEYCandidates           uint32
	MaxRRsetSignatureChecks       uint32
	MaxSignatureChecks            uint32
	MaxDSDigests                  uint32
	MaxNSEC3Hashes                uint32
	MaxConcurrentCrypto           uint32
}

// RecursionWorkLedger aggregates work across one complete recursive request
// tree. It owns no timer: the existing request context deadline remains the
// single authoritative time budget.
type recursionWorkLedgerState uint32

const (
	recursionWorkLedgerLive recursionWorkLedgerState = iota
	recursionWorkLedgerRootDone
	recursionWorkLedgerPending
	recursionWorkLedgerClosed
)

type RecursionWorkLedger struct {
	policy RecursionWorkPolicy

	outbound    atomic.Uint32
	internal    atomic.Uint32
	signatures  atomic.Uint32
	dsDigests   atomic.Uint32
	nsec3Hashes atomic.Uint32
	exhausted   atomic.Uint32
	first       atomic.Uint32
	refs        atomic.Int64
	// rootState packs root completion and immutable pending/closed control
	// states into the existing atomic word. This keeps a live ledger in the
	// 80-byte allocator class instead of adding a separate lifecycle field.
	rootState atomic.Uint32
	finished  atomic.Bool
}

// NewRecursionWorkLedger constructs a ledger for policy. Callers normally use
// EnsureRecursionWork so every nested pipeline shares the ResponseMeta-owned
// instance.
func NewRecursionWorkLedger(policy RecursionWorkPolicy) *RecursionWorkLedger {
	ledger := &RecursionWorkLedger{policy: policy}
	ledger.refs.Store(1)
	return ledger
}

func (l *RecursionWorkLedger) controlError() (error, bool) {
	if l == nil {
		return nil, false
	}
	switch l.lifecycleState() {
	case recursionWorkLedgerLive, recursionWorkLedgerRootDone:
		return nil, false
	case recursionWorkLedgerClosed:
		return context.Canceled, true
	default:
		return nil, true
	}
}

func (l *RecursionWorkLedger) isLive() bool {
	if l == nil {
		return false
	}
	state := l.lifecycleState()
	return state == recursionWorkLedgerLive || state == recursionWorkLedgerRootDone
}

func (l *RecursionWorkLedger) lifecycleState() recursionWorkLedgerState {
	return recursionWorkLedgerState(l.rootState.Load())
}

// Debit reserves one unit of kind. Shadow mode records crossings but always
// permits work. Enforce mode never lets an accepted counter exceed its cap and
// records the rejection as terminal provenance for the request tree. Work is
// never refunded: failed, cancelled, and losing attempts consumed the resource
// they started.
func (l *RecursionWorkLedger) Debit(kind RecursionWorkKind) error {
	return l.debit(kind, true)
}

// DebitBestEffort reserves work for an optional branch. It shares the same
// counters and returns the same limit error to stop that branch, but a rejected
// debit does not make an otherwise successful request fail later via
// EnforcementError. Exhaustion remains visible in the tree snapshot and
// metrics.
func (l *RecursionWorkLedger) DebitBestEffort(kind RecursionWorkKind) error {
	return l.debit(kind, false)
}

func (l *RecursionWorkLedger) debit(kind RecursionWorkKind, latchRejection bool) error {
	if err, control := l.controlError(); control {
		return err
	}
	if l == nil || !l.policy.Enabled() {
		return nil
	}

	counter, limit, bit, ok := l.aggregateDimension(kind)
	if !ok {
		panic("middleware: aggregate Debit called with local recursion-work kind")
	}
	if l.policy.Mode == RecursionWorkShadow {
		// Exactly one goroutine observes the crossing, so work beyond the
		// limit does not repeat the atomic exhaustion update.
		if counter.Add(1) == limit+1 {
			l.markExhausted(kind, bit, false)
		}
		return nil
	}

	for {
		used := counter.Load()
		if used >= limit {
			l.markExhausted(kind, bit, latchRejection)
			return &RecursionWorkLimitError{Kind: kind, Limit: limit}
		}
		if counter.CompareAndSwap(used, used+1) {
			return nil
		}
	}
}

// CheckLocal checks a per-validation-object limit before the next item is
// examined. used is the number of items already examined: values below the
// limit are allowed, while used == limit is the first crossing. Local limits
// do not add to graph-wide counters.
func (l *RecursionWorkLedger) CheckLocal(kind RecursionWorkKind, used uint32) error {
	return l.checkLocal(kind, used, true)
}

// Reject records a governor failure that has no accepted-work counter, such
// as timing out while waiting for the resolver-wide crypto semaphore.
func (l *RecursionWorkLedger) Reject(kind RecursionWorkKind) error {
	return l.reject(kind, true)
}

func (l *RecursionWorkLedger) reject(kind RecursionWorkKind, latchRejection bool) error {
	if err, control := l.controlError(); control {
		return err
	}
	if l == nil || !l.policy.Enabled() {
		return nil
	}
	limit, bit, ok := l.localDimension(kind)
	if !ok {
		panic("middleware: Reject called with aggregate recursion-work kind")
	}
	l.markExhausted(kind, bit, l.policy.Mode == RecursionWorkEnforce && latchRejection)
	if l.policy.Mode == RecursionWorkShadow {
		return nil
	}
	return &RecursionWorkLimitError{Kind: kind, Limit: limit}
}

func (l *RecursionWorkLedger) checkLocal(kind RecursionWorkKind, used uint32, latchRejection bool) error {
	if err, control := l.controlError(); control {
		return err
	}
	if l == nil || !l.policy.Enabled() {
		return nil
	}

	limit, bit, ok := l.localDimension(kind)
	if !ok {
		panic("middleware: CheckLocal called with aggregate recursion-work kind")
	}
	if used < limit {
		return nil
	}

	if l.policy.Mode == RecursionWorkShadow {
		if used == limit {
			l.markExhausted(kind, bit, false)
		}
		return nil
	}
	l.markExhausted(kind, bit, latchRejection)
	return &RecursionWorkLimitError{Kind: kind, Limit: limit}
}

func (l *RecursionWorkLedger) aggregateDimension(kind RecursionWorkKind) (*atomic.Uint32, uint32, uint32, bool) {
	switch kind {
	case RecursionWorkOutboundQuery:
		return &l.outbound, l.policy.MaxOutboundQueries, outboundExhausted, true
	case RecursionWorkInternalQuery:
		return &l.internal, l.policy.MaxInternalQueries, internalExhausted, true
	case RecursionWorkSignature:
		return &l.signatures, l.policy.MaxSignatureChecks, signatureExhausted, true
	case RecursionWorkDSDigest:
		return &l.dsDigests, l.policy.MaxDSDigests, dsDigestExhausted, true
	case RecursionWorkNSEC3Hash:
		return &l.nsec3Hashes, l.policy.MaxNSEC3Hashes, nsec3HashExhausted, true
	default:
		return nil, 0, 0, false
	}
}

func (l *RecursionWorkLedger) localDimension(kind RecursionWorkKind) (uint32, uint32, bool) {
	switch kind {
	case RecursionWorkDNSKEYCandidate:
		return l.policy.MaxDNSKEYCandidates, dnskeyCandidateExhausted, true
	case RecursionWorkRRsetSignature:
		return l.policy.MaxRRsetSignatureChecks, rrsetSignatureExhausted, true
	case RecursionWorkConcurrentCrypto:
		return l.policy.MaxConcurrentCrypto, concurrentCryptoExhausted, true
	default:
		return 0, 0, false
	}
}

func (l *RecursionWorkLedger) limit(kind RecursionWorkKind) (uint32, bool) {
	if _, limit, _, ok := l.aggregateDimension(kind); ok {
		return limit, true
	}
	limit, _, ok := l.localDimension(kind)
	return limit, ok
}

func (l *RecursionWorkLedger) markExhausted(kind RecursionWorkKind, bit uint32, latchRejection bool) {
	if !l.isLive() {
		return
	}
	l.exhausted.Or(bit)
	if latchRejection {
		l.first.CompareAndSwap(0, uint32(kind)+1)
	}
}

// EnforcementError returns the first rejected dimension in enforce mode.
func (l *RecursionWorkLedger) EnforcementError() error {
	if err, control := l.controlError(); control {
		return err
	}
	if l == nil || l.policy.Mode != RecursionWorkEnforce {
		return nil
	}
	first := l.first.Load()
	if first == 0 {
		return nil
	}
	if first > uint32(RecursionWorkConcurrentCrypto)+1 {
		return nil
	}
	kind := RecursionWorkKind(first - 1) //nolint:gosec // first is bounded to the RecursionWorkKind range above.
	limit, ok := l.limit(kind)
	if !ok {
		return nil
	}
	return &RecursionWorkLimitError{Kind: kind, Limit: limit}
}

// Snapshot returns the current accepted/observed work totals and crossings.
func (l *RecursionWorkLedger) Snapshot() RecursionWorkSnapshot {
	if !l.isLive() {
		return RecursionWorkSnapshot{}
	}
	exhausted := l.exhausted.Load()
	return RecursionWorkSnapshot{
		Mode:                          l.policy.Mode,
		OutboundQueries:               l.outbound.Load(),
		InternalQueries:               l.internal.Load(),
		SignatureChecks:               l.signatures.Load(),
		DSDigests:                     l.dsDigests.Load(),
		NSEC3Hashes:                   l.nsec3Hashes.Load(),
		OutboundExhausted:             exhausted&outboundExhausted != 0,
		InternalExhausted:             exhausted&internalExhausted != 0,
		DNSKEYCandidatesExhausted:     exhausted&dnskeyCandidateExhausted != 0,
		RRsetSignatureChecksExhausted: exhausted&rrsetSignatureExhausted != 0,
		SignatureChecksExhausted:      exhausted&signatureExhausted != 0,
		DSDigestsExhausted:            exhausted&dsDigestExhausted != 0,
		NSEC3HashesExhausted:          exhausted&nsec3HashExhausted != 0,
		ConcurrentCryptoExhausted:     exhausted&concurrentCryptoExhausted != 0,
		MaxOutboundQueries:            l.policy.MaxOutboundQueries,
		MaxInternalQueries:            l.policy.MaxInternalQueries,
		MaxDNSKEYCandidates:           l.policy.MaxDNSKEYCandidates,
		MaxRRsetSignatureChecks:       l.policy.MaxRRsetSignatureChecks,
		MaxSignatureChecks:            l.policy.MaxSignatureChecks,
		MaxDSDigests:                  l.policy.MaxDSDigests,
		MaxNSEC3Hashes:                l.policy.MaxNSEC3Hashes,
		MaxConcurrentCrypto:           l.policy.MaxConcurrentCrypto,
	}
}

// Retain keeps the request-tree ledger open for asynchronous work that can
// outlive the client-facing chain. The returned release function is safe to
// call more than once; callers must call it when that work is complete.
func (l *RecursionWorkLedger) Retain() (release func(), ok bool) {
	if !l.isLive() || !l.policy.Enabled() {
		return nil, false
	}
	for {
		refs := l.refs.Load()
		if refs == 0 {
			return nil, false
		}
		if l.refs.CompareAndSwap(refs, refs+1) {
			var once sync.Once
			return func() {
				once.Do(l.release)
			}, true
		}
	}
}

// finish releases the root owner exactly once. Publication waits for any
// retained asynchronous work, so its debits are included without delaying
// the client response.
func (l *RecursionWorkLedger) finish() {
	if !l.isLive() ||
		!l.policy.Enabled() ||
		!l.rootState.CompareAndSwap(uint32(recursionWorkLedgerLive), uint32(recursionWorkLedgerRootDone)) {
		return
	}
	l.release()
}

func (l *RecursionWorkLedger) release() {
	if !l.isLive() {
		return
	}
	if l.refs.Add(-1) != 0 || !l.finished.CompareAndSwap(false, true) {
		return
	}
	snapshot := l.Snapshot()
	mode := "shadow"
	if snapshot.Mode == RecursionWorkEnforce {
		mode = "enforce"
	}
	if snapshot.OutboundExhausted {
		recursionFirewallExhaustions.WithLabelValues("outbound_queries", mode).Inc()
	}
	if snapshot.InternalExhausted {
		recursionFirewallExhaustions.WithLabelValues("internal_queries", mode).Inc()
	}
	if snapshot.DNSKEYCandidatesExhausted {
		recursionFirewallExhaustions.WithLabelValues("dnskey_candidates", mode).Inc()
	}
	if snapshot.RRsetSignatureChecksExhausted {
		recursionFirewallExhaustions.WithLabelValues("rrset_signature_checks", mode).Inc()
	}
	if snapshot.SignatureChecksExhausted {
		recursionFirewallExhaustions.WithLabelValues("signature_checks", mode).Inc()
	}
	if snapshot.DSDigestsExhausted {
		recursionFirewallExhaustions.WithLabelValues("ds_digests", mode).Inc()
	}
	if snapshot.NSEC3HashesExhausted {
		recursionFirewallExhaustions.WithLabelValues("nsec3_hashes", mode).Inc()
	}
	if snapshot.ConcurrentCryptoExhausted {
		recursionFirewallExhaustions.WithLabelValues("concurrent_crypto", mode).Inc()
	}

	dnssecWorkTotal.WithLabelValues("signature_checks", mode).Add(int64(snapshot.SignatureChecks))
	dnssecWorkTotal.WithLabelValues("ds_digests", mode).Add(int64(snapshot.DSDigests))
	dnssecWorkTotal.WithLabelValues("nsec3_hashes", mode).Add(int64(snapshot.NSEC3Hashes))
	dnssecWorkPerRequest.WithLabelValues("signature_checks", mode).Observe(float64(snapshot.SignatureChecks))
	dnssecWorkPerRequest.WithLabelValues("ds_digests", mode).Observe(float64(snapshot.DSDigests))
	dnssecWorkPerRequest.WithLabelValues("nsec3_hashes", mode).Observe(float64(snapshot.NSEC3Hashes))

	// One recursive resolution tree is the denominator, so the count of
	// outbound transport attempts is also that tree's fan-out ratio.
	recursionFanoutRatio.Observe(float64(snapshot.OutboundQueries))
}

// recursionWorkKey carries either an explicit heap ledger on ordinary derived
// contexts or an internal LazyDeadline lifecycle pin. Both forms avoid
// reloading a pooled ResponseMeta after its Chain has been reset.
type recursionWorkKeyType struct{}
type recursionWorkBestEffortKeyType struct{}

var recursionWorkKey = &recursionWorkKeyType{}
var recursionWorkBestEffortKey = &recursionWorkBestEffortKeyType{}

// A LazyDeadline has one request-owned pin slot. Immutable control ledgers turn
// that slot into a tiny lifecycle state machine without allocating a real
// ledger for cache/local hits:
//
//	pending -> ledger -> finished by the outer Chain
//	pending -> closed  -> no later pooled ResponseMeta fallback is allowed
//
// Pointers keep atomic.Value updates allocation-free. rootState makes their
// immutability explicit and every mutating ledger entry point rejects them.
var (
	recursionWorkPending = newRecursionWorkControlLedger(recursionWorkLedgerPending)
	recursionWorkClosed  = newRecursionWorkControlLedger(recursionWorkLedgerClosed)
)

func newRecursionWorkControlLedger(state recursionWorkLedgerState) *RecursionWorkLedger {
	ledger := new(RecursionWorkLedger)
	ledger.rootState.Store(uint32(state))
	return ledger
}

// WithRecursionWork returns a derived context carrying the exact ledger.
func WithRecursionWork(ctx context.Context, ledger *RecursionWorkLedger) context.Context {
	return context.WithValue(ctx, recursionWorkKey, ledger)
}

// WithBestEffortRecursionWork marks optional work that must stop at the shared
// cap without turning a successful required branch into a policy failure.
func WithBestEffortRecursionWork(ctx context.Context) context.Context {
	return context.WithValue(ctx, recursionWorkBestEffortKey, struct{}{})
}

// IsBestEffortRecursionWork reports whether work debited through ctx belongs to
// an optional branch.
func IsBestEffortRecursionWork(ctx context.Context) bool {
	_, ok := ctx.Value(recursionWorkBestEffortKey).(struct{})
	return ok
}

// RecursionWorkFrom returns the request-tree ledger, if one exists. The
// ResponseMeta fallback supports upstream response-writer contexts that were
// captured before a downstream resolver pinned the ledger directly.
func RecursionWorkFrom(ctx context.Context) *RecursionWorkLedger {
	if ledger, _ := ctx.Value(recursionWorkKey).(*RecursionWorkLedger); ledger != nil {
		return ledger
	}
	if pinned, ok := pinnedRecursionWork(ctx); ok {
		switch pinned.lifecycleState() {
		case recursionWorkLedgerClosed:
			// The owning Chain has completed. Never fall through to its
			// pooled ResponseMeta, which may already belong to another
			// request.
			return nil
		case recursionWorkLedgerPending:
			// The context-aware installer publishes the heap ledger to
			// ResponseMeta immediately before replacing this pin. The Chain
			// is still active, so observing that narrow window is safe.
			if meta := ResponseMetaFrom(ctx); meta != nil {
				return meta.RecursionWork()
			}
			return nil
		default:
			return pinned
		}
	}
	if meta := ResponseMetaFrom(ctx); meta != nil {
		return meta.RecursionWork()
	}
	return nil
}

// EnsureRecursionWork establishes one heap ledger beside ResponseMeta and
// pins it into the returned context. The first policy in a request tree wins.
func EnsureRecursionWork(ctx context.Context, policy RecursionWorkPolicy) (context.Context, *RecursionWorkLedger) {
	if pinned, _ := ctx.Value(recursionWorkKey).(*RecursionWorkLedger); pinned != nil {
		return ctx, pinned
	}
	if pinned, ok := pinnedRecursionWork(ctx); ok {
		switch pinned.lifecycleState() {
		case recursionWorkLedgerClosed:
			return ctx, recursionWorkClosed
		case recursionWorkLedgerPending:
			meta := ResponseMetaFrom(ctx)
			if meta == nil {
				return ctx, nil
			}
			if meta.workPolicy.Enabled() {
				policy = meta.workPolicy
			}

			value, _ := contextutil.TryUpdatePinnedValueLocked(
				ctx,
				recursionWorkKey,
				recursionWorkPending,
				func() *RecursionWorkLedger {
					if ledger := meta.RecursionWork(); ledger != nil {
						return ledger
					}
					if !policy.Enabled() {
						return recursionWorkPending
					}
					return meta.ensureRecursionWork(policy)
				},
			)
			switch value {
			case recursionWorkClosed:
				return ctx, recursionWorkClosed
			case recursionWorkPending, nil:
				return ctx, nil
			default:
				return ctx, value
			}
		default:
			return ctx, pinned
		}
	}

	meta := ResponseMetaFrom(ctx)
	if meta == nil {
		if !policy.Enabled() {
			return ctx, nil
		}
		meta = new(ResponseMeta)
		ctx = WithResponseMeta(ctx, meta)
	}
	if ledger := meta.RecursionWork(); ledger != nil {
		return WithRecursionWork(ctx, ledger), ledger
	}
	if meta.workPolicy.Enabled() {
		policy = meta.workPolicy
	}
	if !policy.Enabled() {
		return ctx, nil
	}

	ledger := meta.ensureRecursionWork(policy)
	return WithRecursionWork(ctx, ledger), ledger
}

func recursionWorkForUse(ctx context.Context) *RecursionWorkLedger {
	if ledger := RecursionWorkFrom(ctx); ledger != nil {
		return ledger
	}
	if pinned, ok := pinnedRecursionWork(ctx); ok && pinned == recursionWorkClosed {
		return recursionWorkClosed
	}
	meta := ResponseMetaFrom(ctx)
	if meta == nil || !meta.workPolicy.Enabled() {
		return nil
	}
	_, ledger := EnsureRecursionWork(ctx, meta.workPolicy)
	return ledger
}

// DebitRecursionWork debits the current tree when accounting is active.
func DebitRecursionWork(ctx context.Context, kind RecursionWorkKind) error {
	if ledger := recursionWorkForUse(ctx); ledger != nil {
		if IsBestEffortRecursionWork(ctx) {
			return ledger.DebitBestEffort(kind)
		}
		return ledger.Debit(kind)
	}
	return nil
}

// CheckRecursionWorkLocalLimit checks a local DNSSEC work limit in the current
// request tree. used is the number of candidates or signatures already
// examined, so the first rejected value in enforce mode is exactly the limit.
func CheckRecursionWorkLocalLimit(ctx context.Context, kind RecursionWorkKind, used uint32) error {
	if ledger := recursionWorkForUse(ctx); ledger != nil {
		if IsBestEffortRecursionWork(ctx) {
			return ledger.checkLocal(kind, used, false)
		}
		return ledger.CheckLocal(kind, used)
	}
	return nil
}

// RejectRecursionWork records a governor rejection that occurs outside an
// accepted-work counter. Shadow mode observes it without replacing the
// original operational error; enforce mode returns a typed policy error.
func RejectRecursionWork(ctx context.Context, kind RecursionWorkKind) error {
	if ledger := recursionWorkForUse(ctx); ledger != nil {
		if IsBestEffortRecursionWork(ctx) {
			return ledger.reject(kind, false)
		}
		return ledger.Reject(kind)
	}
	return nil
}

// RecursionWorkRootOwned reports whether an outer middleware Chain owns the
// ledger's completion boundary, including when the ledger has not yet been
// materialized.
func RecursionWorkRootOwned(ctx context.Context) bool {
	pinned, ok := pinnedRecursionWork(ctx)
	return ok && pinned != recursionWorkClosed
}

func beginLazyRecursionWorkOwner(ctx context.Context) bool {
	return contextutil.TryPinValue(ctx, recursionWorkKey, recursionWorkPending)
}

func finishLazyRecursionWork(ctx context.Context, meta *ResponseMeta) {
	for {
		pinned, ok := pinnedRecursionWork(ctx)
		if !ok {
			return
		}
		switch pinned {
		case recursionWorkClosed:
			return
		case recursionWorkPending:
			next, _ := contextutil.TryUpdatePinnedValueLocked(
				ctx,
				recursionWorkKey,
				recursionWorkPending,
				func() *RecursionWorkLedger {
					if ledger := meta.RecursionWork(); ledger != nil {
						return ledger
					}
					return recursionWorkClosed
				},
			)
			if next == recursionWorkPending {
				continue
			}
			if next == nil || next == recursionWorkClosed {
				return
			}
			next.finish()
			return
		default:
			pinned.finish()
			return
		}
	}
}

func pinnedRecursionWork(ctx context.Context) (*RecursionWorkLedger, bool) {
	value, ok := contextutil.PinnedValue(ctx, recursionWorkKey)
	if !ok {
		return nil, false
	}
	pinned, ok := value.(*RecursionWorkLedger)
	return pinned, ok
}

// RecursionWorkEnforcementError returns the local request tree's first policy
// rejection. Checking this context-owned state, rather than trusting an EDE
// received on the wire, preserves shadow-mode compatibility with upstreams
// that legitimately emit the same policy code.
func RecursionWorkEnforcementError(ctx context.Context) error {
	if ledger := RecursionWorkFrom(ctx); ledger != nil {
		return ledger.EnforcementError()
	}
	return nil
}

// RecursionWorkEDE returns the request tree's latched enforcement EDE. When
// no local rejection is latched (for example, an upstream returned a generic
// policy error), it preserves the existing recursion-work fallback.
func RecursionWorkEDE(ctx context.Context) (uint16, string) {
	if err := RecursionWorkEnforcementError(ctx); err != nil {
		var limitErr *RecursionWorkLimitError
		if errors.As(err, &limitErr) {
			return limitErr.EDECode(), limitErr.Error()
		}
	}
	return RecursionWorkEDECode, RecursionWorkEDEText
}

// RecursionWorkErrorEDE maps a directly returned recursion-work error before
// consulting the request tree's latched rejection. Direct Queryer and Exchange
// errors may carry more specific DNSSEC provenance than the context fallback.
func RecursionWorkErrorEDE(ctx context.Context, err error) (uint16, string) {
	var limitErr *RecursionWorkLimitError
	if errors.As(err, &limitErr) {
		return limitErr.EDECode(), limitErr.Error()
	}
	return RecursionWorkEDE(ctx)
}

// FinishRecursionWork publishes the current tree exactly once. Normal client
// pipelines finish at the outer Chain boundary; direct Resolver API callers
// use this when they had to establish their own standalone ledger.
func FinishRecursionWork(ctx context.Context) {
	if ledger := RecursionWorkFrom(ctx); ledger != nil {
		ledger.finish()
	}
}

var (
	recursionFirewallExhaustions = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_recursion_firewall_exhaustions_total",
		Help: "Recursion request trees that exhausted a work budget",
	}, []string{"reason", "mode"})

	dnssecWorkTotal = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dnssec_work_total",
		Help: "Accepted or observed DNSSEC work across completed request trees",
	}, []string{"operation", "mode"})

	// internal/metric intentionally shards scalar counters only; histograms
	// remain native Prometheus collectors because bucket observations cannot
	// use its delta-flush model.
	dnssecWorkPerRequest = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dnssec_work_per_request",
		Help:    "DNSSEC operations observed per completed recursive request tree",
		Buckets: []float64{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
	}, []string{"operation", "mode"})

	recursionFanoutRatio = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "dns_recursion_fanout_ratio",
		Help:    "Outbound recursive transport attempts per resolution tree",
		Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128},
	})

	_ = recursionFirewallExhaustions.Register("outbound_queries", "shadow")
	_ = recursionFirewallExhaustions.Register("outbound_queries", "enforce")
	_ = recursionFirewallExhaustions.Register("internal_queries", "shadow")
	_ = recursionFirewallExhaustions.Register("internal_queries", "enforce")
	_ = recursionFirewallExhaustions.Register("dnskey_candidates", "shadow")
	_ = recursionFirewallExhaustions.Register("dnskey_candidates", "enforce")
	_ = recursionFirewallExhaustions.Register("rrset_signature_checks", "shadow")
	_ = recursionFirewallExhaustions.Register("rrset_signature_checks", "enforce")
	_ = recursionFirewallExhaustions.Register("signature_checks", "shadow")
	_ = recursionFirewallExhaustions.Register("signature_checks", "enforce")
	_ = recursionFirewallExhaustions.Register("ds_digests", "shadow")
	_ = recursionFirewallExhaustions.Register("ds_digests", "enforce")
	_ = recursionFirewallExhaustions.Register("nsec3_hashes", "shadow")
	_ = recursionFirewallExhaustions.Register("nsec3_hashes", "enforce")
	_ = recursionFirewallExhaustions.Register("concurrent_crypto", "shadow")
	_ = recursionFirewallExhaustions.Register("concurrent_crypto", "enforce")

	_ = dnssecWorkTotal.Register("signature_checks", "shadow")
	_ = dnssecWorkTotal.Register("signature_checks", "enforce")
	_ = dnssecWorkTotal.Register("ds_digests", "shadow")
	_ = dnssecWorkTotal.Register("ds_digests", "enforce")
	_ = dnssecWorkTotal.Register("nsec3_hashes", "shadow")
	_ = dnssecWorkTotal.Register("nsec3_hashes", "enforce")
)

func init() {
	for _, operation := range []string{"signature_checks", "ds_digests", "nsec3_hashes"} {
		for _, mode := range []string{"shadow", "enforce"} {
			dnssecWorkPerRequest.WithLabelValues(operation, mode)
		}
	}
	prometheus.MustRegister(recursionFanoutRatio, dnssecWorkPerRequest)
}
