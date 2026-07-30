package middleware

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
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
)

const (
	// RecursionWorkEDEText is deliberately stable because it is returned to
	// clients as RFC 8914 Extended DNS Error text in enforce mode.
	RecursionWorkEDEText = "Recursion work budget exceeded"

	// RecursionWorkEDECode deliberately uses RFC 8914's finalized catch-all
	// code. The more specific "Unable to Conform to Policy" registry entry
	// still references an Internet-Draft, so it is not part of this wire
	// contract.
	RecursionWorkEDECode = dns.ExtendedErrorCodeOther

	outboundExhausted uint32 = 1 << iota
	internalExhausted
)

// ErrRecursionWorkLimit is the sentinel carried by a
// RecursionWorkLimitError.
var ErrRecursionWorkLimit = errors.New("recursion work limit exceeded")

// RecursionWorkPolicy is immutable after a ledger is created.
type RecursionWorkPolicy struct {
	Mode               RecursionWorkMode
	MaxOutboundQueries uint32
	MaxInternalQueries uint32
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

func (e *RecursionWorkLimitError) Error() string { return RecursionWorkEDEText }

func (e *RecursionWorkLimitError) Unwrap() error { return ErrRecursionWorkLimit }

// EDECode maps enforcement to RFC 8914's finalized catch-all EDE code.
func (e *RecursionWorkLimitError) EDECode() uint16 {
	return RecursionWorkEDECode
}

// RecursionWorkSnapshot is a race-safe point-in-time ledger view.
type RecursionWorkSnapshot struct {
	Mode               RecursionWorkMode
	OutboundQueries    uint32
	InternalQueries    uint32
	OutboundExhausted  bool
	InternalExhausted  bool
	MaxOutboundQueries uint32
	MaxInternalQueries uint32
}

// RecursionWorkLedger aggregates work across one complete recursive request
// tree. It owns no timer: the existing request context deadline remains the
// single authoritative time budget.
type RecursionWorkLedger struct {
	policy RecursionWorkPolicy

	outbound  atomic.Uint32
	internal  atomic.Uint32
	exhausted atomic.Uint32
	first     atomic.Uint32
	refs      atomic.Int64
	rootDone  atomic.Bool
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

// Debit reserves one unit of kind. Shadow mode records crossings but always
// permits work. Enforce mode never lets an accepted counter exceed its cap.
// Work is never refunded: failed, cancelled, and losing attempts consumed the
// resource they started.
func (l *RecursionWorkLedger) Debit(kind RecursionWorkKind) error {
	if l == nil || !l.policy.Enabled() {
		return nil
	}

	counter, limit, bit := l.dimension(kind)
	if l.policy.Mode == RecursionWorkShadow {
		if counter.Add(1) > limit {
			l.markExhausted(kind, bit)
		}
		return nil
	}

	for {
		used := counter.Load()
		if used >= limit {
			l.markExhausted(kind, bit)
			return &RecursionWorkLimitError{Kind: kind, Limit: limit}
		}
		if counter.CompareAndSwap(used, used+1) {
			return nil
		}
	}
}

func (l *RecursionWorkLedger) dimension(kind RecursionWorkKind) (*atomic.Uint32, uint32, uint32) {
	switch kind {
	case RecursionWorkInternalQuery:
		return &l.internal, l.policy.MaxInternalQueries, internalExhausted
	default:
		return &l.outbound, l.policy.MaxOutboundQueries, outboundExhausted
	}
}

func (l *RecursionWorkLedger) markExhausted(kind RecursionWorkKind, bit uint32) {
	l.exhausted.Or(bit)
	l.first.CompareAndSwap(0, uint32(kind)+1)
}

// EnforcementError returns the first rejected dimension in enforce mode.
func (l *RecursionWorkLedger) EnforcementError() error {
	if l == nil || l.policy.Mode != RecursionWorkEnforce {
		return nil
	}
	first := l.first.Load()
	if first == 0 {
		return nil
	}
	kind := RecursionWorkOutboundQuery
	if first == uint32(RecursionWorkInternalQuery)+1 {
		kind = RecursionWorkInternalQuery
	}
	_, limit, _ := l.dimension(kind)
	return &RecursionWorkLimitError{Kind: kind, Limit: limit}
}

// Snapshot returns the current accepted/observed work totals and crossings.
func (l *RecursionWorkLedger) Snapshot() RecursionWorkSnapshot {
	if l == nil {
		return RecursionWorkSnapshot{}
	}
	exhausted := l.exhausted.Load()
	return RecursionWorkSnapshot{
		Mode:               l.policy.Mode,
		OutboundQueries:    l.outbound.Load(),
		InternalQueries:    l.internal.Load(),
		OutboundExhausted:  exhausted&outboundExhausted != 0,
		InternalExhausted:  exhausted&internalExhausted != 0,
		MaxOutboundQueries: l.policy.MaxOutboundQueries,
		MaxInternalQueries: l.policy.MaxInternalQueries,
	}
}

// Retain keeps the request-tree ledger open for asynchronous work that can
// outlive the client-facing chain. The returned release function is safe to
// call more than once; callers must call it when that work is complete.
func (l *RecursionWorkLedger) Retain() (release func(), ok bool) {
	if l == nil || !l.policy.Enabled() {
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
	if l == nil || !l.policy.Enabled() || !l.rootDone.CompareAndSwap(false, true) {
		return
	}
	l.release()
}

func (l *RecursionWorkLedger) release() {
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

	// One recursive resolution tree is the denominator, so the count of
	// outbound transport attempts is also that tree's fan-out ratio.
	recursionFanoutRatio.Observe(float64(snapshot.OutboundQueries))
}

// recursionWorkKey pins the exact heap ledger in contexts passed to resolver
// goroutines. This avoids reloading a pooled ResponseMeta after its Chain has
// been reset for another request.
type recursionWorkKeyType struct{}

var recursionWorkKey = &recursionWorkKeyType{}

// WithRecursionWork returns a derived context carrying the exact ledger.
func WithRecursionWork(ctx context.Context, ledger *RecursionWorkLedger) context.Context {
	return context.WithValue(ctx, recursionWorkKey, ledger)
}

// RecursionWorkFrom returns the request-tree ledger, if one exists. The
// ResponseMeta fallback supports upstream response-writer contexts that were
// captured before a downstream resolver pinned the ledger directly.
func RecursionWorkFrom(ctx context.Context) *RecursionWorkLedger {
	if ledger, _ := ctx.Value(recursionWorkKey).(*RecursionWorkLedger); ledger != nil {
		return ledger
	}
	if meta := ResponseMetaFrom(ctx); meta != nil {
		return meta.RecursionWork()
	}
	return nil
}

// EnsureRecursionWork establishes one heap ledger beside ResponseMeta and
// pins it into the returned context. The first policy in a request tree wins.
func EnsureRecursionWork(ctx context.Context, policy RecursionWorkPolicy) (context.Context, *RecursionWorkLedger) {
	if ledger := RecursionWorkFrom(ctx); ledger != nil {
		if pinned, _ := ctx.Value(recursionWorkKey).(*RecursionWorkLedger); pinned != ledger {
			ctx = WithRecursionWork(ctx, ledger)
		}
		return ctx, ledger
	}
	if !policy.Enabled() {
		return ctx, nil
	}

	meta := ResponseMetaFrom(ctx)
	if meta == nil {
		meta = new(ResponseMeta)
		ctx = WithResponseMeta(ctx, meta)
	}
	ledger := meta.EnsureRecursionWork(policy)
	if pinned, _ := ctx.Value(recursionWorkKey).(*RecursionWorkLedger); pinned != ledger {
		ctx = WithRecursionWork(ctx, ledger)
	}
	return ctx, ledger
}

// DebitRecursionWork debits the current tree when accounting is active.
func DebitRecursionWork(ctx context.Context, kind RecursionWorkKind) error {
	if ledger := RecursionWorkFrom(ctx); ledger != nil {
		return ledger.Debit(kind)
	}
	return nil
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

	recursionFanoutRatio = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "dns_recursion_fanout_ratio",
		Help:    "Outbound recursive transport attempts per resolution tree",
		Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128},
	})

	_ = recursionFirewallExhaustions.Register("outbound_queries", "shadow")
	_ = recursionFirewallExhaustions.Register("outbound_queries", "enforce")
	_ = recursionFirewallExhaustions.Register("internal_queries", "shadow")
	_ = recursionFirewallExhaustions.Register("internal_queries", "enforce")
)

func init() {
	prometheus.MustRegister(recursionFanoutRatio)
}
