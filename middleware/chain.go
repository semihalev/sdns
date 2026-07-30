package middleware

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
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

type ResponseMeta struct {
	// cut is an atomic pointer to an immutable deadline. Resolver work can
	// fan out into concurrent NS-address sub-queries that share the request
	// context, so a plain time.Time here races even though every update is
	// min-only.
	cut atomic.Pointer[responseCut]

	// work points at a heap-owned request-tree ledger. Reset detaches the
	// pointer without mutating the ledger so resolver goroutines that briefly
	// outlive a pooled Chain keep charging their original request.
	work atomic.Pointer[RecursionWorkLedger]

	// attempts points at a heap-owned RFC 9520 request-tree retry guard.
	// Reset only detaches it; pinned resolver goroutines keep their original
	// guard even after the pooled Chain is reused.
	attempts atomic.Pointer[ResolutionAttemptGuard]

	// cachedFailures points at a heap-owned, pointer-identity set of failure
	// cache responses currently crossing outer response-writer wrappers.
	// Reset detaches the set rather than mutating it, matching the lifetime
	// rules for work and attempts above.
	cachedFailures atomic.Pointer[cachedFailureResponseSet]
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

	next := &responseCut{deadline: deadline, key: key}
	for {
		current := m.cut.Load()
		if current != nil && !deadline.Before(current.deadline) {
			return
		}
		if m.cut.CompareAndSwap(current, next) {
			return
		}
	}
}

// Cut returns the earliest delegation-cut deadline observed for the request
// tree and the delegation-cache key that supplied it. A zero deadline means
// unbounded; in that case the key is also zero.
func (m *ResponseMeta) Cut() (time.Time, uint64) {
	if m == nil {
		return time.Time{}, 0
	}
	if cut := m.cut.Load(); cut != nil {
		return cut.deadline, cut.key
	}
	return time.Time{}, 0
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
		m.cut.Store(nil)
		m.work.Store(nil)
		m.attempts.Store(nil)
		m.cachedFailures.Store(nil)
	}
}

// MarkCachedFailureResponse marks msg as a response currently being emitted
// from the RFC 9520 failure cache and returns an idempotent release function.
// Callers must keep the mark only around the synchronous WriteMsg call.
func (m *ResponseMeta) MarkCachedFailureResponse(msg *dns.Msg) func() {
	if m == nil || msg == nil {
		return func() {}
	}

	markers := m.cachedFailures.Load()
	if markers == nil {
		candidate := &cachedFailureResponseSet{messages: make(map[*dns.Msg]uint32)}
		if m.cachedFailures.CompareAndSwap(nil, candidate) {
			markers = candidate
		} else {
			markers = m.cachedFailures.Load()
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
	markers := m.cachedFailures.Load()
	if markers == nil {
		return false
	}

	markers.mu.RLock()
	marked := markers.messages[msg] > 0
	markers.mu.RUnlock()
	return marked
}

// EnsureResolutionAttemptGuard returns the request tree's retry guard,
// installing one on first use.
func (m *ResponseMeta) EnsureResolutionAttemptGuard() *ResolutionAttemptGuard {
	if m == nil {
		return nil
	}
	if guard := m.attempts.Load(); guard != nil {
		return guard
	}

	guard := NewResolutionAttemptGuard()
	if m.attempts.CompareAndSwap(nil, guard) {
		return guard
	}
	return m.attempts.Load()
}

// ResolutionAttemptGuard returns the request tree's retry guard, if present.
func (m *ResponseMeta) ResolutionAttemptGuard() *ResolutionAttemptGuard {
	if m == nil {
		return nil
	}
	return m.attempts.Load()
}

// EnsureRecursionWork returns the request tree's ledger, installing one with
// policy when this is the first recursive work in the tree.
func (m *ResponseMeta) EnsureRecursionWork(policy RecursionWorkPolicy) *RecursionWorkLedger {
	if m == nil || !policy.Enabled() {
		return nil
	}
	if ledger := m.work.Load(); ledger != nil {
		return ledger
	}

	ledger := NewRecursionWorkLedger(policy)
	if m.work.CompareAndSwap(nil, ledger) {
		return ledger
	}
	return m.work.Load()
}

// RecursionWork returns the request tree's ledger, if accounting is active.
func (m *ResponseMeta) RecursionWork() *RecursionWorkLedger {
	if m == nil {
		return nil
	}
	return m.work.Load()
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

// ResponseMetaFrom returns the ctx's response metadata sink, or nil
// when none was established (background/priming work).
func ResponseMetaFrom(ctx context.Context) *ResponseMeta {
	m, _ := ctx.Value(responseMetaKey).(*ResponseMeta)
	return m
}

// Chain carries per-request state through the middleware pipeline.
// Instances are reused via a sync.Pool: NewChain allocates the fixed
// pipeline reference, Reset rebinds the per-request writer + message.
type Chain struct {
	Writer  ResponseWriter
	Request *dns.Msg

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
}

// NewChain returns a Chain bound to the given handler pipeline. The slice
// is captured by reference and must not be mutated by the caller after
// this call.
func NewChain(handlers []Handler) *Chain {
	return newChain(handlers, RecursionWorkPolicy{})
}

func newChain(handlers []Handler, workPolicy RecursionWorkPolicy) *Chain {
	return &Chain{
		Writer:     &responseWriter{},
		handlers:   handlers,
		count:      len(handlers),
		workPolicy: workPolicy,
	}
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
		meta := ResponseMetaFrom(ctx)
		if meta == nil {
			meta = &ch.Meta
			ctx = WithResponseMeta(ctx, meta)
		}
		if ch.workPolicy.Enabled() {
			hadLedger := RecursionWorkFrom(ctx) != nil
			var ledger *RecursionWorkLedger
			ctx, ledger = EnsureRecursionWork(ctx, ch.workPolicy)
			if !hadLedger {
				defer ledger.finish()
			}
		}
	}

	h := ch.handlers[ch.pos]
	ch.pos++
	ch.count--
	h.ServeDNS(ctx, ch)
}

// Cancel stops the chain without writing a response. Subsequent Next
// calls become no-ops.
func (ch *Chain) Cancel() {
	ch.count = 0
}

// CancelWithRcode writes a reply with the given rcode and stops the
// chain. do controls the DO bit in the response's OPT record.
func (ch *Chain) CancelWithRcode(rcode int, do bool) {
	m := new(dns.Msg)
	m.Extra = ch.Request.Extra
	m.SetRcode(ch.Request, rcode)
	m.RecursionAvailable = true
	m.RecursionDesired = true

	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(do)
	}

	_ = ch.Writer.WriteMsg(m)
	ch.count = 0
}

// Reset rebinds the chain to a fresh writer + request for pool reuse.
func (ch *Chain) Reset(w dns.ResponseWriter, r *dns.Msg) {
	ch.Writer.Reset(w)
	ch.Request = r
	ch.Meta.Reset()
	ch.pos = 0
	ch.count = len(ch.handlers)
}
