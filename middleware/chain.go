package middleware

import (
	"context"
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

type ResponseMeta struct {
	// cut is an atomic pointer to an immutable deadline. Resolver work can
	// fan out into concurrent NS-address sub-queries that share the request
	// context, so a plain time.Time here races even though every update is
	// min-only.
	cut atomic.Pointer[responseCut]
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

// Reset clears the accumulated deadline before a pooled Chain is reused.
// Store(nil) is safe even if the ResponseMeta has previously been used; do
// not replace the struct by assignment because atomic values must not be
// copied after first use.
func (m *ResponseMeta) Reset() {
	if m != nil {
		m.cut.Store(nil)
	}
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
}

// NewChain returns a Chain bound to the given handler pipeline. The slice
// is captured by reference and must not be mutated by the caller after
// this call.
func NewChain(handlers []Handler) *Chain {
	return &Chain{
		Writer:   &responseWriter{},
		handlers: handlers,
		count:    len(handlers),
	}
}

// Next invokes the next handler in the chain. Each handler is responsible
// for calling Next to continue, or Cancel/CancelWithRcode to stop.
func (ch *Chain) Next(ctx context.Context) {
	if ch.count == 0 {
		return
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
