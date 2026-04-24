package middleware

// queryer.go runs a DNS request through an internal sub-pipeline —
// typically every middleware from the "answer surface" inward
// (hostsfile, blocklist, as112, kubernetes, cache, failover, and
// the resolver or forwarder) with client-only guards filtered out
// (metrics, dnstap, accesslist, ratelimit, reflex, accesslog).
//
// It replaces the top-of-chain re-entry behaviour of
// util.ExchangeInternal with a deliberately narrower sub-pipeline,
// driven by a BufferWriter rather than a sentinel-address mock.
// The sub-pipelines are constructed in Setup and installed on
// middlewares via QueryerSetter / PrefetchQueryerSetter.
//
// DNS-layer outcomes (SERVFAIL, REFUSED, NXDOMAIN, etc.) come back
// as a *dns.Msg. ErrNoResponse is returned only when the
// sub-pipeline completes without any middleware calling WriteMsg —
// mirroring util.ExchangeInternal's "no replied any message" so
// existing callers can distinguish wire-level failures from
// executor failures.

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// Queryer answers a client-shaped DNS query through the internal
// sub-pipeline.
type Queryer interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// ErrNoResponse signals that the sub-pipeline ran without any
// middleware writing a response.
var ErrNoResponse = errors.New("queryer: no response written")

// ErrMaxRecursion signals that a Queryer.Query call nested past
// the recursion bound. The old middleware/loop package counted
// per-(qname, qtype) re-entries through util.ExchangeInternal and
// returned SERVFAIL after maxLoops. With loop retired and
// ExchangeInternal routed through the sub-pipeline, built-in
// paths (CNAME/DNAME/resolver-depth) still have their own caps,
// but a plugin middleware that calls util.ExchangeInternal from
// its own ServeDNS has no other generic bound.
var ErrMaxRecursion = errors.New("queryer: max recursion depth exceeded")

// maxQueryerRecursion bounds the number of nested Queryer.Query
// calls in a single client request tree. Chosen loose enough to
// accommodate legitimate deep resolution (DS chain walk + CNAME
// chase + DNAME target combined; worst-case ~20-30 in
// pathological but valid cases) while still catching plugin-
// driven infinite recursion quickly. The resolver's own
// cfg.Maxdepth (default 30) bounds total resolution depth per
// Resolve; this counter bounds the count of distinct sub-pipeline
// invocations nested together.
const maxQueryerRecursion = 32

// queryerDepthKeyType tags ctx with the current Queryer recursion
// depth. Sentinel pointer keeps ctx.Value alloc-free.
type queryerDepthKeyType struct{}

var queryerDepthKey = &queryerDepthKeyType{}

// internalCtxKey tags contexts manually marked via MarkInternal.
// Sentinel value so lookups avoid allocation from context.WithValue
// boxing an interface.
type internalCtxKey struct{}

var internalKeyVal = &internalCtxKey{}

// MarkInternal returns a derived ctx tagged as originating from an
// internal sub-pipeline run. Provided as public API for plugin
// middleware that wants to signal internal-ness without relying on
// the BufferWriter's Internal() flag (e.g. when a plugin spawns
// its own internal work without going through Queryer.Query).
//
// sdns's own Queryer.Query does NOT call MarkInternal — the
// BufferWriter it installs already reports Internal()==true, and
// every in-tree consumer (cache.ServeDNS dedup guard, cache-hit
// rate limiter) reads the writer flag. Skipping MarkInternal on
// the hot path saves one context.valueCtx allocation per internal
// sub-query.
func MarkInternal(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalKeyVal, struct{}{})
}

// IsInternal reports whether ctx was tagged by MarkInternal.
// Intended for plugin middleware that wants a ctx-based internal
// signal; sdns's own middlewares read the writer flag instead.
func IsInternal(ctx context.Context) bool {
	return ctx.Value(internalKeyVal) != nil
}

// NewPipelineQueryer returns a Queryer that dispatches requests
// through sub. sub is expected to be the result of
// Pipeline.SubPipeline with client-only guards filtered out; this
// function does not validate its shape.
func NewPipelineQueryer(sub *Pipeline) Queryer {
	return &pipelineQueryer{sub: sub}
}

type pipelineQueryer struct {
	sub *Pipeline
}

func (q *pipelineQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// Generic recursion bound — see ErrMaxRecursion doc for the
	// motivation. A plugin middleware that dispatches an internal
	// sub-query from inside its own ServeDNS and ends up back in
	// itself (directly or via another handler) will hit this gate
	// instead of blowing the stack.
	depth, _ := ctx.Value(queryerDepthKey).(int)
	if depth >= maxQueryerRecursion {
		return nil, ErrMaxRecursion
	}
	ctx = context.WithValue(ctx, queryerDepthKey, depth+1)

	// The BufferWriter is propagated as internal via its
	// Internal() method (picked up by middleware.responseWriter's
	// Reset interface check), which is what every in-tree
	// consumer reads. MarkInternal/IsInternal remain a public
	// ctx-based API for plugin code that wants to tag internal
	// traffic without a writer in scope — not called here
	// because it would add a context.WithValue alloc per
	// sub-query on the hot path for no in-tree benefit.
	w := getBufferWriter()
	defer putBufferWriter(w)
	ch := q.sub.NewChain()
	defer q.sub.PutChain(ch)

	ch.Reset(w, req)
	ch.Next(ctx)

	// w.Msg() is evaluated for the return value before the
	// deferred putBufferWriter clears w.msg, and the *dns.Msg it
	// returns remains valid afterwards because the message is
	// heap-allocated and the caller now owns the reference. On
	// panic mid-chain, the defers still run and the pool stays
	// clean.
	if !w.Written() {
		return nil, ErrNoResponse
	}
	return w.Msg(), nil
}

// BufferWriter is the dns.ResponseWriter used inside Queryer.Query.
// It captures the response in memory and presents itself as a TCP
// connection so edns.ServeDNS picks the TCP-sized (MaxMsgSize) EDNS
// buffer rather than truncating internal replies at 512 bytes.
//
// Internal() always reports true. middleware.responseWriter.Reset
// propagates that through the interface check so the cache
// middleware's remaining Internal() branches keep behaving
// correctly during Phase 3 — those branches are replaced with
// queryer.IsInternal(ctx) in Phase 4.
type BufferWriter struct {
	msg    *dns.Msg
	local  *net.TCPAddr
	remote *net.TCPAddr
}

var (
	bufferLocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	// bufferRemoteAddr reuses the legacy internal sentinel IP so
	// plugins that still inspect RemoteAddr() see a familiar value.
	bufferRemoteAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 255), Port: 0}
)

// bufferWriterPool avoids a per-internal-query *BufferWriter alloc
// on the hot path. The zero-init constructor sets the shared
// package-level addrs; putBufferWriter clears the captured msg so
// the next user starts clean.
var bufferWriterPool = sync.Pool{
	New: func() any {
		return &BufferWriter{local: bufferLocalAddr, remote: bufferRemoteAddr}
	},
}

func getBufferWriter() *BufferWriter {
	return bufferWriterPool.Get().(*BufferWriter)
}

func putBufferWriter(w *BufferWriter) {
	w.msg = nil
	bufferWriterPool.Put(w)
}

// LocalAddr satisfies dns.ResponseWriter.
func (w *BufferWriter) LocalAddr() net.Addr { return w.local }

// RemoteAddr satisfies dns.ResponseWriter.
func (w *BufferWriter) RemoteAddr() net.Addr { return w.remote }

// WriteMsg captures m as the recorded response.
func (w *BufferWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

// Write unpacks b and captures the parsed message.
func (w *BufferWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	w.msg = m
	return len(b), nil
}

// Close satisfies dns.ResponseWriter.
func (w *BufferWriter) Close() error { return nil }

// TsigStatus satisfies dns.ResponseWriter.
func (w *BufferWriter) TsigStatus() error { return nil }

// TsigTimersOnly satisfies dns.ResponseWriter.
func (w *BufferWriter) TsigTimersOnly(bool) {}

// Hijack satisfies dns.ResponseWriter.
func (w *BufferWriter) Hijack() {}

// Msg returns the captured response (nil if the sub-pipeline never
// wrote).
func (w *BufferWriter) Msg() *dns.Msg { return w.msg }

// Written reports whether any middleware in the sub-pipeline wrote
// a response.
func (w *BufferWriter) Written() bool { return w.msg != nil }

// Proto is consulted by edns.ServeDNS to decide the UDP vs TCP EDNS
// buffer cap. Returning "tcp" keeps internal replies from being
// truncated at 512 bytes.
func (w *BufferWriter) Proto() string { return "tcp" }

// Internal reports this writer as belonging to an internal
// sub-pipeline run. middleware.responseWriter.Reset propagates it
// via the interface check.
func (w *BufferWriter) Internal() bool { return true }
