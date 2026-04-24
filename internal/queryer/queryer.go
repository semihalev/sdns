// Package queryer runs a DNS request through an internal sub-pipeline
// — typically every middleware from the "answer surface" inward
// (hostsfile, blocklist, as112, kubernetes, cache, failover, and the
// resolver or forwarder) with client-only guards filtered out
// (metrics, dnstap, accesslist, ratelimit, reflex, accesslog, loop).
//
// It replaces the top-of-chain re-entry behaviour of
// util.ExchangeInternal with a deliberately narrower sub-pipeline,
// driven by a BufferWriter rather than a sentinel-address mock.
// The sub-pipeline is constructed once at startup by sdns.go; a
// single BufferWriter per Query() captures the downstream reply.
//
// DNS-layer outcomes (SERVFAIL, REFUSED, NXDOMAIN, etc.) come back
// as a *dns.Msg. ErrNoResponse is returned only when the
// sub-pipeline completes without any middleware calling WriteMsg —
// mirroring util.ExchangeInternal's "no replied any message" so
// existing callers can distinguish wire-level failures from
// executor failures.
package queryer

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// Queryer answers a client-shaped DNS query through the internal
// sub-pipeline.
type Queryer interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// ErrNoResponse signals that the sub-pipeline ran without any
// middleware writing a response.
var ErrNoResponse = errors.New("queryer: no response written")

// internalCtxKey tags contexts originating inside a Queryer.Query
// invocation. Sentinel value so lookups avoid allocation from
// context.WithValue boxing an interface.
type internalCtxKey struct{}

var internalKeyVal = &internalCtxKey{}

// MarkInternal returns a derived ctx tagged as originating from an
// internal sub-pipeline run. Middleware that skips client-only
// guards (cache-hit rate limit, dedup join) consults IsInternal
// instead of the deprecated ResponseWriter.Internal() flag.
func MarkInternal(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalKeyVal, struct{}{})
}

// IsInternal reports whether ctx was tagged by MarkInternal.
func IsInternal(ctx context.Context) bool {
	return ctx.Value(internalKeyVal) != nil
}

// NewPipelineQueryer returns a Queryer that dispatches requests
// through sub. sub is expected to be the result of
// middleware.Pipeline.SubPipeline with client-only guards filtered
// out; this function does not validate its shape.
func NewPipelineQueryer(sub *middleware.Pipeline) Queryer {
	return &pipelineQueryer{sub: sub}
}

type pipelineQueryer struct {
	sub *middleware.Pipeline
}

func (q *pipelineQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx = MarkInternal(ctx)
	w := newBufferWriter()
	ch := q.sub.NewChain()
	ch.Reset(w, req)
	ch.Next(ctx)
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

func newBufferWriter() *BufferWriter {
	return &BufferWriter{local: bufferLocalAddr, remote: bufferRemoteAddr}
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
