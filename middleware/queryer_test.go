package middleware

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

func TestMarkAndIsInternal(t *testing.T) {
	ctx := context.Background()
	if IsInternal(ctx) {
		t.Fatal("fresh ctx must not be marked internal")
	}
	marked := MarkInternal(ctx)
	if !IsInternal(marked) {
		t.Fatal("MarkInternal should make IsInternal report true")
	}
	if IsInternal(ctx) {
		t.Fatal("MarkInternal must not mutate the original ctx")
	}
}

func TestBufferWriterPresentsAsTCP(t *testing.T) {
	w := getBufferWriter()
	if got := w.Proto(); got != "tcp" {
		t.Fatalf("Proto = %q, want \"tcp\" (edns uses this for buffer cap)", got)
	}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); !ok {
		t.Fatalf("RemoteAddr type = %T, want *net.TCPAddr", w.RemoteAddr())
	}
	if !w.Internal() {
		t.Fatal("BufferWriter.Internal must return true so responseWriter propagation works")
	}
	if w.Written() {
		t.Fatal("fresh BufferWriter must not be Written")
	}
}

func TestBufferWriterCapturesMsg(t *testing.T) {
	w := getBufferWriter()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeServerFailure

	if err := w.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if !w.Written() {
		t.Fatal("Written should be true after WriteMsg")
	}
	got := w.Msg()
	if got == nil {
		t.Fatal("Msg returned nil after WriteMsg")
	}
	if got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("captured rcode = %d, want SERVFAIL", got.Rcode)
	}
}

// TestBufferWriterWriteUnpacks covers the Write([]byte) path —
// used when a middleware calls Write with packed DNS bytes instead
// of WriteMsg (uncommon in-tree, supported for
// dns.ResponseWriter-interface completeness).
func TestBufferWriterWriteUnpacks(t *testing.T) {
	src := new(dns.Msg)
	src.SetQuestion("example.com.", dns.TypeA)
	src.Rcode = dns.RcodeSuccess
	packed, err := src.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	w := getBufferWriter()
	n, err := w.Write(packed)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(packed) {
		t.Fatalf("Write returned %d, want %d", n, len(packed))
	}
	if !w.Written() || w.Msg() == nil {
		t.Fatal("BufferWriter should hold captured msg after Write")
	}

	// Malformed bytes must surface as an unpack error without
	// mutating writer state.
	w = getBufferWriter()
	if _, err := w.Write([]byte{0xff, 0xff}); err == nil {
		t.Fatal("Write of garbage bytes should error")
	}
	if w.Written() {
		t.Fatal("failed Write must not flip Written")
	}
}

// TestBufferWriterInterfaceMethods covers the remaining
// dns.ResponseWriter satisfiers (LocalAddr, Close, TsigStatus,
// TsigTimersOnly, Hijack). They are no-ops/stubs in our
// in-memory writer; exercising them ensures the interface is
// actually satisfied and guards against accidental signature
// drift.
func TestBufferWriterInterfaceMethods(t *testing.T) {
	w := getBufferWriter()

	if w.LocalAddr() == nil {
		t.Fatal("LocalAddr must be non-nil for dns.ResponseWriter consumers")
	}
	if _, ok := w.LocalAddr().(*net.TCPAddr); !ok {
		t.Fatalf("LocalAddr type = %T, want *net.TCPAddr", w.LocalAddr())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close returned %v, want nil (no-op on in-memory writer)", err)
	}
	if err := w.TsigStatus(); err != nil {
		t.Fatalf("TsigStatus returned %v, want nil", err)
	}
	// TsigTimersOnly + Hijack return nothing; just confirm no panic.
	w.TsigTimersOnly(true)
	w.Hijack()
}

// recordingHandler captures the ctx it was invoked with and writes a
// SERVFAIL reply. Used to verify that Queryer runs its sub-pipeline
// under a ctx marked IsInternal and that DNS-layer failures surface
// as *dns.Msg rather than Go error.
type recordingHandler struct {
	name   string
	sawCtx context.Context
	rcode  int
}

func (h *recordingHandler) Name() string { return h.name }
func (h *recordingHandler) ServeDNS(ctx context.Context, ch *Chain) {
	h.sawCtx = ctx
	reply := new(dns.Msg)
	reply.SetReply(ch.Request)
	reply.Rcode = h.rcode
	_ = ch.Writer.WriteMsg(reply)
}

// silentHandler satisfies Handler but never writes. Used
// to exercise the Queryer "no response" path.
type silentHandler struct{ name string }

func (h *silentHandler) Name() string                          { return h.name }
func (h *silentHandler) ServeDNS(_ context.Context, ch *Chain) { ch.Cancel() }

func buildPipeline(t *testing.T, handlers ...Handler) *Pipeline {
	t.Helper()
	Reset()
	t.Cleanup(Reset)
	for _, h := range handlers {
		DefaultRegistry.Register(h.Name(), func(_ *config.Config) Handler { return h })
	}
	// Build requires a *config.Config but none of these handlers
	// consume it — a zero-value pointer is safe.
	Setup(&config.Config{})
	return GlobalPipeline()
}

func TestQueryerReturnsServfailAsMsg(t *testing.T) {
	rec := &recordingHandler{name: "rec", rcode: dns.RcodeServerFailure}
	pipe := buildPipeline(t, rec)

	q := NewPipelineQueryer(pipe)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := q.Query(context.Background(), req)
	if err != nil {
		t.Fatalf("Query returned error on DNS-layer SERVFAIL: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("resp rcode = %v, want SERVFAIL *dns.Msg", resp)
	}
}

// TestQueryerUsesWriterFlagNotCtx pins the Phase-6-perf behaviour
// that Query does NOT call MarkInternal on the ctx: the internal
// signal is the BufferWriter's Internal() method, which every
// in-tree consumer reads. MarkInternal / IsInternal remain a
// public ctx-based API for plugin code that prefers a ctx signal.
func TestQueryerUsesWriterFlagNotCtx(t *testing.T) {
	rec := &recordingHandler{name: "rec", rcode: dns.RcodeSuccess}
	pipe := buildPipeline(t, rec)

	q := NewPipelineQueryer(pipe)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := q.Query(context.Background(), req); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if IsInternal(rec.sawCtx) {
		t.Fatal("Query should not mark ctx; consumers should read the writer flag")
	}
}

func TestQueryerReturnsErrOnNoResponse(t *testing.T) {
	pipe := buildPipeline(t, &silentHandler{name: "silent"})
	q := NewPipelineQueryer(pipe)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	_, err := q.Query(context.Background(), req)
	if !errors.Is(err, ErrNoResponse) {
		t.Fatalf("err = %v, want ErrNoResponse", err)
	}
}

// reentrantHandler calls the injected queryer from its own
// ServeDNS, simulating a plugin middleware that dispatches an
// internal sub-query from inside its handler. Without a generic
// recursion bound this would loop forever; the
// maxQueryerRecursion gate must fail the nested call with
// ErrMaxRecursion. sawMaxErr is sticky so ErrMaxRecursion at any
// depth is observable from the outermost test, regardless of
// how subsequent unwinding handlers behave.
type reentrantHandler struct {
	name      string
	q         Queryer
	sawMaxErr bool
	depth     int
}

func (h *reentrantHandler) Name() string { return h.name }
func (h *reentrantHandler) ServeDNS(ctx context.Context, ch *Chain) {
	h.depth++
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	_, err := h.q.Query(ctx, req)
	if errors.Is(err, ErrMaxRecursion) {
		h.sawMaxErr = true
	}
	// Write a trivial reply so the outer Query unwinds with a
	// response instead of ErrNoResponse — the point of the test
	// is the inner cap fires, not the outer one.
	reply := new(dns.Msg)
	reply.SetReply(ch.Request)
	_ = ch.Writer.WriteMsg(reply)
}

func TestQueryerRecursionBoundCatchesReentry(t *testing.T) {
	h := &reentrantHandler{name: "reentrant"}
	pipe := buildPipeline(t, h)
	h.q = NewPipelineQueryer(pipe)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	_, err := h.q.Query(context.Background(), req)
	if err != nil {
		t.Fatalf("outer Query returned err; expected unwind via inner depth-cap failure: %v", err)
	}
	if !h.sawMaxErr {
		t.Fatal("inner recursion never observed ErrMaxRecursion; depth bound did not fire")
	}
	if h.depth > maxQueryerRecursion+1 {
		t.Fatalf("handler invoked %d times; want at most %d (bound + 1 outer)", h.depth, maxQueryerRecursion+1)
	}
}

func BenchmarkPipelineQueryerQuery(b *testing.B) {
	rec := &recordingHandler{name: "rec", rcode: dns.RcodeSuccess}
	pipe := buildBenchPipeline(b, rec)
	q := NewPipelineQueryer(pipe)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = q.Query(ctx, req)
	}
}

func buildBenchPipeline(b *testing.B, handlers ...Handler) *Pipeline {
	b.Helper()
	Reset()
	b.Cleanup(Reset)
	for _, h := range handlers {
		DefaultRegistry.Register(h.Name(), func(_ *config.Config) Handler { return h })
	}
	Setup(&config.Config{})
	return GlobalPipeline()
}
