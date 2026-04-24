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

func TestQueryerMarksCtxInternal(t *testing.T) {
	rec := &recordingHandler{name: "rec", rcode: dns.RcodeSuccess}
	pipe := buildPipeline(t, rec)

	q := NewPipelineQueryer(pipe)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := q.Query(context.Background(), req); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !IsInternal(rec.sawCtx) {
		t.Fatal("handler observed ctx without IsInternal tag")
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
