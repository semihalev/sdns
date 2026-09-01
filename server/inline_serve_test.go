package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/defaults"
)

// The inline serve contract: ServeRawInline finishes a warm wire hit on
// the caller's goroutine, hands off what needs a worker unwritten, and
// ServeRawReplay finishes the handoff with the replay mark visible to
// every handler that runs.

// replayWitness stands at the pipeline tail in the resolver's place. The
// inline pass hands off at the cache, so every invocation this handler
// sees must carry the replay mark, a call without it means the inline
// pass ran past the barrier.
type replayWitness struct {
	calls        int
	replayCalls  int
	inlineOnlyAt int
	respond      func(req *dns.Msg) *dns.Msg
}

func (rw *replayWitness) Name() string { return "replay-witness" }

func (rw *replayWitness) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	rw.calls++
	if ch.Replay() {
		rw.replayCalls++
	}
	if ch.InlineOnly() {
		rw.inlineOnlyAt++
	}
	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	_ = ctx
	_ = ch.Writer.WriteMsg(rw.respond(req))
	ch.Cancel()
}

func newInlineTestServer(t *testing.T, witness *replayWitness) *Server {
	t.Helper()
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	defaults.RegisterUpTo("resolver")
	middleware.Register("replay-witness", func(*config.Config) middleware.Handler { return witness })

	cfg := &config.Config{ //nolint:gosec // G101, the cookie secret is a test fixture, not a credential
		Bind:         "127.0.0.1:0",
		Expire:       600,
		CacheSize:    10240,
		CookieSecret: "6c6f6f6b61686172646c6f6f6b6168617264",
	}
	cfg.QueryTimeout.Duration = 10 * time.Second
	middleware.Setup(cfg)
	return New(cfg)
}

func stubAnswer(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 77),
	}}
	return resp
}

func TestServeRawInlineContract(t *testing.T) {
	witness := &replayWitness{respond: stubAnswer}
	s := newInlineTestServer(t, witness)

	if !s.InlineReady() {
		t.Fatal("pipeline with the cache must report inline-ready")
	}

	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 40), Port: 4242}}

	// Cold query: the inline pass must stop at the cache, unwritten,
	// handed off, and the resolver stand-in untouched.
	raw := packRawQuery(t, "inline.zero.test.", true)
	if s.ServeRawInline(job, raw, time.Now()) {
		t.Fatal("cold query claimed handled on the inline pass")
	}
	if len(job.wrote) != 0 {
		t.Fatalf("inline handoff left %d written bytes", len(job.wrote))
	}
	if witness.calls != 0 {
		t.Fatalf("inline pass ran past the cache barrier: %d resolver calls", witness.calls)
	}

	// The replay finishes it, and the tail handler sees the replay mark.
	if !s.ServeRawReplay(job, raw, time.Now()) {
		t.Fatal("replay did not handle the handed-off query")
	}
	if witness.calls != 1 || witness.replayCalls != 1 {
		t.Fatalf("replay pass reached the tail %d times, %d with the mark; want 1 and 1",
			witness.calls, witness.replayCalls)
	}
	if witness.inlineOnlyAt != 0 {
		t.Fatal("replay pass still carried the inline-only mark")
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(job.wrote); err != nil {
		t.Fatalf("replay reply unpack: %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
		t.Fatalf("replay reply wrong: rcode=%d answers=%d", reply.Rcode, len(reply.Answer))
	}

	// Warm now: the inline pass serves the wire hit itself, no handoff,
	// no resolver call.
	job.wrote = job.wrote[:0]
	if !s.ServeRawInline(job, raw, time.Now()) {
		t.Fatal("warm hit not served on the inline pass")
	}
	if witness.calls != 1 {
		t.Fatalf("warm inline serve reached the resolver: %d calls", witness.calls)
	}
	hit := new(dns.Msg)
	if err := hit.Unpack(job.wrote); err != nil {
		t.Fatalf("inline hit unpack: %v", err)
	}
	if hit.Rcode != dns.RcodeSuccess || len(hit.Answer) == 0 {
		t.Fatalf("inline hit wrong: rcode=%d answers=%d", hit.Rcode, len(hit.Answer))
	}
	if hit.Id != reply.Id {
		t.Fatalf("inline hit ID %d does not echo the query ID %d", hit.Id, reply.Id)
	}
}

// A pipeline without an inline barrier (no cache) must refuse the fast
// path outright: nothing in it can stop the reader short of blocking
// work, and the engines consult InlineReady before wiring serveInline.
func TestInlineReadyRequiresBarrier(t *testing.T) {
	s := newRawTestServer(t)
	if s.InlineReady() {
		t.Fatal("pipeline without an inline barrier reported inline-ready")
	}
}
