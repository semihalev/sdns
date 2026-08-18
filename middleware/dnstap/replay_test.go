package dnstap

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func newTapForFrames(t *testing.T) *Dnstap {
	t.Helper()
	d := &Dnstap{
		identity:     []byte("test"),
		version:      []byte("test"),
		logQueries:   true,
		logResponses: true,
		messageQueue: make(chan *DnstapMessage, 16),
	}
	r, w := net.Pipe()
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	d.mu.Lock()
	d.conn = w
	d.mu.Unlock()
	return d
}

func wireBornChain(t *testing.T, next middleware.Handler) (*middleware.Chain, []byte) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("tap.example.", dns.TypeA)
	q.SetEdns0(1232, false)
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	ch := middleware.NewChain([]middleware.Handler{next})
	ch.ResetWire(mock.NewWriter("udp", "203.0.113.70:5353"), req)
	return ch, raw
}

func drainFrames(d *Dnstap) []*DnstapMessage {
	var out []*DnstapMessage
	for {
		select {
		case m := <-d.messageQueue:
			out = append(out, m)
		default:
			return out
		}
	}
}

// A connected tap must stay on the byte path: the query frame comes from
// an owned copy of the wire bytes, the request stays undecoded for the
// handlers below (the cache's wire ladder among them), and the response
// frame comes from the writer wrapper.
func TestDnstapWireBornStaysUndecoded(t *testing.T) {
	d := newTapForFrames(t)

	undecodedBelow := false
	next := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		undecodedBelow = ch.Request.Undecoded()
		ctx, req := ch.Materialize(ctx)
		if req == nil {
			return
		}
		_ = ctx
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	ch, raw := wireBornChain(t, next)
	d.ServeDNS(context.Background(), ch)

	if !undecodedBelow {
		t.Fatal("connected tap materialized a wire-born request")
	}
	frames := drainFrames(d)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want query + response", len(frames))
	}
	if frames[0].Type != MessageTypeQuery || !bytes.Equal(frames[0].QueryMessage, raw) {
		t.Fatal("query frame does not carry the verbatim wire bytes")
	}
	if frames[1].Type != MessageTypeResponse || len(frames[1].ResponseMsg) == 0 {
		t.Fatal("response frame missing or empty")
	}
}

// The replay pass finishes a query the inline pass already tapped: no
// second query frame — but the response wrapper still installs, because
// the replay is the pass that writes.
func TestDnstapReplayEmitsOnlyResponseFrame(t *testing.T) {
	d := newTapForFrames(t)

	next := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		ctx, req := ch.Materialize(ctx)
		if req == nil {
			return
		}
		_ = ctx
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	ch, _ := wireBornChain(t, next)
	ch.SetReplay()
	d.ServeDNS(context.Background(), ch)

	frames := drainFrames(d)
	if len(frames) != 1 {
		t.Fatalf("got %d frames on the replay pass, want the response alone", len(frames))
	}
	if frames[0].Type != MessageTypeResponse {
		t.Fatalf("replay pass emitted a %v frame, want response", frames[0].Type)
	}
}
