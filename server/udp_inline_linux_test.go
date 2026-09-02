//go:build linux

package server

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// The batch reader's inline path, end to end over real sockets: hits
// finish on the reader and ride the cycle's transmit burst, handoffs
// travel the ring and finish on a worker via ServeRawReplay, a panicking
// inline serve is dropped without killing the reader, and through all of
// it the in-flight accounting balances, which the quiescence barrier at
// the end proves. The pre-fix engine failed exactly there: every inline
// terminal decremented a count enqueue never incremented, so Quiesced()
// was false forever after the first inline serve.

type inlineStubHandler struct {
	inlineServed atomic.Int64
	replayServed atomic.Int64
}

func (h *inlineStubHandler) InlineReady() bool { return true }

func (h *inlineStubHandler) answer(w middleware.Transport, raw []byte) bool {
	r := new(dns.Msg)
	if err := r.Unpack(raw); err != nil {
		return false
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 60},
		A: net.IPv4(192, 0, 2, 2),
	})
	_ = w.WriteMsg(m)
	return true
}

func (h *inlineStubHandler) ServeRaw(w middleware.Transport, raw []byte, _ time.Time) bool {
	return h.answer(w, raw)
}

func (h *inlineStubHandler) ServeRawInline(w middleware.Transport, raw []byte, _ time.Time) bool {
	r := new(dns.Msg)
	if err := r.Unpack(raw); err != nil {
		return true
	}
	name := r.Question[0].Name
	switch {
	case strings.HasPrefix(name, "panic."):
		panic("inline stub panic")
	case strings.HasPrefix(name, "miss."):
		return false
	}
	if h.answer(w, raw) {
		h.inlineServed.Add(1)
	}
	return true
}

func (h *inlineStubHandler) ServeRawReplay(w middleware.Transport, raw []byte, _ time.Time) bool {
	if h.answer(w, raw) {
		h.replayServed.Add(1)
	}
	return true
}

func TestUDPInlineServeEndToEnd(t *testing.T) {
	stub := &inlineStubHandler{}
	l := newUDPListener("127.0.0.1:0", stub, time.Second, 4, 64, defaultResourcePlan(1))
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for !l.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.Serving() {
		t.Fatal("engine did not start serving")
	}
	defer func() {
		if err := l.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("serve did not return after shutdown")
		}
	}()

	addr := l.pcs[0].LocalAddr().String()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	exchange := func(name string, id uint16) (*dns.Msg, error) {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		q.Id = id
		wire, _ := q.Pack()
		if _, err := conn.Write(wire); err != nil {
			return nil, err
		}
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		m := new(dns.Msg)
		if err := m.Unpack(buf[:n]); err != nil {
			return nil, err
		}
		return m, nil
	}

	// Inline hits and ring handoffs, interleaved.
	for i := 0; i < 50; i++ {
		name := "hit.example."
		if i%2 == 1 {
			name = "miss.example."
		}
		m, err := exchange(name, uint16(1000+i)) //nolint:gosec // bounded test loop
		if err != nil {
			t.Fatalf("query %d (%s): %v", i, name, err)
		}
		if m.Id != uint16(1000+i) || len(m.Answer) != 1 { //nolint:gosec // bounded test loop
			t.Fatalf("query %d (%s): bad reply %v", i, name, m)
		}
	}
	if stub.inlineServed.Load() == 0 {
		t.Fatal("no query served on the inline path")
	}
	if stub.replayServed.Load() == 0 {
		t.Fatal("no handoff finished on the replay path")
	}

	// A panicking inline serve drops the query and nothing else: no
	// reply for it, and the reader keeps serving.
	q := new(dns.Msg)
	q.SetQuestion("panic.example.", dns.TypeA)
	q.Id = 9999
	wire, _ := q.Pack()
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("panicked inline serve produced a reply")
	}
	if m, err := exchange("hit.example.", 424); err != nil || m.Id != 424 {
		t.Fatalf("reader did not survive the inline panic: %v", err)
	}

	// The balance proof: with the load stopped, every slab must return
	// to the ring. An inline terminal that decrements what enqueue never
	// incremented keeps this false forever.
	settle := time.Now().Add(2 * time.Second)
	for !l.Quiesced() && time.Now().Before(settle) {
		time.Sleep(10 * time.Millisecond)
	}
	if !l.Quiesced() {
		t.Fatal("engine did not quiesce after inline traffic: the in-flight accounting leaked")
	}
}
