package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestUDPShutdownDrainsInFlight pins the shutdown order: a request that
// was already being served when Shutdown started must still be answered.
// Closing the sockets to stop admission also took away the socket the
// reply had to leave through, so the client saw a timeout instead.
func TestUDPShutdownDrainsInFlight(t *testing.T) {
	serving := make(chan struct{})
	proceed := make(chan struct{})

	slow := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		// Announce that the request is in flight, then wait for the test
		// to begin shutting the listener down before answering.
		select {
		case serving <- struct{}{}:
		default:
		}
		<-proceed
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	})

	l := newUDPListener("127.0.0.1:0", slow, 5*time.Second, 2, 16, defaultResourcePlan(1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Bind(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for !l.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("listener never started serving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	l.mu.Lock()
	addr := l.pcs[0].LocalAddr().String()
	l.mu.Unlock()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	q := new(dns.Msg)
	q.SetQuestion("drain.zero.test.", dns.TypeA)
	q.Id = 0x5151
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}

	select {
	case <-serving:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never received the query")
	}

	// Shutdown begins while the request is mid-flight; the handler then
	// answers into a listener that is draining.
	done := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		done <- l.Shutdown(sctx)
	}()
	time.Sleep(50 * time.Millisecond)
	close(proceed)

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("in-flight request was dropped by shutdown: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if resp.Id != q.Id {
		t.Fatalf("reply id %#x, want %#x", resp.Id, q.Id)
	}

	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
