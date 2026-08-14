package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestTCPPipelinedBurst pins the burst layer's contract: a client that
// pipelines many queries on one connection gets every reply, matched to
// its query, and gets them without having to send anything further —
// the flush must happen when the connection is about to block, not on a
// timer and not on the next query.
func TestTCPPipelinedBurst(t *testing.T) {
	echo := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR(r.Question[0].Name + " 30 IN A 192.0.2.1")
		if err == nil {
			m.Answer = []dns.RR{rr}
		}
		_ = w.WriteMsg(m)
		return true
	})

	l := newTCPListener("127.0.0.1:0", echo, time.Second, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Bind(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve(ctx) }()
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = l.Shutdown(sctx)
	})

	deadline := time.Now().Add(3 * time.Second)
	for !l.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("listener never started serving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	l.mu.Lock()
	addr := l.ln.Addr().String()
	l.mu.Unlock()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// One burst, written before a single reply is read.
	const burst = 40
	names := make([]string, burst)
	var out []byte
	for i := range burst {
		names[i] = dns.Fqdn("q" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".burst.test")
		q := new(dns.Msg)
		q.SetQuestion(names[i], dns.TypeA)
		q.Id = uint16(1000 + i) //nolint:gosec // bounded test values
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(raw))) //nolint:gosec // bounded
		out = append(out, prefix[:]...)
		out = append(out, raw...)
	}
	if _, err := conn.Write(out); err != nil {
		t.Fatal(err)
	}

	// Every reply must arrive without another query being sent.
	buf := make([]byte, 65535)
	for i := range burst {
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			t.Fatalf("reply %d prefix: %v", i, err)
		}
		n := int(binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			t.Fatalf("reply %d body: %v", i, err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			t.Fatalf("reply %d unpack: %v", i, err)
		}
		if resp.Id != uint16(1000+i) { //nolint:gosec // bounded
			t.Fatalf("reply %d has id %d", i, resp.Id)
		}
		if len(resp.Question) != 1 || resp.Question[0].Name != names[i] {
			t.Fatalf("reply %d question %v, want %s", i, resp.Question, names[i])
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("reply %d answer %v", i, resp.Answer)
		}
	}

	// The connection stays usable for an ordinary single query after the
	// burst — the buffers reset cleanly between bursts.
	q := new(dns.Msg)
	q.SetQuestion("after.burst.test.", dns.TypeA)
	q.Id = 4242
	raw, _ := q.Pack()
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(raw))) //nolint:gosec // bounded
	if _, err := conn.Write(append(prefix[:], raw...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("single-query prefix after burst: %v", err)
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, buf[:n]); err != nil {
		t.Fatalf("single-query body after burst: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if resp.Id != 4242 {
		t.Fatalf("single-query reply id %d", resp.Id)
	}
}

// TestTCPStreamOversizedFrame pins the path around the fill buffer: a
// frame larger than it is read straight into the job, and a reply larger
// than the drain buffer is written on its own.
func TestTCPStreamOversizedFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := new(tcpStream)
	s.reset(server)

	payload := make([]byte, tcpFillSize*2)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() {
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(payload))) //nolint:gosec // bounded
		_, _ = client.Write(prefix[:])
		_, _ = client.Write(payload)
	}()

	got, err := s.next(2)
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.BigEndian.Uint16(got)) != len(payload) {
		t.Fatalf("prefix %v", got)
	}
	dst := make([]byte, len(payload))
	if err := s.body(dst); err != nil {
		t.Fatal(err)
	}
	for i := range dst {
		if dst[i] != payload[i] {
			t.Fatalf("oversized frame corrupted at %d", i)
		}
	}
}
