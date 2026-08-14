package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestUDPSilentTerminalDoesNotResendAStaleReply pins the one thing a
// recycled slab must never do: answer a request that was decided in
// silence.
//
// A malformed packet gets no reply by design — any answer to an
// unparseable header is amplification, and the library keeps quiet for
// the same reason. But the slab serving it has served before, and if the
// staged reply from that earlier request is still in its TX, the burst
// sends those bytes to whoever holds the slab now. That is another
// client's answer delivered to an address that never asked for it.
func TestUDPSilentTerminalDoesNotResendAStaleReply(t *testing.T) {
	echo := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR(r.Question[0].Name + " 30 IN A 198.51.100.7")
		if err == nil {
			m.Answer = []dns.RR{rr}
		}
		_ = w.WriteMsg(m)
		return true
	})

	addr, stop := startEngine(t, echo, 1, 1)
	defer stop()

	// Cycle the ring: every slab must have staged a reply at least once,
	// so whichever one takes the malformed packet is carrying one.
	served, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer served.Close()
	buf := make([]byte, 65535)
	for i := range 128 {
		q := new(dns.Msg)
		q.SetQuestion("warm.stale.test.", dns.TypeA)
		q.Id = uint16(9000 + i) //nolint:gosec // bounded test values
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := served.Write(raw); err != nil {
			t.Fatal(err)
		}
		_ = served.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := served.Read(buf)
		if err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
	}

	// A fresh client, so anything that arrives was addressed to someone
	// else. One byte is not a header, so this reaches the silent
	// terminal.
	quiet, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	if _, err := quiet.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}
	_ = quiet.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := quiet.Read(buf)
	if err == nil {
		t.Fatalf("a malformed packet drew a %d-byte reply: % x — the slab "+
			"sent the answer it was still carrying for another client", n, buf[:n])
	}
	if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
		t.Fatalf("read error %v, want a timeout (silence)", err)
	}
}
