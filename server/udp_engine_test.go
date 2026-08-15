package server

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// rawHandlerFunc adapts a func to the server's rawHandler interface for
// test stubs. Shared by every in-package test that feeds the engines.
type rawHandlerFunc func(middleware.Transport, []byte, time.Time) bool

func (f rawHandlerFunc) ServeRaw(w middleware.Transport, raw []byte, t time.Time) bool {
	return f(w, raw, t)
}

// startEngine binds an owned UDP listener around handler and returns the
// client-facing address and a shutdown func.
func startEngine(t *testing.T, handler rawHandler, workers, queue int) (string, func()) {
	t.Helper()
	l := newUDPListener("127.0.0.1:0", handler, time.Second, workers, queue)
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(context.Background()) }()
	// Wait for serving.
	deadline := time.Now().Add(2 * time.Second)
	for !l.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.Serving() {
		t.Fatal("engine did not start serving")
	}
	addr := l.pcs[0].LocalAddr().String()
	return addr, func() {
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
	}
}

func echoHandler() rawHandler {
	return rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 60},
			A: net.IPv4(192, 0, 2, 1),
		})
		_ = w.WriteMsg(m)
		return true
	})
}

func TestUDPEngineServes(t *testing.T) {
	addr, stop := startEngine(t, echoHandler(), 4, 64)
	defer stop()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for i := 0; i < 100; i++ {
		q := new(dns.Msg)
		q.SetQuestion("engine.example.", dns.TypeA)
		q.Id = uint16(100 + i)
		wire, _ := q.Pack()
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		var r dns.Msg
		if err := r.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if r.Id != q.Id || len(r.Answer) != 1 {
			t.Fatalf("query %d: bad reply %v", i, r)
		}
	}
}

// TestUDPEngineAcceptParity pins the library server's pre-handler
// semantics on raw datagrams: silence for garbage and responses, NOTIMP
// for foreign opcodes, FORMERR for count violations and undecodable
// bodies — with ID, opcode, and RD echoed on rejects.
func TestUDPEngineAcceptParity(t *testing.T) {
	handlerCalled := make(chan struct{}, 16)
	addr, stop := startEngine(t, rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		handlerCalled <- struct{}{}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	}), 2, 16)
	defer stop()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expectSilence := func(name string, pkt []byte) {
		t.Helper()
		if _, err := conn.Write(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, err := conn.Read(buf); err == nil {
			t.Fatalf("%s: got %d-byte reply, want silence", name, n)
		}
		select {
		case <-handlerCalled:
			t.Fatalf("%s: handler ran", name)
		default:
		}
	}
	expectRcode := func(name string, pkt []byte, rcode int) {
		t.Helper()
		if _, err := conn.Write(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("%s: no reply: %v", name, err)
		}
		if n < 12 {
			t.Fatalf("%s: short reply", name)
		}
		if got := int(buf[3] & 0x0F); got != rcode {
			t.Fatalf("%s: rcode %d, want %d", name, got, rcode)
		}
		if buf[2]&0x80 == 0 {
			t.Fatalf("%s: QR not set", name)
		}
		if binary.BigEndian.Uint16(buf[0:2]) != binary.BigEndian.Uint16(pkt[0:2]) {
			t.Fatalf("%s: ID not echoed", name)
		}
		select {
		case <-handlerCalled:
			t.Fatalf("%s: handler ran", name)
		default:
		}
	}

	header := func(id uint16, flags uint16, qd, an, ns, ar uint16) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[0:2], id)
		binary.BigEndian.PutUint16(b[2:4], flags)
		binary.BigEndian.PutUint16(b[4:6], qd)
		binary.BigEndian.PutUint16(b[6:8], an)
		binary.BigEndian.PutUint16(b[8:10], ns)
		binary.BigEndian.PutUint16(b[10:12], ar)
		return b
	}

	expectSilence("short garbage", []byte{0x01, 0x02, 0x03})
	expectSilence("qr set", header(7, 0x8000, 1, 0, 0, 0))
	expectRcode("update opcode", header(8, uint16(dns.OpcodeUpdate)<<11, 0, 0, 0, 0), dns.RcodeNotImplemented)
	expectRcode("qdcount 2", header(9, 0, 2, 0, 0, 0), dns.RcodeFormatError)
	expectRcode("ancount 2", header(10, 0, 1, 2, 0, 0), dns.RcodeFormatError)
	expectRcode("arcount 3", header(11, 0, 1, 0, 0, 3), dns.RcodeFormatError)
	// Accepted header, undecodable body: a question name whose compression
	// pointer points at itself never decodes.
	expectRcode("bad body", append(header(12, 0, 1, 0, 0, 0), 0xC0, 0x0C, 0, 1, 0, 1), dns.RcodeFormatError)

	// Library parity quirk, pinned deliberately: Unpack tolerates a
	// truncated question section (QDCOUNT=1, no bytes), so the packet
	// reaches the handler with an empty question — where the real
	// pipeline's ingress guard answers FORMERR (Test_ServerEmptyQuestion).
	{
		pkt := header(13, 0, 1, 0, 0, 0)
		if _, err := conn.Write(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("tolerated truncation: no reply: %v", err)
		}
		select {
		case <-handlerCalled:
		case <-time.After(time.Second):
			t.Fatal("tolerated truncation did not reach the handler")
		}
	}

	// A healthy query still reaches the handler afterwards.
	q := new(dns.Msg)
	q.SetQuestion("ok.example.", dns.TypeA)
	q.Id = 99
	wire, _ := q.Pack()
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("healthy query: %v", err)
	}
	select {
	case <-handlerCalled:
	case <-time.After(time.Second):
		t.Fatal("healthy query never reached the handler")
	}
}

// TestUDPEngineShedsWhenSaturated pins the load-shedding contract: with a
// blocked handler, an empty ring and the stretch at its bound, excess
// packets are dropped while the reader keeps consuming — and the engine
// drains cleanly afterwards.
func TestUDPEngineShedsWhenSaturated(t *testing.T) {
	// Saturation is the ring and the stretch together, so the bound is
	// lowered here rather than standing up thousands of blocked requests
	// to reach the real one. Set before the engine exists and restored
	// after it is gone: nothing reads it in between.
	defer func(n int64) { maxSpareSlabs = n }(maxSpareSlabs)
	maxSpareSlabs = 2

	release := make(chan struct{})
	addr, stop := startEngine(t, rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		<-release
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	}), 2, 4)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	before := udpDropFull.Value()
	q := new(dns.Msg)
	q.SetQuestion("flood.example.", dns.TypeA)
	wire, _ := q.Pack()
	// What bounds this is the ring plus the stretch: two workers, four
	// queued, a batch in the reader's hand, and the spares above. A packet
	// arriving with no slab left anywhere must be shed rather than block
	// the reader — saturation costs drops, never the socket. (Neither a
	// full queue nor an empty ring is a drop on its own: the first is
	// served on its own goroutine and the second borrows a spare, which is
	// what a miss-heavy resolver needs and what a fixed ring used to cap.)
	for i := 0; i < 200; i++ {
		binary.BigEndian.PutUint16(wire[0:2], uint16(i+1))
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for udpDropFull.Value() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if udpDropFull.Value() == before {
		t.Fatal("saturation produced no shed drops")
	}

	close(release) // let the blocked handlers finish, then drain
	stop()
}
