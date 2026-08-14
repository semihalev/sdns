package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTCPEngine(t *testing.T, handler dns.Handler, maxConns int) (string, *tcpListener, func()) {
	t.Helper()
	l := newTCPListener("127.0.0.1:0", handler, time.Second, maxConns)
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for !l.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	addr := l.ln.Addr().String()
	return addr, l, func() {
		if err := l.Shutdown(context.Background()); err != nil {
			t.Logf("shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			t.Error("serve did not return after shutdown")
		}
	}
}

func writeFrame(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed, uint16(len(payload))) //nolint:gosec // fixture payloads are small
	copy(framed[2:], payload)
	if _, err := conn.Write(framed); err != nil {
		t.Fatal(err)
	}
}

func readFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var prefix [2]byte
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

func TestTCPEngineServesSerially(t *testing.T) {
	addr, _, stop := startTCPEngine(t, echoHandler(), 8)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for i := 0; i < 200; i++ {
		q := new(dns.Msg)
		q.SetQuestion("tcp.example.", dns.TypeA)
		q.Id = uint16(1 + i)
		wireQ, _ := q.Pack()
		writeFrame(t, conn, wireQ)
		var r dns.Msg
		if err := r.Unpack(readFrame(t, conn)); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if r.Id != q.Id || len(r.Answer) != 1 {
			t.Fatalf("query %d: wrong reply", i)
		}
	}
}

// TestTCPEnginePrefixFirstHoldsNoJob pins the idle-connection property:
// connections that have sent nothing pin no large-class slab.
func TestTCPEnginePrefixFirstHoldsNoJob(t *testing.T) {
	addr, l, stop := startTCPEngine(t, echoHandler(), 64)
	defer stop()

	var idle []net.Conn
	for i := 0; i < 32; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, conn)
		defer conn.Close()
	}
	// Give the accept loop a moment to admit them all.
	deadline := time.Now().Add(2 * time.Second)
	for l.engine.active.Load() < 32 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := l.engine.active.Load(); got != 32 {
		t.Fatalf("admitted %d conns, want 32", got)
	}
	// Every job is still in the ring: idle connections acquired nothing.
	if free := len(l.engine.free); free != defaultTCPJobs {
		t.Fatalf("%d jobs free, want %d — idle connections pinned slabs", free, defaultTCPJobs)
	}
	// And they still serve.
	q := new(dns.Msg)
	q.SetQuestion("idle.example.", dns.TypeA)
	wireQ, _ := q.Pack()
	writeFrame(t, idle[7], wireQ)
	var r dns.Msg
	if err := r.Unpack(readFrame(t, idle[7])); err != nil {
		t.Fatal(err)
	}
}

func TestTCPEngineConnectionCap(t *testing.T) {
	release := make(chan struct{})
	addr, _, stop := startTCPEngine(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		<-release
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	}), 4)
	defer stop()
	defer close(release)

	for i := 0; i < 4; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	before := tcpDropConnCap.Value()
	deadline := time.Now().Add(3 * time.Second)
	for tcpDropConnCap.Value() == before && time.Now().Before(deadline) {
		extra, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		// The engine closes over-cap conns immediately; a read shows it.
		_ = extra.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		var b [1]byte
		_, _ = extra.Read(b[:])
		_ = extra.Close()
	}
	if tcpDropConnCap.Value() == before {
		t.Fatal("connection cap never rejected")
	}
}

// TestTCPEngineSubHeaderFrameCloses pins the fatal-reject rule for streams.
func TestTCPEngineSubHeaderFrameCloses(t *testing.T) {
	addr, _, stop := startTCPEngine(t, echoHandler(), 8)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeFrame(t, conn, []byte{1, 2, 3}) // < header size
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("connection stayed open after a sub-header frame")
	}
}

// TestTCPEngineAcceptParityOverStream pins reject shapes on TCP: NOTIMP
// for foreign opcodes, FORMERR for count violations, session continues.
func TestTCPEngineAcceptParityOverStream(t *testing.T) {
	addr, _, stop := startTCPEngine(t, echoHandler(), 8)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	header := func(id uint16, flags uint16, qd uint16) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[0:2], id)
		binary.BigEndian.PutUint16(b[2:4], flags)
		binary.BigEndian.PutUint16(b[4:6], qd)
		return b
	}

	writeFrame(t, conn, header(21, uint16(dns.OpcodeUpdate)<<11, 0))
	reply := readFrame(t, conn)
	if got := int(reply[3] & 0x0F); got != dns.RcodeNotImplemented {
		t.Fatalf("opcode reject rcode %d", got)
	}
	writeFrame(t, conn, header(22, 0, 2))
	reply = readFrame(t, conn)
	if got := int(reply[3] & 0x0F); got != dns.RcodeFormatError {
		t.Fatalf("count reject rcode %d", got)
	}

	// The session survives rejects and still answers real queries.
	q := new(dns.Msg)
	q.SetQuestion("after.example.", dns.TypeA)
	q.Id = 23
	wireQ, _ := q.Pack()
	writeFrame(t, conn, wireQ)
	var r dns.Msg
	if err := r.Unpack(readFrame(t, conn)); err != nil || r.Id != 23 {
		t.Fatalf("post-reject query: %v", err)
	}
}

// TestDoTEngineRoundTrip drives one query through the owned engine behind
// a tls.Listener — the DoT path is the TCP path plus the handshake, which
// the first-frame deadline covers.
func TestDoTEngineRoundTrip(t *testing.T) {
	cert, key := generateTestCert(t, "dot.test")
	dir := t.TempDir()
	certPath, keyPath := dir+"/cert.pem", dir+"/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)
	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Stop()

	l := newTLSListener("127.0.0.1:0", echoHandler(), cm, time.Second, 8)
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(context.Background()) }()
	defer func() {
		_ = l.Shutdown(context.Background())
		<-served
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !l.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	conn, err := tls.Dial("tcp", l.ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test cert
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	q := new(dns.Msg)
	q.SetQuestion("dot.example.", dns.TypeA)
	q.Id = 77
	wireQ, _ := q.Pack()
	writeFrame(t, conn, wireQ)
	var r dns.Msg
	if err := r.Unpack(readFrame(t, conn)); err != nil || r.Id != 77 || len(r.Answer) != 1 {
		t.Fatalf("DoT reply: %v", err)
	}
}

// TestTCPEngineShutdownForcesBlockedConns pins the force phase: a
// connection parked in a blocked read is woken by the forced deadline and
// the drain completes.
func TestTCPEngineShutdownForcesBlockedConns(t *testing.T) {
	addr, l, _ := startTCPEngine(t, echoHandler(), 8)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Half a frame: the engine sits in the payload read.
	if _, err := conn.Write([]byte{0, 30, 0, 0}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	l.timeout = 100 * time.Millisecond // force quickly
	start := time.Now()
	_ = l.Shutdown(context.Background())
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %v; force phase did not fire", elapsed)
	}
}
