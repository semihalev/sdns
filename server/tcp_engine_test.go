package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

func startTCPEngine(t *testing.T, handler rawHandler, maxConns int) (string, *tcpListener, func()) {
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
	if free, want := len(l.engine.freeSmall), cap(l.engine.freeSmall); free != want {
		t.Fatalf("%d small jobs free, want %d — idle connections pinned slabs", free, want)
	}
	if free, want := len(l.engine.freeLarge), cap(l.engine.freeLarge); free != want {
		t.Fatalf("%d large jobs free, want %d — idle connections pinned slabs", free, want)
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

// waitForRing blocks until the ring is back to full, which is the shape
// every slow-client assertion here takes: the slab has to come back on
// the server's own budget, with the client doing nothing to help.
func waitForRing(t *testing.T, e *tcpEngine, within time.Duration) {
	t.Helper()
	want := cap(e.freeSmall)
	deadline := time.Now().Add(within)
	for len(e.freeSmall) < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if free := len(e.freeSmall); free != want {
		t.Fatalf("%d slabs free after %v, want %d", free, within, want)
	}
}

// ringSize is the small-slab ring these tests exhaust. It is the
// connection cap, because a server cannot have more frames in flight
// than connections — so the number of stalled clients it takes to own
// the ring is the number the cap admits.
const ringSize = 8

// TestTCPEngineStalledPrefixReleasesRing pins the slow-client bound: a
// client that announces a frame and then goes quiet owns its slab for one
// query budget, not for as long as it keeps the socket open. Enough of
// them to own the whole ring is the availability case — before the bound,
// they held it for free.
func TestTCPEngineStalledPrefixReleasesRing(t *testing.T) {
	addr, l, stop := startTCPEngine(t, echoHandler(), ringSize)
	defer stop()

	for i := 0; i < ringSize; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		// A frame announced and never delivered.
		if _, err := conn.Write([]byte{0, 30}); err != nil {
			t.Fatal(err)
		}
	}

	drained := time.Now().Add(3 * time.Second)
	for len(l.engine.freeSmall) > 0 && time.Now().Before(drained) {
		time.Sleep(2 * time.Millisecond)
	}
	if free := len(l.engine.freeSmall); free != 0 {
		t.Fatalf("%d slabs still free; the stall never took the ring", free)
	}

	waitForRing(t, l.engine, tcpQueryWait+3*time.Second)

	// And the engine serves normally on the ring it got back.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := new(dns.Msg)
	q.SetQuestion("after-stall.example.", dns.TypeA)
	wireQ, _ := q.Pack()
	writeFrame(t, conn, wireQ)
	var r dns.Msg
	if err := r.Unpack(readFrame(t, conn)); err != nil || len(r.Answer) != 1 {
		t.Fatalf("post-stall query: %v", err)
	}
}

// TestTCPEngineJobWaitBounded pins the other end of the same budget: with
// every slab out, a connection arriving behind them waits inside its own
// query budget and is dropped when it runs out. An unbounded wait here is
// what turns a held ring into a wedged listener — nothing but shutdown
// would ever wake the connections queued on it.
func TestTCPEngineJobWaitBounded(t *testing.T) {
	release := make(chan struct{})
	addr, l, stop := startTCPEngine(t, rawHandlerFunc(func(middleware.Transport, []byte, time.Time) bool {
		<-release
		return true
	}), defaultTCPLargeJobs*4)
	defer stop()
	defer close(release)

	// Large frames, because the small ring cannot be exhausted: it holds
	// one slab per admissible connection, and a connection serves one
	// frame at a time. The bounded wait exists for the class that can run
	// out, which is the large one.
	q := new(dns.Msg)
	q.SetQuestion("held.example.", dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	wireQ := make([]byte, tcpSmallFrame+1)
	copy(wireQ, packed)
	for i := 0; i < defaultTCPLargeJobs; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		writeFrame(t, conn, wireQ)
	}
	drained := time.Now().Add(5 * time.Second)
	for len(l.engine.freeLarge) > 0 && time.Now().Before(drained) {
		time.Sleep(2 * time.Millisecond)
	}
	if free := len(l.engine.freeLarge); free != 0 {
		t.Fatalf("%d large slabs still free; the handlers did not take the ring", free)
	}

	late, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	before := tcpDropJobWait.Value()
	writeFrame(t, late, wireQ)

	start := time.Now()
	_ = late.SetReadDeadline(time.Now().Add(tcpQueryWait + 5*time.Second))
	var b [1]byte
	_, err = late.Read(b[:])
	if err == nil {
		t.Fatal("late connection was answered off an owned ring")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("late connection still parked in the job wait after %v", time.Since(start))
	}
	if tcpDropJobWait.Value() <= before {
		t.Fatal("the job wait ended without counting a drop")
	}
}

// TestTCPEngineSilentClientReleasesJob pins the write half: a client that
// pipelines queries and then stops reading fills the socket buffers, and
// every reply the engine writes into them is written with a slab in hand.
// Without a write bound that slab is gone for as long as the client cares
// to hold the socket open.
func TestTCPEngineSilentClientReleasesJob(t *testing.T) {
	// A reply larger than the drain buffer goes out on its own, which is
	// the write made under a held slab.
	big := make([]byte, 60000)
	addr, l, stop := startTCPEngine(t, rawHandlerFunc(func(w middleware.Transport, _ []byte, _ time.Time) bool {
		_, _ = w.Write(big)
		return true
	}), 8)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		// A pinned receive window stalls the server after a few megabytes
		// instead of letting autotuning swallow the whole burst.
		_ = tc.SetReadBuffer(4096)
	}

	q := new(dns.Msg)
	q.SetQuestion("silent.example.", dns.TypeA)
	wireQ, _ := q.Pack()
	var out []byte
	for i := 0; i < 100; i++ {
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(wireQ))) //nolint:gosec // bounded fixture
		out = append(out, prefix[:]...)
		out = append(out, wireQ...)
	}
	// One burst, so the slab is held across every reply — and not a byte
	// of them is ever read.
	if _, err := conn.Write(out); err != nil {
		t.Fatal(err)
	}

	pinned := time.Now().Add(3 * time.Second)
	for len(l.engine.freeSmall) == cap(l.engine.freeSmall) && time.Now().Before(pinned) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(l.engine.freeSmall) == cap(l.engine.freeSmall) {
		t.Fatal("the silent client never took a slab")
	}
	// Parked, not merely busy: six megabytes of replies cannot move into a
	// pinned receive window nobody reads from, so the slab is still out.
	time.Sleep(500 * time.Millisecond)
	if len(l.engine.freeSmall) == cap(l.engine.freeSmall) {
		t.Fatal("the replies drained without the client reading; the write never blocked")
	}

	waitForRing(t, l.engine, tcpWriteWait+10*time.Second)

	// A client that does read is still served.
	reader, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	writeFrame(t, reader, wireQ)
	if got := readFrame(t, reader); len(got) != len(big) {
		t.Fatalf("reply %d bytes, want %d", len(got), len(big))
	}
}

// TestTCPEnginePanicReturnsSlab pins the abnormal exit: a handler that
// panics takes its connection down, not a slab. A slab lost to a panic is
// lost for the life of the process, so more panics than the ring is deep
// would drain it outright.
func TestTCPEnginePanicReturnsSlab(t *testing.T) {
	echo := echoHandler()
	handler := rawHandlerFunc(func(w middleware.Transport, raw []byte, readTime time.Time) bool {
		m := new(dns.Msg)
		if err := m.Unpack(raw); err == nil && len(m.Question) == 1 &&
			m.Question[0].Name == "boom.example." {
			panic("handler exploded")
		}
		return echo.ServeRaw(w, raw, readTime)
	})
	addr, l, stop := startTCPEngine(t, handler, 32)
	defer stop()

	before := tcpDropPanic.Value()
	q := new(dns.Msg)
	q.SetQuestion("boom.example.", dns.TypeA)
	wireQ, _ := q.Pack()
	for i := 0; i < ringSize*2; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		writeFrame(t, conn, wireQ)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			t.Fatal("connection survived a panicking handler")
		}
		_ = conn.Close()
	}
	if tcpDropPanic.Value() <= before {
		t.Fatal("panic counter never moved; the handler was not the one panicking")
	}

	waitForRing(t, l.engine, 3*time.Second)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ok := new(dns.Msg)
	ok.SetQuestion("fine.example.", dns.TypeA)
	wireOK, _ := ok.Pack()
	writeFrame(t, conn, wireOK)
	var r dns.Msg
	if err := r.Unpack(readFrame(t, conn)); err != nil || len(r.Answer) != 1 {
		t.Fatalf("engine stopped serving after panics: %v", err)
	}
}

func TestTCPEngineConnectionCap(t *testing.T) {
	release := make(chan struct{})
	addr, _, stop := startTCPEngine(t, rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		<-release
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
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
