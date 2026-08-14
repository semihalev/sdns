package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// The owned TCP/DoT engine. Per the zero-path contract:
//
//   - The handler runs inline on the connection goroutine — connections
//     already amortize goroutine and stack costs, queries on one
//     connection are served serially (library parity), and the inline
//     model is natural backpressure and frame serialization in one.
//   - Jobs are prefix-first: the connection goroutine owns a 2-byte
//     length scratch and acquires a large-class job only after a frame
//     announces itself, so idle connections pin no slab. Acquisition
//     blocks — for a stream transport, waiting is the correct
//     backpressure — but wakes on shutdown.
//   - The TX buffer carries prefix headroom, so a reply is one plain
//     write with no gather and no allocation.
//
// Library-parity behaviors kept deliberately: first frame read within
// 2s, subsequent frames within an 8s idle timeout, at most 2048 queries
// per connection, then close; a sub-header frame closes the connection.

const (
	tcpJobBufSize      = dns.MaxMsgSize
	tcpFirstReadWait   = 2 * time.Second
	tcpIdleWait        = 8 * time.Second
	tcpQueryBudget     = 2048
	defaultTCPConns    = 512
	defaultTCPJobs     = 64
	tcpAcceptErrPause  = 5 * time.Millisecond
	minTCPFrame        = wire.HeaderLen
	tcpShutdownForceIn = time.Millisecond
)

// tcpJob is the large-class slab: RX for one frame's payload, TX with
// prefix headroom for one plain-write reply.
type tcpJob struct {
	engine   *tcpEngine
	conn     net.Conn
	rx       [tcpJobBufSize]byte
	tx       [dnsclient.FramePrefixLen + tcpJobBufSize]byte
	written  bool
	readTime time.Time

	// Strict-path state, job-owned (see strict.go).
	req        middleware.Request
	carrier    jobCarrier
	ednsWriter edns.ResponseWriter
}

// StrictSlots hands ServeRaw the job-owned strict-path storage.
func (j *tcpJob) StrictSlots() (*middleware.Request, *jobCarrier, *edns.ResponseWriter) {
	return &j.req, &j.carrier, &j.ednsWriter
}

// LeaseWire hands out the TX payload region behind the frame-prefix
// headroom, so a committed body is one plain framed write.
func (j *tcpJob) LeaseWire(capacity int) []byte {
	if capacity > tcpJobBufSize {
		return nil
	}
	return j.tx[dnsclient.FramePrefixLen:dnsclient.FramePrefixLen]
}

// Write sends pooled or foreign bytes as one frame: copied behind the
// job's prefix headroom, one syscall, no gather, no allocation.
func (j *tcpJob) Write(b []byte) (int, error) {
	if len(b) > tcpJobBufSize {
		return 0, dnsclient.ErrFrameTooLarge
	}
	j.written = true
	n := copy(j.tx[dnsclient.FramePrefixLen:], b)
	return dnsclient.WriteFramePrefixed(j.conn, j.tx[:], n)
}

// WriteMsg packs directly into the TX payload region and frames it.
func (j *tcpJob) WriteMsg(m *dns.Msg) error {
	out, err := m.PackBuffer(j.tx[dnsclient.FramePrefixLen:dnsclient.FramePrefixLen])
	if err != nil {
		return err
	}
	j.written = true
	if len(out) > tcpJobBufSize {
		return dnsclient.ErrFrameTooLarge
	}
	if &out[0] == &j.tx[dnsclient.FramePrefixLen] {
		_, err = dnsclient.WriteFramePrefixed(j.conn, j.tx[:], len(out))
		return err
	}
	// PackBuffer outgrew the slab (pathological size): frame the escape
	// buffer with a gather write.
	_, err = dnsclient.WriteFrameFrom(j.conn, out)
	return err
}

func (j *tcpJob) LocalAddr() net.Addr  { return j.conn.LocalAddr() }
func (j *tcpJob) RemoteAddr() net.Addr { return j.conn.RemoteAddr() }
func (j *tcpJob) Close() error         { return j.conn.Close() }

// tcpEngine owns one listener's accept loop, connection registry, and
// job ring.
type tcpEngine struct {
	handler  rawHandler
	proto    string // "tcp" or "tls", for metrics
	maxConns int64

	free    chan *tcpJob
	closing chan struct{}

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	active atomic.Int64
	wg     sync.WaitGroup
}

func newTCPEngine(handler rawHandler, proto string, maxConns int) *tcpEngine {
	if maxConns <= 0 {
		maxConns = defaultTCPConns
	}
	e := &tcpEngine{
		handler:  handler,
		proto:    proto,
		maxConns: int64(maxConns),
		free:     make(chan *tcpJob, defaultTCPJobs),
		closing:  make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	for i := 0; i < defaultTCPJobs; i++ {
		e.free <- &tcpJob{engine: e}
	}
	return e
}

// acceptLoop admits connections until the listener closes.
func (e *tcpEngine) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedNetErr(err) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// Transient accept failure (EMFILE and friends): brief pause
			// keeps the loop from spinning.
			time.Sleep(tcpAcceptErrPause)
			continue
		}
		if e.active.Load() >= e.maxConns {
			_ = conn.Close()
			tcpDropConnCap.Inc()
			continue
		}
		e.register(conn)
		go e.serveConn(conn)
	}
}

func (e *tcpEngine) register(conn net.Conn) {
	e.active.Add(1)
	e.wg.Add(1)
	e.mu.Lock()
	e.conns[conn] = struct{}{}
	e.mu.Unlock()
}

func (e *tcpEngine) unregister(conn net.Conn) {
	e.mu.Lock()
	delete(e.conns, conn)
	e.mu.Unlock()
	e.active.Add(-1)
	e.wg.Done()
}

// serveConn is the inline per-connection loop: prefix-first job
// acquisition, serial queries, library-parity timeouts and budget.
func (e *tcpEngine) serveConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			tcpDropPanic.Inc()
		}
		_ = conn.Close()
		e.unregister(conn)
	}()

	var prefix [dnsclient.FramePrefixLen]byte
	wait := tcpFirstReadWait
	for served := 0; served < tcpQueryBudget; served++ {
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(prefix[:]))
		if length < minTCPFrame {
			// Sub-header frames end the session (library parity: the
			// message layer rejects, and rejection on a stream is fatal).
			return
		}

		var j *tcpJob
		select {
		case j = <-e.free:
		case <-e.closing:
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleWait))
		if _, err := io.ReadFull(conn, j.rx[:length]); err != nil {
			e.free <- j
			return
		}
		j.conn = conn
		j.written = false
		j.readTime = time.Now()
		ok := e.serveFrame(j, length)
		j.conn = nil
		e.free <- j
		if !ok {
			return
		}
		wait = tcpIdleWait
	}
}

// serveFrame runs one query inline. The header-accept verdicts mirror the
// UDP engine (and the library): garbage and responses are silent, foreign
// opcodes NOTIMP, count violations and undecodable bodies FORMERR. A
// false return closes the connection.
func (e *tcpEngine) serveFrame(j *tcpJob, length int) bool {
	header, ok := wire.ParseHeader(j.rx[:length])
	if !ok {
		return false
	}
	switch verdict := acceptHeader(header); verdict {
	case acceptOK:
	case acceptIgnore:
		tcpDropIgnored.Inc()
		return true
	case acceptNotImplemented, acceptFormatError:
		j.rejectInPlace(verdict, length)
		return true
	}

	// The one ingress: the server decides eligibility, decode, and
	// context. A false return means an undecodable body — FORMERR,
	// library parity, session continues.
	if !e.handler.ServeRaw(j, j.rx[:length], j.readTime) {
		j.rejectInPlace(acceptFormatError, length)
	}
	return true
}

// rejectInPlace frames the library-shaped bare-header rejection from the
// job's TX headroom, allocation-free.
func (j *tcpJob) rejectInPlace(verdict acceptVerdict, _ int) {
	out := j.tx[dnsclient.FramePrefixLen : dnsclient.FramePrefixLen+wire.HeaderLen]
	for i := range out {
		out[i] = 0
	}
	copy(out[0:2], j.rx[0:2])
	opcode := (j.rx[2] >> 3) & 0xF
	rcode := byte(dns.RcodeFormatError)
	if verdict == acceptNotImplemented {
		rcode = byte(dns.RcodeNotImplemented)
	}
	out[2] = 0x80 | (opcode << 3) | (j.rx[2] & 0x01)
	out[3] = rcode
	j.written = true
	_, _ = dnsclient.WriteFramePrefixed(j.conn, j.tx[:], wire.HeaderLen)
}

// shutdown is the engine's barrier half: the caller already closed the
// accept listener. Wake job-waiters, drain within the deadline, then
// force-close the survivors and join.
func (e *tcpEngine) shutdown(deadline time.Time) error {
	close(e.closing)
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()

	wait := time.Until(deadline)
	if wait <= 0 {
		wait = tcpShutdownForceIn
	}
	select {
	case <-done:
		return nil
	case <-time.After(wait):
	}

	// Force phase: a past deadline wakes every blocked read; the
	// connection loops exit on the error.
	e.mu.Lock()
	for conn := range e.conns {
		_ = conn.SetDeadline(time.Now())
	}
	e.mu.Unlock()
	select {
	case <-done:
		return errDrainTimeout // drained, but only under force — report it
	case <-time.After(2 * time.Second):
		return errDrainTimeout
	}
}

var (
	tcpIngressDrops = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_tcp_ingress_drops_total",
		Help: "TCP events dropped before the handler, by reason",
	}, []string{"reason"})

	tcpDropConnCap = tcpIngressDrops.Register("conncap")
	tcpDropIgnored = tcpIngressDrops.Register("ignored")
	tcpDropPanic   = tcpIngressDrops.Register("panic")
)
