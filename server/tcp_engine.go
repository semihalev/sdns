package server

import (
	"encoding/binary"
	"errors"
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
//     backpressure — but only inside the announcing query's own budget,
//     and it wakes on shutdown.
//   - The TX buffer carries prefix headroom, so a reply is one plain
//     write with no gather and no allocation.
//
// Library-parity behaviors kept deliberately: first frame read within
// 2s, subsequent frames within an 8s idle timeout, at most 2048 queries
// per connection, then close; a sub-header frame closes the connection.

const (
	tcpJobBufSize = dns.MaxMsgSize
	// tcpSmallFrame is the frame size the small slab class covers. A
	// query or reply larger than this is rare enough to be worth a slab
	// twenty times its size; everything else is the ordinary traffic a
	// resolver serves, and giving it a 64KB pair each is what made the
	// ring small enough to run out.
	tcpSmallFrame    = 4 << 10
	tcpFirstReadWait = 2 * time.Second
	tcpIdleWait      = 8 * time.Second
	// tcpQueryWait is the absolute budget a query gets from the moment its
	// prefix lands: the wait for a free slab and the read of the body that
	// prefix announced both run inside it. Announcing a frame buys no more
	// time than announcing it did, which is why this is the first-read
	// allowance and not the idle timeout — staying silent is a client's
	// right, holding a shared slab while it does so is not.
	tcpQueryWait    = tcpFirstReadWait
	tcpQueryBudget  = 2048
	defaultTCPConns = 512
	// defaultTCPLargeJobs bounds the big class. Large frames are rare, so
	// this exists to serve them without letting them define the ring's
	// memory: the small class is what a busy server actually runs on.
	defaultTCPLargeJobs = 16
	// maxSmallJobs caps the small ring at 8MB of slabs.
	maxSmallJobs       = 1024
	tcpAcceptErrPause  = 5 * time.Millisecond
	minTCPFrame        = wire.HeaderLen
	tcpShutdownForceIn = time.Millisecond
)

// tcpJob is the large-class slab: RX for one frame's payload, TX with
// prefix headroom for one plain-write reply.
type tcpJob struct {
	engine *tcpEngine
	conn   net.Conn
	stream *tcpStream
	// rx and tx are sized by the slab's class and never resized. A
	// connection takes the class its announced frame needs, which the
	// length prefix has already told it — prefix-first acquisition was
	// worth having for backpressure and turns out to pay twice.
	rx       []byte
	tx       []byte
	large    bool
	written  bool
	readTime time.Time

	// Strict-path state, job-owned (see strict.go). The chain is here for
	// the same reason as everything else in this struct: the strict path
	// takes nothing from a pool.
	req        middleware.Request
	chain      middleware.Chain
	carrier    jobCarrier
	ednsWriter edns.ResponseWriter
}

// StrictSlots hands ServeRaw the job-owned strict-path storage.
func (j *tcpJob) StrictSlots() (*middleware.Request, *middleware.Chain, *jobCarrier, *edns.ResponseWriter) {
	return &j.req, &j.chain, &j.carrier, &j.ednsWriter
}

// LeaseWire hands out the TX payload region behind the frame-prefix
// headroom, so a committed body is one plain framed write.
func (j *tcpJob) LeaseWire(capacity int) []byte {
	if capacity > len(j.tx)-dnsclient.FramePrefixLen {
		// This slab cannot hold the reply. Declining sends the request to
		// the Msg body, which packs into a buffer of its own — the same
		// road every other byte-path decline takes.
		return nil
	}
	return j.tx[dnsclient.FramePrefixLen:dnsclient.FramePrefixLen]
}

// Write stages pooled or foreign bytes as one frame on the connection's
// drain buffer. The bytes leave when the connection is about to block for
// more input, so a burst of pipelined replies costs one write syscall and
// a lone reply costs exactly one too.
func (j *tcpJob) Write(b []byte) (int, error) {
	if len(b) > tcpJobBufSize {
		return 0, dnsclient.ErrFrameTooLarge
	}
	j.written = true
	if err := j.stream.stage(b); err != nil {
		return 0, err
	}
	return dnsclient.FramePrefixLen + len(b), nil
}

// WriteMsg packs into the TX payload region and stages the frame.
// WriteMsg packs into the TX payload region when the reply fits it, and
// PackBuffer allocates when it does not — a reply larger than this slab's
// class is rare and correctness comes first.
func (j *tcpJob) WriteMsg(m *dns.Msg) error {
	out, err := m.PackBuffer(j.tx[dnsclient.FramePrefixLen:dnsclient.FramePrefixLen])
	if err != nil {
		return err
	}
	j.written = true
	if len(out) > tcpJobBufSize {
		return dnsclient.ErrFrameTooLarge
	}
	return j.stream.stage(out)
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

	// Two rings, by frame size. One ring of 64KB pairs was 8MB that ran
	// out at 64 concurrent frames — measured: contention starts exactly
	// where connections reach slabs, and the connection cap is 512.
	freeSmall chan *tcpJob
	freeLarge chan *tcpJob
	closing   chan struct{}
	// streams are per-connection framing buffers. Unlike the job ring
	// they are not strict-path state — a connection holds one for its
	// whole life — so a pool is the right shape: an idle server keeps
	// none, and a busy one reuses what its connection churn frees.
	streams sync.Pool

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	active atomic.Int64
	wg     sync.WaitGroup
	// acceptG joins the accept loops (one per listener sharing this
	// engine — plain TCP and DoT each have their own). It is a separate
	// barrier from wg because it has to be waited on first: an accept
	// loop is what puts new members into wg.
	acceptG sync.WaitGroup
}

func newTCPEngine(handler rawHandler, proto string, maxConns int) *tcpEngine {
	if maxConns <= 0 {
		maxConns = defaultTCPConns
	}
	// One small slab per admissible connection, up to a ceiling: a server
	// cannot have more frames in flight than it has connections, so at
	// this size the ordinary path stops queueing altogether. The ceiling
	// keeps a very large connection cap from turning into a very large
	// resident set; past it, the bounded wait does its job.
	small := maxConns
	if small > maxSmallJobs {
		small = maxSmallJobs
	}
	e := &tcpEngine{
		handler:   handler,
		proto:     proto,
		maxConns:  int64(maxConns),
		freeSmall: make(chan *tcpJob, small),
		freeLarge: make(chan *tcpJob, defaultTCPLargeJobs),
		closing:   make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}
	e.streams.New = func() any { return new(tcpStream) }
	for i := 0; i < small; i++ {
		e.freeSmall <- &tcpJob{
			engine: e,
			rx:     make([]byte, tcpSmallFrame),
			tx:     make([]byte, dnsclient.FramePrefixLen+tcpSmallFrame),
		}
	}
	for i := 0; i < defaultTCPLargeJobs; i++ {
		e.freeLarge <- &tcpJob{
			engine: e,
			large:  true,
			rx:     make([]byte, tcpJobBufSize),
			tx:     make([]byte, dnsclient.FramePrefixLen+tcpJobBufSize),
		}
	}
	return e
}

// ring returns the class a frame of this length needs.
func (e *tcpEngine) ring(length int) chan *tcpJob {
	if length > tcpSmallFrame {
		return e.freeLarge
	}
	return e.freeSmall
}

// put returns a slab to the class it came from.
func (e *tcpEngine) put(j *tcpJob) {
	if j.large {
		e.freeLarge <- j
		return
	}
	e.freeSmall <- j
}

// quiesced reports whether every slab is back in the ring. Idle
// connections hold none — a slab is taken only once a frame's length
// prefix has arrived — so this is true whenever no frame is mid-flight.
func (e *tcpEngine) quiesced() bool {
	return len(e.freeSmall) == cap(e.freeSmall) && len(e.freeLarge) == cap(e.freeLarge)
}

// startAccepting runs the accept loop on its own goroutine, joining it to
// the accept barrier before that goroutine exists. Joining from inside it
// would be too late: a shutdown that began first would wait on an empty
// barrier and miss the loop entirely.
func (e *tcpEngine) startAccepting(ln net.Listener, onExit func()) {
	e.acceptG.Add(1)
	go func() {
		defer e.acceptG.Done()
		e.acceptLoop(ln)
		onExit()
	}()
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

	stream := e.streams.Get().(*tcpStream)
	stream.reset(conn)
	defer func() {
		if stream.held > 0 {
			// Whatever is still staged has to leave, and the client on the
			// other end may be exactly the one that never reads.
			if err := stream.beforeWrite(); err == nil {
				_ = stream.flush()
			}
		}
		stream.reset(nil)
		e.streams.Put(stream)
	}()

	// The job is held for a burst, not for a frame. Handing one back to
	// the ring between the frames a client already sent was the loop's
	// remaining cost once the syscalls were batched away — two channel
	// operations per query across every connection goroutine. It is
	// still released before the connection blocks, so the property that
	// pays for the ring is intact: an idle connection pins no slab.
	var job *tcpJob
	release := func() {
		if job == nil {
			return
		}
		job.conn = nil
		job.stream = nil
		e.put(job)
		job = nil
	}
	// Deferred last so it unwinds first: the slab goes back before the
	// recover above ever sees the panic. A slab lost to one is lost for
	// the life of the process.
	defer release()

	wait := tcpFirstReadWait
	for served := 0; served < tcpQueryBudget; served++ {
		if !stream.framePrefixBuffered() {
			// About to block: the client's replies go out, the slab goes
			// back, and only then does the connection wait.
			//
			// The test is for a whole length prefix, not for any bytes at
			// all. A single buffered byte is half a prefix: reading the
			// other half blocks exactly like an empty buffer does, so
			// treating it as pending input would keep the slab and strand
			// the burst's replies until the deadline expired.
			release()
			if err := stream.beforeRead(wait); err != nil {
				return
			}
		}

		prefix, err := stream.next(dnsclient.FramePrefixLen)
		if err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(prefix))
		if length < minTCPFrame || length > tcpJobBufSize {
			// Sub-header frames end the session (library parity: the
			// message layer rejects, and rejection on a stream is fatal).
			return
		}

		// The query's clock starts where its frame announced itself, and
		// the stream carries it from here: the wait for a slab and the read
		// of the announced body are both spent inside it.
		readTime := time.Now()
		stream.deadline = readTime.Add(tcpQueryWait)

		// A burst that started small and met a large frame hands the small
		// slab back rather than trying to read into it: the class is the
		// frame's, not the connection's.
		if job != nil && length > len(job.rx) {
			release()
		}
		if job == nil {
			if job = e.acquire(stream, stream.deadline, length); job == nil {
				return
			}
		}
		if err := stream.body(job.rx[:length]); err != nil {
			return
		}
		job.conn = conn
		job.stream = stream
		job.written = false
		job.readTime = readTime
		if !e.serveFrame(job, length) {
			return
		}
		wait = tcpIdleWait
	}
}

// acquire takes a slab from the ring within the announcing query's
// budget. Waiting is the right backpressure for a stream transport;
// waiting forever is not. defaultTCPJobs clients that announce frames
// they never send would otherwise own the ring outright, and every
// connection behind them would park in this select with nothing but
// shutdown to wake it. A connection that cannot be served inside its own
// budget is dropped instead, so the slab it never took stays in the ring
// for someone who can use it.
// The wait is bounded by the connection's own reusable timer: a slab
// runs out exactly when the server is saturated, and a timer built per
// wait would put an allocation on the path that decides whether a queued
// query is served or dropped — under the load the ring exists to absorb.
func (e *tcpEngine) acquire(s *tcpStream, deadline time.Time, length int) *tcpJob {
	free := e.ring(length)
	select {
	case j := <-free:
		return j
	default:
	}
	waited := s.waitFor(time.Until(deadline))
	defer s.wait.Stop()
	select {
	case j := <-free:
		return j
	case <-waited:
		tcpDropJobWait.Inc()
		return nil
	case <-e.closing:
		return nil
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
	_ = j.stream.stage(out)
}

// shutdown is the engine's barrier half: the caller already closed the
// accept listener. Wake job-waiters, drain within the deadline, then
// force-close the survivors and join.
func (e *tcpEngine) shutdown(deadline time.Time) error {
	close(e.closing)

	// The accept loop is joined before the connections are, because it is
	// the only thing that can still join the connection barrier. A
	// connection admitted while that barrier is being waited on is a
	// member added after the wait began: the drain would return without
	// it, and the request it is in the middle of would be cut off by the
	// close that follows.
	e.acceptG.Wait()

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
	tcpDropJobWait = tcpIngressDrops.Register("jobwait")
)
