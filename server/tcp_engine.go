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
	"github.com/semihalev/zlog/v2"
)

// The owned TCP/DoT engine. Its contract:
//
//   - The handler runs inline on the connection goroutine, connections
//     already amortize goroutine and stack costs, queries on one
//     connection are served serially (library parity), and the inline
//     model is natural backpressure and frame serialization in one.
//   - Jobs are prefix-first: the connection goroutine owns a 2-byte
//     length scratch and acquires a large-class job only after a frame
//     announces itself, so idle connections pin no slab. Acquisition
//     blocks, for a stream transport, waiting is the correct
//     backpressure, but only inside the announcing query's own budget,
//     and it wakes on shutdown.
//   - The TX buffer carries prefix headroom, so a reply is one plain
//     write with no gather and no allocation.
//
// Library-parity behaviors kept deliberately: first frame read within
// 2s, subsequent frames within an 8s idle timeout, at most 2048 queries
// per connection, then close; a sub-header frame closes the connection.

const (
	tcpJobBufSize = dns.MaxMsgSize
	// The small class is sized by what each side actually carries, which
	// is not the same number. A query is small, a few hundred bytes, and
	// 2KB is already generous, while its reply can be several times that
	// once it is signed. Sizing both at the protocol maximum is what made
	// the ring small enough to run out; sizing them equally would either
	// waste the receive side or push ordinary signed replies off the byte
	// path and into a packing buffer.
	tcpSmallFrame = 2 << 10
	// tcpSmallReply is two bytes short of 16KB so the TX buffer, reply
	// plus its frame prefix, lands exactly on the allocator's 16,384B
	// size class. At 16KB even, the prefix pushed every small TX into
	// the 18,432B class: two waste kilobytes per slab, times the whole
	// class. A reply of exactly 16,383 or 16,384 bytes declines the
	// lease and packs into its own buffer, as every oversized reply
	// already does.
	tcpSmallReply    = 16<<10 - dnsclient.FramePrefixLen
	tcpFirstReadWait = 2 * time.Second
	tcpIdleWait      = 8 * time.Second
	// tcpQueryWait is the absolute budget a query gets from the moment its
	// prefix lands: the wait for a free slab and the read of the body that
	// prefix announced both run inside it. Announcing a frame buys no more
	// time than announcing it did, which is why this is the first-read
	// allowance and not the idle timeout, staying silent is a client's
	// right, holding a shared slab while it does so is not.
	tcpQueryWait = tcpFirstReadWait
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
	// slabShard is where this job's slab returns on release; TCP has no
	// per-slot reader, so acquisition deals shards out round-robin.
	slabShard uint8
	// rx and tx are sized by the slab's class and never resized. A
	// connection takes the class its announced frame needs, which the
	// length prefix has already told it, prefix-first acquisition was
	// worth having for backpressure and turns out to pay twice.
	rx       []byte
	tx       []byte
	large    bool
	written  bool
	readTime time.Time

	// leased is the double-release guard: set when the job is acquired,
	// cleared exactly once when it is returned. A slab released twice is
	// two connections writing into one buffer, so the second release is
	// a panic, not a counter skew.
	leased atomic.Bool

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
		// the Msg body, which packs into a buffer of its own, the same
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
// PackBuffer allocates when it does not, a reply larger than this slab's
// class is rare and correctness comes first.
func (j *tcpJob) WriteMsg(m *dns.Msg) error {
	// The full-length slice matters: PackBuffer selects the caller's
	// buffer by len, not cap, so a zero-length slice allocated every
	// Msg-path reply while the slab sat idle.
	out, err := m.PackBuffer(j.tx[dnsclient.FramePrefixLen:])
	if err != nil {
		return err
	}
	j.written = true
	if len(out) > tcpJobBufSize {
		return dnsclient.ErrFrameTooLarge
	}
	return j.stream.stage(out)
}

// FlushStaged writes the connection's drain buffer, replies of
// pipelined frames served before this one, so they never wait behind
// this request's slow path. Runs on the connection goroutine that owns
// the stream.
func (j *tcpJob) FlushStaged() {
	if j.stream == nil {
		return
	}
	if err := j.stream.beforeWrite(); err == nil {
		_ = j.stream.flush()
	}
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

	// slabRotor deals slab shards to acquisitions; connections have no
	// stable index the way the UDP readers do.
	slabRotor atomic.Uint32

	// Two classes by frame size, each with its own admission tokens and
	// its own idle cache. The tokens are the authority, how many frames
	// of the class may hold a slab at once, and what acquire waits on
	// under saturation, while the cache is only where scrubbed slabs
	// wait for reuse. Separate classes because one shared bound would
	// let the rare 128KB pairs starve the 18KB ones that a busy server
	// actually runs on.
	smallTokens chan struct{}
	largeTokens chan struct{}
	smallCache  slabCache[tcpJob]
	largeCache  slabCache[tcpJob]
	closing     chan struct{}
	// streams are per-connection framing buffers. Unlike the job ring
	// they are not strict-path state. A connection holds one for its
	// whole life, so a pool is the right shape: an idle server keeps
	// none, and a busy one reuses what its connection churn frees.
	streams sync.Pool

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	active atomic.Int64
	wg     sync.WaitGroup
	// stopped is set under mu once shutdown is about to wait on the
	// accept barrier, so a listener that starts accepting concurrently
	// either joins before the wait or is refused, never both.
	stopped bool
	// acceptG joins the accept loops (one per listener sharing this
	// engine, plain TCP and DoT each have their own). It is a separate
	// barrier from wg because it has to be waited on first: an accept
	// loop is what puts new members into wg.
	acceptG sync.WaitGroup
}

func newTCPEngine(handler rawHandler, proto string, maxConns int, plan resourcePlan) *tcpEngine {
	small, large := plan.tcpSmallJobs, plan.tcpLargeJobs
	if maxConns <= 0 {
		// The admission cap guards against a connection flood, and what
		// it is allowed to spend is what the machine can spare, see
		// ingress_bounds.go. Connections arriving past it are refused
		// rather than queued, and a goroutine plus a pooled stream is a
		// far cheaper thing to bound than the slabs are.
		maxConns = plan.tcpConns
	} else {
		// An explicit cap overrides the memory heuristics, never the
		// descriptor allowance: a connection past what the kernel will
		// grant is EMFILE at accept, not capacity.
		if plan.tcpConnsFD > 0 && maxConns > plan.tcpConnsFD {
			zlog.Warn("Configured ingress TCP connection cap exceeds the descriptor allowance, clamping",
				"proto", proto, "configured", maxConns, "allowance", plan.tcpConnsFD)
			maxConns = plan.tcpConnsFD
		}
		// An explicit cap also sizes the small class, the way it always
		// did: a server cannot have more frames in flight than it has
		// connections.
		small = maxConns
		if small > maxSmallJobs {
			small = maxSmallJobs
		}
	}
	if large < 1 {
		large = 1
	}
	e := &tcpEngine{
		handler:     handler,
		proto:       proto,
		maxConns:    int64(maxConns),
		smallTokens: make(chan struct{}, small),
		largeTokens: make(chan struct{}, large),
		closing:     make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
	}
	for i := 0; i < small; i++ {
		e.smallTokens <- struct{}{}
	}
	for i := 0; i < large; i++ {
		e.largeTokens <- struct{}{}
	}
	e.streams.New = func() any { return new(tcpStream) }
	return e
}

// newTCPJob allocates one slab of the given class. Called only with the
// class's token held; the slab parks in the class cache between
// requests.
func newTCPJob(e *tcpEngine, large bool) *tcpJob {
	j := &tcpJob{engine: e, large: large}
	if large {
		j.rx = make([]byte, tcpJobBufSize)
		j.tx = make([]byte, dnsclient.FramePrefixLen+tcpJobBufSize)
		return j
	}
	j.rx = make([]byte, tcpSmallFrame)
	j.tx = make([]byte, dnsclient.FramePrefixLen+tcpSmallReply)
	return j
}

// largeClass reports whether a frame of this length needs the large class.
func largeClass(length int) bool { return length > tcpSmallFrame }

// tokens returns the admission tokens for a frame of this length.
func (e *tcpEngine) tokens(length int) chan struct{} {
	if largeClass(length) {
		return e.largeTokens
	}
	return e.smallTokens
}

// put returns a slab: parked in its class cache first, and only then the
// token back, the other order could admit a frame the cache cannot yet
// serve, which is a needless allocation.
func (e *tcpEngine) put(j *tcpJob) {
	if !j.leased.CompareAndSwap(true, false) {
		panic("server: tcp job released twice")
	}
	if j.large {
		e.largeCache.put(int(j.slabShard), j)
		e.largeTokens <- struct{}{}
		return
	}
	e.smallCache.put(int(j.slabShard), j)
	e.smallTokens <- struct{}{}
}

// quiesced reports whether every admission token is home. Idle
// connections hold none. A slab is taken only once a frame's length
// prefix has arrived, so this is true whenever no frame is mid-flight.
func (e *tcpEngine) quiesced() bool {
	return len(e.smallTokens) == cap(e.smallTokens) && len(e.largeTokens) == cap(e.largeTokens)
}

// trimIdle drops both classes' parked slabs, so a burst's memory is
// collectable. The tokens are untouched: admission does not change,
// only what the next admissions will have to allocate.
func (e *tcpEngine) trimIdle() int {
	return e.smallCache.trim() + e.largeCache.trim()
}

// startAccepting runs the accept loop on its own goroutine, joining it to
// the accept barrier before that goroutine exists. Joining from inside it
// would be too late: a shutdown that began first would wait on an empty
// barrier and miss the loop entirely.
//
// Joining and the shutdown that waits on the barrier are serialized by
// the engine lock, because a WaitGroup gives no ordering of its own: an
// Add racing a Wait is a race whether or not the counter happens to be
// zero, and at zero it is also a loop the drain never sees. Starting
// after shutdown is refused rather than joined. The listener goes back
// to the caller closed, which is the same state it would have reached a
// moment later anyway.
func (e *tcpEngine) startAccepting(ln net.Listener, onExit func()) bool {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		_ = ln.Close()
		return false
	}
	e.acceptG.Add(1)
	e.mu.Unlock()

	go func() {
		defer e.acceptG.Done()
		e.acceptLoop(ln)
		onExit()
	}()
	return true
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
	// remaining cost once the syscalls were batched away, two channel
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

	// A session serves until its client leaves. There is deliberately no
	// per-connection query cap here: fairness is enforced where slabs are
	// admitted (a token per announced frame), session count where
	// connections are (the engine's conncap), and RFC 7766 tells clients
	// to hold their connections open. A cap did exist once, and a busy
	// pipelined client burned through it in under a second, every expiry
	// a server-forced reconnect, and the reconnect storm cost the stream
	// path half its throughput.
	wait := tcpFirstReadWait
	for {
		// Shutdown between frames, before any buffered prefix keeps the
		// burst alive: a connection with pipelined frames in its fill
		// buffer never blocks on the socket, so the closed socket alone
		// cannot stop it.
		select {
		case <-e.closing:
			return
		default:
		}
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

		// The class belongs to the frame, not to the connection, and that
		// cuts both ways. Growing is the obvious half: a small slab cannot
		// hold a large frame, so it goes back rather than being read into.
		// Shrinking is the half that decides whether the server stays up.
		// The large ring is defaultTCPLargeJobs deep because large frames
		// are rare; a burst that met one and then went back to ordinary
		// queries would hold one of those few for the rest of the
		// connection, and that many connections own the class outright.
		// The next client to announce a large frame then waits its whole
		// budget and is dropped, with a ring full of slabs no one needs.
		// Handing it back costs two channel operations on a transition that
		// is rare by construction, and the small class it swaps into has a
		// slab per admissible connection.
		if job != nil && job.large != largeClass(length) {
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

// acquire takes an admission token within the announcing query's budget,
// then a slab: from the class cache when one is parked there, allocated
// when not. Waiting, on the token, never on memory, is the right
// backpressure for a stream transport; waiting forever is not. A class's
// worth of clients that announce frames they never send would otherwise
// own it outright, and every connection behind them would park in this
// select with nothing but shutdown to wake it. A connection that cannot
// be served inside its own budget is dropped instead, so the token it
// never took stays free for someone who can use it.
// The wait is bounded by the connection's own reusable timer: tokens run
// out exactly when the server is saturated, and a timer built per wait
// would put an allocation on the path that decides whether a queued
// query is served or dropped, under the load the bound exists to absorb.
func (e *tcpEngine) acquire(s *tcpStream, deadline time.Time, length int) *tcpJob {
	tokens := e.tokens(length)
	select {
	case <-tokens:
	default:
		// Parking for a token with replies still staged is the deadlock
		// beforeRead guards against, one seam over: the frame that needs
		// this class was already buffered, so no flush ran on the way
		// here, and the client may be waiting on exactly these replies
		// while its next frame waits on another tenant's token. The
		// uncontended path above never pays this check.
		if s.held > 0 {
			if err := s.beforeWrite(); err == nil {
				_ = s.flush()
			}
		}
		waited := s.waitFor(time.Until(deadline))
		defer s.wait.Stop()
		select {
		case <-tokens:
		case <-waited:
			tcpDropJobWait.Inc()
			return nil
		case <-e.closing:
			return nil
		}
	}

	large := largeClass(length)
	cache := &e.smallCache
	if large {
		cache = &e.largeCache
	}
	shard := int(e.slabRotor.Add(1))
	j := cache.get(shard)
	if j == nil {
		j = newTCPJob(e, large)
	}
	j.slabShard = uint8(shard & (slabShardCount - 1))
	j.leased.Store(true)
	return j
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
	// context. A false return means an undecodable body, FORMERR,
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

	// Close the door on late joiners before waiting on the barrier: from
	// here a listener that has not started accepting yet is refused, so
	// no Add can happen while this Wait runs.
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()

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

	// Force phase: close the survivors outright. A past deadline was
	// tried here once and lost the race it was meant to win, the
	// connection loop re-arms deadlines per operation, and a loop with a
	// pipelined frame already buffered never touches the deadline at
	// all, so a chatty client could keep being served after Stopped()
	// said true. Close is not raceable: every read and write on the
	// connection fails from here on, and the loops exit on the error.
	e.mu.Lock()
	for conn := range e.conns {
		_ = conn.Close()
	}
	e.mu.Unlock()
	select {
	case <-done:
		return errDrainTimeout // drained, but only under force, report it
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
