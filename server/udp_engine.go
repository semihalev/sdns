package server

import (
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// The owned UDP engine replaces the library server's read loop. Its shape
// follows the zero-path contract (docs/zero-path.md):
//
//   - Jobs are preallocated slabs in a ring; the reader acquires a slot
//     first and reads the datagram directly into it. No slot ⇒ the packet
//     is consumed into a reserved discard buffer and dropped, counted —
//     the reader never blocks on the ring and never stalls the socket.
//   - Workers are fixed for the server's lifetime and serve from the ready
//     queue, so their stacks stay grown across requests instead of paying
//     the per-goroutine growth tax on every packet.
//   - Every job path ends in exactly one release; the job's state field
//     asserts the reader→queue→worker→free walk.
//   - Header-level accept runs on raw bytes before any decode, with the
//     library server's exact semantics: unparseable or QR-set packets are
//     silently ignored (any reply is amplification), foreign opcodes get
//     NOTIMP, count violations and unpack failures get FORMERR — all
//     built in place, allocation-free.
//
// The request *dns.Msg is still decoded per packet here; it leaves in Z1
// with the request view.

// udpJobBufSize is the strict-path UDP buffer class (StrictRXCap). The
// edns layer clamps advertised sizes to the default message size, so a
// compliant response fits; a datagram larger than the class is truncated
// by the kernel and dropped by policy.
const udpJobBufSize = 4096

// udpJob is one preallocated per-request slab. It is also the
// middleware.Transport the pipeline writes through: the classic address
// views are cached in the slab and rewritten per packet, so nothing on
// the reply path materializes addresses.
type udpJob struct {
	engine *udpEngine
	pc     *net.UDPConn

	rx       [udpJobBufSize]byte
	rxLen    int
	tx       [udpJobBufSize]byte
	raddr    netip.AddrPort
	readTime time.Time

	// pktinfo carries the wildcard-bind destination-address control
	// message for the reply, already in sendable form. Empty on specific
	// binds and on platforms without the machinery.
	pktinfo    [pktinfoSpace]byte
	pktinfoLen int

	// Cached classic views handed to the middleware chain. RemoteAddr's
	// IP always points into ipScratch; observers must copy, never retain
	// (zero-path contract §2).
	remote    net.UDPAddr
	ipScratch [16]byte

	// Strict-path state, all job-owned: the wire-born request, the chain
	// that walks it, the context carrier, and the edns writer wrapper's
	// storage. The chain lives here rather than in the pipeline's pool
	// because the collector empties pools, and a hit that allocates after
	// two GCs is not a hard-zero path.
	req        middleware.Request
	chain      middleware.Chain
	carrier    jobCarrier
	ednsWriter edns.ResponseWriter

	// TX-burst state. The reply is staged in tx and sent with the
	// worker's burst, so a job stays owned from read to send and nothing
	// on the reply path is copied twice or handed between goroutines.
	// rawSA holds the client's kernel sockaddr verbatim, so a batched
	// reply needs no address re-encoding — scoped IPv6 sources included.
	rawSA    [28]byte //nolint:unused // Linux batch path (udp_batch_linux.go)
	rawSALen uint32   //nolint:unused // Linux batch path
	txLen    int
	burst    *udpTXBurst

	written bool
	state   uint8 // udpJobFree → udpJobReading → udpJobQueued → udpJobServing → free
}

const (
	udpJobFree uint8 = iota
	udpJobReading
	udpJobQueued
	udpJobServing
)

func (j *udpJob) transition(from, to uint8) {
	if j.state != from {
		panic("server: udp job ownership violated")
	}
	j.state = to
}

// setRemote rewrites the cached classic view in place.
func (j *udpJob) setRemote(ap netip.AddrPort) {
	j.raddr = ap
	addr := ap.Addr()
	if addr.Is4() {
		v4 := addr.As4()
		j.remote.IP = append(j.ipScratch[:0], v4[:]...)
	} else {
		v16 := addr.As16()
		j.remote.IP = append(j.ipScratch[:0], v16[:]...)
	}
	j.remote.Port = int(ap.Port())
	j.remote.Zone = addr.Zone()
}

// middleware.Transport — the transport half. The middleware chain's base
// writer wraps this and derives proto/remote identity from RemoteAddr.

func (j *udpJob) LocalAddr() net.Addr  { return j.pc.LocalAddr() }
func (j *udpJob) RemoteAddr() net.Addr { return &j.remote }

// Write stages the reply in the job's own TX buffer and leaves the send
// to the worker's burst. Bytes that already live there — the wire path
// builds its body in the lease this buffer backs — are staged by their
// length alone; anything else is copied in, because a caller's buffer
// (the packer's pooled scratch, most of all) is only valid until it
// returns.
//
// The syscall's result therefore arrives after this call. A datagram
// transport has no delivery semantics to preserve here, and the byte
// path's own error handling already treats a failed send as "the
// response left the process"; a send that fails is counted (tx_error)
// rather than returned.
func (j *udpJob) Write(b []byte) (int, error) {
	j.written = true
	if len(b) > len(j.tx) {
		return 0, dnsclient.ErrFrameTooLarge
	}
	if j.burst != nil {
		if len(b) > 0 && &b[0] != &j.tx[0] {
			copy(j.tx[:], b)
		}
		j.txLen = len(b)
		return len(b), nil
	}
	if j.pktinfoLen > 0 {
		n, _, err := j.pc.WriteMsgUDPAddrPort(b, j.pktinfo[:j.pktinfoLen], j.raddr)
		return n, err
	}
	n, _, err := j.pc.WriteMsgUDPAddrPort(b, nil, j.raddr)
	return n, err
}

// sendDirect sends the job's staged reply on its own. It is the send for
// a transport with no batching underneath it, and the fallback for a
// socket the batch path never armed.
func (j *udpJob) sendDirect() {
	if j.txLen == 0 {
		return
	}
	var err error
	if j.pktinfoLen > 0 {
		_, _, err = j.pc.WriteMsgUDPAddrPort(j.tx[:j.txLen], j.pktinfo[:j.pktinfoLen], j.raddr)
	} else {
		_, _, err = j.pc.WriteMsgUDPAddrPort(j.tx[:j.txLen], nil, j.raddr)
	}
	if err != nil {
		udpTXError.Add(1)
	}
}

func (j *udpJob) WriteMsg(m *dns.Msg) error {
	// The byte fast path arrives through Write; this is the Msg-path
	// fallback. Packing into the job's TX buffer keeps the ordinary case
	// allocation-stable; an oversized response lets PackBuffer grow.
	out, err := m.PackBuffer(j.tx[:0])
	if err != nil {
		return err
	}
	_, err = j.Write(out)
	return err
}

func (j *udpJob) Close() error { return nil }

// StrictSlots hands ServeRaw the job-owned strict-path storage.
func (j *udpJob) StrictSlots() (*middleware.Request, *middleware.Chain, *jobCarrier, *edns.ResponseWriter) {
	return &j.req, &j.chain, &j.carrier, &j.ednsWriter
}

// LeaseWire hands out the job's TX buffer for the response-body lease: the
// reply is born where the send happens. The lease lives until the job
// releases — after the middleware unwind — satisfying the post-write
// retention contract.
func (j *udpJob) LeaseWire(capacity int) []byte {
	if capacity > len(j.tx) {
		return nil
	}
	return j.tx[:0]
}

// udpEngine owns the sockets' read loops, the job ring, and the worker
// pool for one listener.
type udpEngine struct {
	handler  rawHandler
	pcs      []*net.UDPConn
	wildcard bool

	free  chan *udpJob
	ready chan *udpJob

	// inFlight counts the slabs between the ready queue and their
	// release: queued, being served, or staged for a send. Slabs parked
	// in a reader are excluded — the readers hold one each by design, so
	// counting them would mean an idle server never reads as settled.
	inFlight atomic.Int64

	// closing is the readers' shutdown signal. The portable reader never
	// blocks on the ring, but the batched one waits for its first slab —
	// and a wait whose only wake-up is another goroutine returning a slab
	// is a wait that shutdown cannot bound.
	closing   chan struct{}
	closeOnce sync.Once

	workers int
	readers sync.WaitGroup
	workerG sync.WaitGroup

	// Per-worker send state and the raw handles their sends go through
	// (Linux; both inert elsewhere). Indexed by worker, never shared, so
	// a send needs no lock and no allocation.
	txSenders []udpTXSender
	txConns   map[*net.UDPConn]syscall.RawConn
}

// defaultIngressWorkers sizes the fixed pool when the config is silent.
func defaultIngressWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n < 2 {
		n = 2
	}
	if n > 64 {
		n = 64
	}
	return n
}

const defaultIngressQueue = 512

// udpBatchSize is how many datagrams one recvmmsg/sendmmsg carries at
// most (Linux batch path). It also sizes the job ring: every reader must
// be able to arm a full batch, or a jobless reader would sit out its
// socket's share of the load. Declared portably because the ring formula
// is.
const udpBatchSize = 16

func newUDPEngine(handler rawHandler, pcs []*net.UDPConn, wildcard bool, workers, queue int) *udpEngine {
	if workers <= 0 {
		workers = defaultIngressWorkers()
	}
	if queue <= 0 {
		queue = defaultIngressQueue
	}
	e := &udpEngine{
		handler:  handler,
		pcs:      pcs,
		wildcard: wildcard,
		workers:  workers,
		txConns:  make(map[*net.UDPConn]syscall.RawConn, len(pcs)),
		closing:  make(chan struct{}),
	}
	e.txSenders = make([]udpTXSender, workers)
	for i := range e.txSenders {
		newUDPTXSender(&e.txSenders[i])
	}
	// The send handles are resolved here, before a single goroutine
	// exists, so nothing ever writes this map while a worker reads it. A
	// socket that will not surrender its descriptor takes the whole
	// engine down the portable path — mixed modes would split the job
	// ring's assumptions.
	for _, pc := range pcs {
		rc, err := pc.SyscallConn()
		if err != nil {
			e.txConns = nil
			break
		}
		e.txConns[pc] = rc
	}
	// Capacity equation (zero-path §7): in-flight jobs = queue depth +
	// one per busy worker + a full batch in each reader's hand (the
	// portable reader arms one of its batch). The ring holds exactly that
	// many slabs; MaxInboundInFlight is this derived bound.
	inFlight := queue + workers + len(pcs)*udpBatchSize
	e.free = make(chan *udpJob, inFlight)
	e.ready = make(chan *udpJob, queue)
	for i := 0; i < inFlight; i++ {
		e.free <- &udpJob{engine: e}
	}
	return e
}

// start launches the fixed workers and one reader per socket.
func (e *udpEngine) start() {
	for i := 0; i < e.workers; i++ {
		e.workerG.Add(1)
		go e.worker(i)
	}
	// Linux takes the batched recvmmsg/sendmmsg path; everywhere else —
	// and on any socket that refuses its raw descriptor — the portable
	// single-datagram reader serves.
	if e.startBatched() {
		return
	}
	for _, pc := range e.pcs {
		e.readers.Add(1)
		go e.reader(pc)
	}
}

// stopAndDrain is the listener-scope half of the shutdown barrier: the
// caller has already closed the sockets (admission stopped, blocked reads
// woken); this joins the readers, closes the ready queue, and waits for
// the workers to drain within the deadline.
func (e *udpEngine) stopAndDrain(deadline time.Time) error {
	e.closeOnce.Do(func() { close(e.closing) })
	e.readers.Wait()
	close(e.ready)
	done := make(chan struct{})
	go func() { e.workerG.Wait(); close(done) }()
	wait := time.Until(deadline)
	if wait <= 0 {
		wait = time.Millisecond
	}
	select {
	case <-done:
		return nil
	case <-time.After(wait):
		return errDrainTimeout
	}
}

func (e *udpEngine) reader(pc *net.UDPConn) {
	defer e.readers.Done()
	var discard [udpJobBufSize]byte
	var oob [pktinfoSpace]byte
	oobBuf := oob[:]
	if !e.wildcard {
		oobBuf = nil
	}
	for {
		var j *udpJob
		select {
		case j = <-e.free:
		default:
			// Ring exhausted: consume and shed. The reader never blocks
			// on the ring — a deep queue only converts drops to timeouts.
			_, _, _, _, err := pc.ReadMsgUDPAddrPort(discard[:], nil)
			if err != nil {
				if isAdmissionStopErr(err) {
					return
				}
				continue
			}
			udpDropFull.Inc()
			continue
		}

		j.transition(udpJobFree, udpJobReading)
		n, oobn, flags, raddr, err := pc.ReadMsgUDPAddrPort(j.rx[:], oobBuf)
		if err != nil {
			j.release(udpJobReading)
			if isAdmissionStopErr(err) {
				return
			}
			// Transient errors (including truncation reported as an
			// error on some platforms) drop the packet, never the loop.
			udpDropError.Inc()
			continue
		}
		if flags&msgTrunc != 0 {
			// The datagram exceeded the buffer class; a partial packet
			// must not reach the parser.
			j.release(udpJobReading)
			udpDropTrunc.Inc()
			continue
		}
		j.rxLen = n
		j.readTime = time.Now()
		j.setRemote(raddr)
		j.pc = pc
		j.pktinfoLen = 0
		if e.wildcard && oobn > 0 {
			if !preparePktinfoReply(oob[:oobn], j) {
				// Control truncation or an unknown shape on a wildcard
				// bind: the destination is unknowable, and replying from
				// the kernel-default source may misattribute. Drop.
				j.release(udpJobReading)
				udpDropCtrunc.Inc()
				continue
			}
		}

		e.enqueue(j)
	}
}

// enqueue hands a filled slab to the workers, or drops it when the queue
// is full.
//
// The state write must precede the send: the channel gives the worker its
// happens-before for every job field.
func (e *udpEngine) enqueue(j *udpJob) {
	// Counted from here rather than from the read: a slab parked in a
	// reader waiting for a packet is idle, not outstanding, and a
	// quiescence check that could not tell the two apart would never see
	// an idle server settle.
	e.inFlight.Add(1)
	j.state = udpJobQueued
	select {
	case e.ready <- j:
	default:
		// Released from the queued state, not walked back to reading:
		// the in-flight count then falls where every other terminal
		// drops it — after the slab is cleared and back in the ring —
		// instead of before a release that has not happened yet.
		j.release(udpJobQueued)
		udpDropQueue.Inc()
	}
}

// quiesced reports whether every slab is back in the ring: nothing is
// being read into, served, or staged for a send. It is the completion
// barrier a measurement needs — the last reply reaching a client says
// nothing about the slab that produced it having been released.
func (e *udpEngine) quiesced() bool { return e.inFlight.Load() == 0 }

// release returns a job to the ring from any owned state.
func (j *udpJob) release(from uint8) {
	j.transition(from, udpJobFree)
	j.written = false
	j.rxLen = 0
	j.pktinfoLen = 0
	// The staged reply dies with the request that produced it. txLen is
	// what the worker reads to decide whether a served job has something
	// to send, so a slab that kept a stale length would answer the next
	// request the chain decided in silence — a malformed packet, an
	// ignored opcode, a panic — with the previous client's bytes, to the
	// new client's address.
	j.txLen = 0
	j.engine.free <- j

	// Counted down last, after the slab is cleared and back in the ring.
	// Quiescence is what a measurement takes as the end of the request,
	// and clearing a slab is inside the request, not after it: decrement
	// any earlier and the window can close while this job is still being
	// wiped. The count may briefly read high — the slab can be taken and
	// queued again before this line runs — which is the safe direction
	// for a barrier: it delays quiescence, it never claims it early.
	if from == udpJobQueued || from == udpJobServing {
		j.engine.inFlight.Add(-1)
	}
}

// worker serves ready jobs and sends their replies in bursts. A reply is
// staged in its own job's TX buffer while the chain unwinds, and the
// staged set leaves together the moment the worker would block for more
// work — the same shape the stream path uses, for the same reason: under
// load the syscall is amortized across whatever arrived together, and
// with nothing else to serve there is nothing to wait for, so a lone
// query still leaves immediately.
//
// Dispatch stays per job rather than per batch on purpose. A cache miss
// occupies its worker for the whole resolution; handing a worker a batch
// would put every query behind the slowest one in it.
func (e *udpEngine) worker(slot int) {
	defer e.workerG.Done()
	burst := udpTXBurst{slot: slot}
	for {
		select {
		case j, ok := <-e.ready:
			if !ok {
				e.flushTX(&burst)
				return
			}
			e.serve(j, &burst)
			if burst.full() {
				e.flushTX(&burst)
			}
		default:
			e.flushTX(&burst)
			j, ok := <-e.ready
			if !ok {
				return
			}
			e.serve(j, &burst)
		}
	}
}

// serve runs one job to a terminal. A job whose reply is staged for the
// burst stays owned until the send; every other terminal releases it here,
// exactly once.
func (e *udpEngine) serve(j *udpJob, burst *udpTXBurst) {
	j.transition(udpJobQueued, udpJobServing)
	j.burst = burst
	defer func() {
		if r := recover(); r != nil {
			// A panic outside the chain (the chain's recovery middleware
			// handles its own) is an abort terminal.
			udpDropPanic.Inc()
		}
		j.burst = nil
		if j.txLen > 0 {
			// The reply leaves with the burst; the burst releases the job.
			burst.add(j)
			return
		}
		j.release(udpJobServing)
	}()

	header, ok := wire.ParseHeader(j.rx[:j.rxLen])
	if !ok {
		// Unparseable header: let the client hang — any reply can
		// amplify. (Library-server parity.)
		udpDropMalformed.Inc()
		return
	}
	switch verdict := acceptHeader(header); verdict {
	case acceptOK:
	case acceptIgnore:
		udpDropIgnored.Inc()
		return
	case acceptNotImplemented, acceptFormatError:
		j.rejectInPlace(verdict)
		return
	}

	// The one ingress: the server decides eligibility, decode, and
	// context. A false return means the accepted header hid an
	// undecodable body — FORMERR, library parity.
	if !e.handler.ServeRaw(j, j.rx[:j.rxLen], j.readTime) {
		j.rejectInPlace(acceptFormatError)
	}
}

// Header-level accept verdicts, mirroring the library's default accept
// function byte for byte.
type acceptVerdict uint8

const (
	acceptOK acceptVerdict = iota
	acceptIgnore
	acceptNotImplemented
	acceptFormatError
)

func acceptHeader(h wire.Header) acceptVerdict {
	if h.QR() {
		return acceptIgnore
	}
	if op := h.Opcode(); op != dns.OpcodeQuery && op != dns.OpcodeNotify {
		return acceptNotImplemented
	}
	if h.QDCount != 1 || h.ANCount > 1 || h.NSCount > 1 || h.ARCount > 2 {
		return acceptFormatError
	}
	return acceptOK
}

// rejectInPlace writes the library-shaped rejection — a bare header with
// the request ID and opcode echoed, QR set, sections zeroed — without
// touching the allocator.
func (j *udpJob) rejectInPlace(verdict acceptVerdict) {
	var reply [wire.HeaderLen]byte
	copy(reply[0:2], j.rx[0:2]) // ID echo
	opcode := (j.rx[2] >> 3) & 0xF
	rcode := byte(dns.RcodeFormatError)
	if verdict == acceptNotImplemented {
		rcode = byte(dns.RcodeNotImplemented)
	}
	reply[2] = 0x80 | (opcode << 3) | (j.rx[2] & 0x01) // QR, opcode, RD echoed
	reply[3] = rcode
	_, _ = j.Write(reply[:])
}
