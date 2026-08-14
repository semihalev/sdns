package server

import (
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
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

	// Strict-path state, all job-owned: the wire-born request, the context
	// carrier, and the edns writer wrapper's storage.
	req        middleware.Request
	carrier    jobCarrier
	ednsWriter edns.ResponseWriter

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

func (j *udpJob) Write(b []byte) (int, error) {
	j.written = true
	if j.pktinfoLen > 0 {
		n, _, err := j.pc.WriteMsgUDPAddrPort(b, j.pktinfo[:j.pktinfoLen], j.raddr)
		return n, err
	}
	n, _, err := j.pc.WriteMsgUDPAddrPort(b, nil, j.raddr)
	return n, err
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
func (j *udpJob) StrictSlots() (*middleware.Request, *jobCarrier, *edns.ResponseWriter) {
	return &j.req, &j.carrier, &j.ednsWriter
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

	workers int
	readers sync.WaitGroup
	workerG sync.WaitGroup
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
	}
	// Capacity equation (zero-path §7): in-flight jobs = queue depth +
	// one per busy worker + one in each reader's hand. The ring holds
	// exactly that many slabs; MaxInboundInFlight is this derived bound.
	inFlight := queue + workers + len(pcs)
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
		go e.worker()
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
				if isClosedNetErr(err) {
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
			if isClosedNetErr(err) {
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

		// The state write must precede the send: the channel gives the
		// worker its happens-before for every job field.
		j.state = udpJobQueued
		select {
		case e.ready <- j:
		default:
			j.state = udpJobReading
			j.release(udpJobReading)
			udpDropQueue.Inc()
		}
	}
}

// release returns a job to the ring from any owned state.
func (j *udpJob) release(from uint8) {
	j.transition(from, udpJobFree)
	j.written = false
	j.rxLen = 0
	j.pktinfoLen = 0
	j.engine.free <- j
}

func (e *udpEngine) worker() {
	defer e.workerG.Done()
	for j := range e.ready {
		e.serve(j)
	}
}

// serve runs one job to a terminal and releases it exactly once.
func (e *udpEngine) serve(j *udpJob) {
	j.transition(udpJobQueued, udpJobServing)
	defer func() {
		if r := recover(); r != nil {
			// A panic outside the chain (the chain's recovery middleware
			// handles its own) is an abort terminal.
			udpDropPanic.Inc()
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
