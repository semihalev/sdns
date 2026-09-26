package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// The owned DNS-over-QUIC engine (RFC 9250). Its contract:
//
//   - A query is a stream: a 2-octet length, the message, and the
//     client's FIN. The reply goes back on the same stream the same way.
//     Streams on one connection are served concurrently, which is what
//     DoQ is for. Each slab owns a goroutine for as long as it lives and
//     a stream is handed to it over a channel: a go statement per stream
//     was the one allocation left on a hit.
//   - A stream takes its slab from the engine the moment it is accepted
//     and gives it back when answered. When none is free the stream alone
//     is refused, with DOQ_EXCESSIVE_LOAD, rather than parked: the slabs
//     bound both the memory and the goroutines serving streams, and a
//     client has a signal it can act on.
//   - The query enters ServeRaw like a UDP or TCP one, as bytes on a
//     job-owned carrier, so a cache hit is served without decoding and
//     packed straight into the slab. The reply's message ID is set to
//     zero in place on its way out.
//   - Protocol errors close the connection with DOQ_PROTOCOL_ERROR, as
//     §4.3.3 lists them. A stream the client abandons, reset or left
//     unfinished, costs that stream only.

// DoQ error codes (RFC 9250 §4.3), untyped: the same code closes a
// stream or a connection, which quic-go types apart.
const (
	doqNoError         = 0x0
	doqInternalError   = 0x1
	doqProtocolError   = 0x2
	doqRequestCanceled = 0x3
	doqExcessiveLoad   = 0x4
)

const (
	// doqALPN is the one token RFC 9250 §4.1 defines. The draft tokens
	// framed messages differently and are not offered.
	doqALPN = "doq"
	// doqQueryWait bounds a stream from acceptance to its FIN, the same
	// allowance a TCP frame gets from its prefix.
	doqQueryWait = tcpFirstReadWait
	// doqIdleTimeout is the connection idle timeout offered to clients.
	doqIdleTimeout = 5 * time.Second
	// doqMaxStreams bounds the streams one connection may have open.
	doqMaxStreams = 32
	// doqShutdownForceIn is the drain allowance when the deadline has
	// already passed.
	doqShutdownForceIn = time.Millisecond
)

var errDoQFrame = errors.New("doq: message length out of range")

// doqQUICConfig is the transport configuration: a DoQ client needs only
// bidirectional streams, and a stream carries one message each way.
func doqQUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:         doqIdleTimeout,
		MaxStreamReceiveWindow: dns.MaxMsgSize + dnsclient.FramePrefixLen,
		MaxIncomingStreams:     doqMaxStreams,
		// A client opening a unidirectional stream is a protocol error
		// (§4.3.3); a negative limit allows none.
		MaxIncomingUniStreams: -1,
	}
}

// doqJob is one stream's slab: RX for the query, TX with prefix headroom
// for the reply, and the strict-path state ServeRaw serves it on.
type doqJob struct {
	engine    *doqEngine
	conn      *quic.Conn
	stream    *quic.Stream
	slabShard uint8
	rx        []byte
	tx        []byte
	// written is set once a whole reply is out; only then does the
	// stream end with a FIN.
	written bool
	// scratch takes the length prefix and the probe for the FIN.
	scratch [dnsclient.FramePrefixLen]byte
	// work hands the slab's goroutine its next stream; closing it ends
	// the goroutine.
	work chan struct{}

	leased atomic.Bool

	req        middleware.Request
	chain      middleware.Chain
	carrier    jobCarrier
	ednsWriter edns.ResponseWriter
}

var _ strictSlots = (*doqJob)(nil)

// StrictSlots hands ServeRaw the job-owned strict-path storage.
func (j *doqJob) StrictSlots() (*middleware.Request, *middleware.Chain, *jobCarrier, *edns.ResponseWriter) {
	return &j.req, &j.chain, &j.carrier, &j.ednsWriter
}

// LeaseWire hands out the TX payload region behind the prefix headroom.
func (j *doqJob) LeaseWire(capacity int) []byte {
	if capacity > len(j.tx)-dnsclient.FramePrefixLen {
		return nil
	}
	return j.tx[dnsclient.FramePrefixLen:dnsclient.FramePrefixLen]
}

// Write sends one reply on the stream: framed, its message ID zero. A
// reply built in the lease is framed where it lies; anything else is
// copied into the slab, or into a buffer of its own when it does not fit,
// never changed where it came from, the bytes may be a cached entry's.
func (j *doqJob) Write(b []byte) (int, error) {
	if len(b) < wire.HeaderLen || len(b) > dns.MaxMsgSize {
		return 0, errDoQFrame
	}
	var frame []byte
	if n := dnsclient.FramePrefixLen + len(b); n <= len(j.tx) {
		frame = j.tx[:n]
		if &frame[dnsclient.FramePrefixLen] != &b[0] {
			copy(frame[dnsclient.FramePrefixLen:], b)
		}
	} else {
		frame = make([]byte, n)
		copy(frame[dnsclient.FramePrefixLen:], b)
	}
	binary.BigEndian.PutUint16(frame, uint16(len(b))) //nolint:gosec // bounded by dns.MaxMsgSize above
	frame[2], frame[3] = 0, 0
	// A client that stops reading, its flow-control window shut, must not
	// hold the slab: the reply gets the allowance a query gets.
	_ = j.stream.SetWriteDeadline(time.Now().Add(doqQueryWait))
	if _, err := j.stream.Write(frame); err != nil {
		// Part of the frame may be out. The stream is reset, not finished:
		// a FIN after a partial message is a protocol error (§4.3.3).
		return 0, err
	}
	j.written = true
	return len(b), nil
}

// WriteMsg packs into the TX payload region when the reply fits it.
func (j *doqJob) WriteMsg(m *dns.Msg) error {
	// The full-length slice: PackBuffer selects the caller's buffer by
	// len, not cap.
	out, err := m.PackBuffer(j.tx[dnsclient.FramePrefixLen:])
	if err != nil {
		return err
	}
	_, err = j.Write(out)
	return err
}

func (j *doqJob) LocalAddr() net.Addr  { return j.conn.LocalAddr() }
func (j *doqJob) RemoteAddr() net.Addr { return j.conn.RemoteAddr() }
func (j *doqJob) Close() error         { return j.stream.Close() }

// Proto names the transport for the chain's base writer.
func (j *doqJob) Proto() string { return "doq" }

// contextRawHandler is a rawHandler that takes the stream's context, so a
// client cancelling a query in flight stops the work it started.
type contextRawHandler interface {
	ServeRawContext(parent context.Context, w middleware.Transport, raw []byte, readTime time.Time) bool
}

// doqStopBit marks the in-flight count closed. Set when shutdown begins,
// it refuses every later stream in the same atomic step that would have
// counted it, so admission and the drain cannot cross.
const doqStopBit = int64(1) << 62

// doqEngine owns one listener's accept loop, connection registry and
// stream slabs.
type doqEngine struct {
	handler    rawHandler
	ctxHandler contextRawHandler
	maxConns   int64

	slabRotor atomic.Uint32
	tokens    chan struct{}
	cache     slabCache[doqJob]
	closing   chan struct{}

	mu      sync.Mutex
	conns   map[*quic.Conn]struct{}
	stopped bool
	active  atomic.Int64
	// inflight counts the streams admitted and not yet done, with
	// doqStopBit once shutdown begins; loops joins the connection loops.
	inflight atomic.Int64
	loops    sync.WaitGroup
}

func newDoQEngine(handler rawHandler, plan resourcePlan) *doqEngine {
	jobs := max(plan.doqJobs, 1)
	e := &doqEngine{
		handler:  handler,
		maxConns: int64(max(plan.doqConns, 1)),
		tokens:   make(chan struct{}, jobs),
		closing:  make(chan struct{}),
		conns:    make(map[*quic.Conn]struct{}),
	}
	e.ctxHandler, _ = handler.(contextRawHandler)
	for range jobs {
		e.tokens <- struct{}{}
	}
	return e
}

func newDoQJob(e *doqEngine) *doqJob {
	j := &doqJob{
		engine: e,
		rx:     make([]byte, tcpSmallFrame),
		tx:     make([]byte, dnsclient.FramePrefixLen+tcpSmallReply),
		work:   make(chan struct{}, 1),
	}
	go j.loop()
	return j
}

// loop is the slab's goroutine: one stream per hand-off, until the slab
// is dropped.
func (j *doqJob) loop() {
	for range j.work {
		j.serve()
	}
}

// stopJob ends a slab's goroutine once the slab can no longer be taken.
func stopJob(j *doqJob) { close(j.work) }

// tryAcquire takes a slab without waiting: a stream with no slab free is
// refused on the spot.
func (e *doqEngine) tryAcquire() *doqJob {
	select {
	case <-e.tokens:
	default:
		return nil
	}
	shard := int(e.slabRotor.Add(1))
	j := e.cache.get(shard)
	if j == nil {
		j = newDoQJob(e)
	}
	j.slabShard = uint8(shard & (slabShardCount - 1))
	j.leased.Store(true)
	return j
}

// put returns a slab to the cache, then its token. After shutdown has
// begun the cache is drained again, whichever of the two comes last: a
// slab parked behind the shutdown's own drain would keep its goroutine.
func (e *doqEngine) put(j *doqJob) {
	if !j.leased.CompareAndSwap(true, false) {
		panic("server: doq job released twice")
	}
	j.conn, j.stream = nil, nil
	e.cache.put(int(j.slabShard), j)
	select {
	case <-e.closing:
		e.cache.drain(stopJob)
	default:
	}
	e.tokens <- struct{}{}
}

// admit counts a stream in, or refuses it once shutdown has begun.
func (e *doqEngine) admit() bool {
	if e.inflight.Add(1)&doqStopBit != 0 {
		e.inflight.Add(-1)
		return false
	}
	return true
}

// release counts a stream out.
func (e *doqEngine) release() { e.inflight.Add(-1) }

// drained waits until the deadline for the streams admitted before the
// stop bit to finish, and reports whether they did.
func (e *doqEngine) drained(deadline time.Time) bool {
	for e.inflight.Load() != doqStopBit {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

func (e *doqEngine) quiesced() bool { return len(e.tokens) == cap(e.tokens) }

func (e *doqEngine) trimIdle() int { return e.cache.drain(stopJob) }

// serve accepts connections until the listener closes.
func (e *doqEngine) serve(ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		if !e.register(conn) {
			_ = conn.CloseWithError(doqExcessiveLoad, "")
			continue
		}
		go e.serveConn(conn)
	}
}

// register admits a connection under the cap, and never once shutdown
// has begun waiting on the connection loops.
func (e *doqEngine) register(conn *quic.Conn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return false
	}
	if e.active.Load() >= e.maxConns {
		doqDropConnCap.Inc()
		return false
	}
	e.active.Add(1)
	e.loops.Add(1)
	e.conns[conn] = struct{}{}
	return true
}

func (e *doqEngine) unregister(conn *quic.Conn) {
	e.mu.Lock()
	delete(e.conns, conn)
	e.mu.Unlock()
	e.active.Add(-1)
	e.loops.Done()
}

// serveConn accepts the connection's streams and hands each to its own
// goroutine with a slab, or refuses it when none is free.
func (e *doqEngine) serveConn(conn *quic.Conn) {
	defer e.unregister(conn)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		if !e.admit() {
			// Shutting down: the connection closes once the drain is over.
			stream.CancelRead(doqNoError)
			stream.CancelWrite(doqNoError)
			continue
		}
		j := e.tryAcquire()
		if j == nil {
			e.release()
			doqDropLoad.Inc()
			stream.CancelRead(doqExcessiveLoad)
			stream.CancelWrite(doqExcessiveLoad)
			continue
		}
		j.conn, j.stream = conn, stream
		j.work <- struct{}{}
	}
}

// serve reads the stream's query, serves it and answers, then returns
// the slab.
func (j *doqJob) serve() {
	e := j.engine
	conn, stream := j.conn, j.stream
	defer e.release()
	defer e.put(j)
	defer func() {
		if r := recover(); r != nil {
			doqDropPanic.Inc()
			stream.CancelRead(doqInternalError)
			stream.CancelWrite(doqInternalError)
		}
	}()

	readTime := time.Now()
	msg, code := j.readQuery(readTime.Add(doqQueryWait))
	switch code {
	case doqNoError:
	case doqProtocolError:
		doqDropProtocol.Inc()
		_ = conn.CloseWithError(doqProtocolError, "")
		return
	default:
		stream.CancelRead(code)
		stream.CancelWrite(code)
		return
	}

	// A client that has already cancelled does not want the answer
	// (§4.3.1).
	if stream.Context().Err() != nil {
		stream.CancelRead(doqRequestCanceled)
		return
	}

	header, _ := wire.ParseHeader(msg)
	if header.ID != 0 || hasTCPKeepalive(msg, header) {
		doqDropProtocol.Inc()
		_ = conn.CloseWithError(doqProtocolError, "")
		return
	}
	j.written = false
	switch verdict := acceptHeader(header); verdict {
	case acceptOK:
		// The ID the chain sees is ours to pick (§4.2.1: a message
		// forwarded from DoQ gets one by the rules of the next transport);
		// the reply goes out with zero regardless.
		binary.BigEndian.PutUint16(msg[0:2], dns.Id())
		var ok bool
		if e.ctxHandler != nil {
			ok = e.ctxHandler.ServeRawContext(stream.Context(), j, msg, readTime)
		} else {
			ok = e.handler.ServeRaw(j, msg, readTime)
		}
		if !ok {
			j.rejectInPlace(acceptFormatError, msg)
		}
	case acceptIgnore:
		doqDropIgnored.Inc()
		stream.CancelWrite(doqProtocolError)
		return
	case acceptNotImplemented, acceptFormatError:
		j.rejectInPlace(verdict, msg)
	}
	if !j.written {
		// Nothing sent, or a reply cut short: §4.3.2 has the stream reset
		// rather than finished, and a FIN after part of a message would be
		// a protocol error of our own.
		stream.CancelWrite(doqInternalError)
		return
	}
	_ = stream.Close()
}

// readQuery reads one framed query and the FIN that must follow it, by
// deadline. It answers the message, or the error code the stream ends
// with: doqProtocolError for what §4.3.3 names, the connection's to
// close; anything else a failure of this stream alone.
func (j *doqJob) readQuery(deadline time.Time) ([]byte, quic.StreamErrorCode) {
	stream := j.stream
	_ = stream.SetReadDeadline(deadline)
	if _, err := io.ReadFull(stream, j.scratch[:]); err != nil {
		return nil, readFailure(err)
	}
	length := int(binary.BigEndian.Uint16(j.scratch[:]))
	if length < wire.HeaderLen {
		return nil, doqProtocolError
	}
	msg := j.rx
	if length > len(msg) {
		// A query past the slab's class is rare. It gets a buffer of its
		// own for this query only: the slab keeps the size it is priced
		// at, rather than carrying the largest query it ever saw.
		msg = make([]byte, length)
	}
	msg = msg[:length]
	if _, err := io.ReadFull(stream, msg); err != nil {
		return nil, readFailure(err)
	}
	// One message per stream, then the FIN.
	switch n, err := stream.Read(j.scratch[:1]); {
	case n > 0:
		return nil, doqProtocolError
	case errors.Is(err, io.EOF):
		return msg, doqNoError
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, doqProtocolError
	default:
		return nil, doqRequestCanceled
	}
}

// readFailure classifies a read that ended before the query did: a FIN
// in the middle of the message is a protocol error (§4.3.3), a client
// that went quiet or cancelled costs its stream only.
func readFailure(err error) quic.StreamErrorCode {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return doqProtocolError
	}
	return doqRequestCanceled
}

// rejectInPlace answers with the library-shaped bare header, from the
// slab, allocation-free.
func (j *doqJob) rejectInPlace(verdict acceptVerdict, msg []byte) {
	out := j.tx[dnsclient.FramePrefixLen : dnsclient.FramePrefixLen+wire.HeaderLen]
	clear(out)
	opcode := (msg[2] >> 3) & 0xF
	rcode := byte(dns.RcodeFormatError)
	if verdict == acceptNotImplemented {
		rcode = byte(dns.RcodeNotImplemented)
	}
	out[2] = 0x80 | (opcode << 3) | (msg[2] & 0x01)
	out[3] = rcode
	_, _ = j.Write(out)
}

// hasTCPKeepalive reports whether the message carries the
// edns-tcp-keepalive option, a protocol error on DoQ (§4.3.3). Only the
// additional section can hold the OPT; a malformed message is left for
// the chain to answer as one.
func hasTCPKeepalive(msg []byte, h wire.Header) bool {
	if h.ARCount == 0 {
		return false
	}
	off := wire.HeaderLen
	for range h.QDCount {
		q, ok := wire.ParseQuestion(msg, off)
		if !ok {
			return false
		}
		off = q.End
	}
	for i := 0; i < int(h.ANCount)+int(h.NSCount)+int(h.ARCount); i++ {
		rr, ok := wire.ParseRR(msg, off)
		if !ok {
			return false
		}
		off = rr.End
		if rr.Type != dns.TypeOPT {
			continue
		}
		for p := rr.End - rr.RDLen; p+4 <= rr.End; {
			code := binary.BigEndian.Uint16(msg[p:])
			size := int(binary.BigEndian.Uint16(msg[p+2:]))
			if code == dns.EDNS0TCPKEEPALIVE {
				return true
			}
			p += 4 + size
		}
	}
	return false
}

// shutdown stops the engine: no connection is admitted from here, the
// streams in flight get until the deadline, then every connection closes.
// The caller has closed the listener.
func (e *doqEngine) shutdown(deadline time.Time) error {
	close(e.closing)
	// From here no stream is admitted, on any connection: the drain below
	// waits on a count nothing can add to.
	e.inflight.Or(doqStopBit)
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()

	wait := time.Until(deadline)
	if wait <= 0 {
		wait = doqShutdownForceIn
	}
	var err error
	if !e.drained(time.Now().Add(wait)) {
		err = errDrainTimeout
	}

	e.mu.Lock()
	for conn := range e.conns {
		_ = conn.CloseWithError(doqNoError, "")
	}
	e.mu.Unlock()

	joined := make(chan struct{})
	go func() { e.loops.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		err = errDrainTimeout
	}
	if !e.drained(time.Now().Add(2 * time.Second)) {
		err = errDrainTimeout
	}
	// The parked slabs' goroutines end here; one still serving ends when
	// its put finds the engine closing.
	e.cache.drain(stopJob)
	return err
}

var (
	doqIngressDrops = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_doq_ingress_drops_total",
		Help: "DoQ connections and streams refused before the handler, by reason",
	}, []string{"reason"})

	doqDropConnCap  = doqIngressDrops.Register("conncap")
	doqDropLoad     = doqIngressDrops.Register("load")
	doqDropProtocol = doqIngressDrops.Register("protocol")
	doqDropIgnored  = doqIngressDrops.Register("ignored")
	doqDropPanic    = doqIngressDrops.Register("panic")
)
