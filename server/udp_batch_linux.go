//go:build linux && (amd64 || arm64)

package server

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/semihalev/zlog/v2"
	"golang.org/x/sys/unix"
)

// The batched UDP I/O layer: raw recvmmsg/sendmmsg over preallocated
// mmsghdr/iovec/sockaddr/OOB arrays. The receive iovecs point straight
// into the job ring's RX buffers, and every descriptor-referenced fact —
// sockaddr, control message, flags — is copied into the job before the
// arrays are re-armed for the next cycle. Sends are armed from the jobs
// of a worker's burst, so a reply is never copied between goroutines and
// never waits on one. The netpoller callbacks are bound once per reader
// and per worker, so a quiet socket costs a parked goroutine and a busy
// one amortizes syscalls without allocating per packet.

// udpReaderPollErr counts poller failures a batch reader survived. A
// reader is its socket's only consumer, so this rate is the signal that
// one socket of a reuseport group is degraded — invisible in the query
// counters, which only show the group's aggregate.
var udpReaderPollErr = udpIngressDrops.Register("pollerr")

// mmsgHdr mirrors struct mmsghdr (linux/socket.h): a msghdr followed by
// the received length, padded to the struct's alignment.
//
// The layout is why this file is built only for the architectures named
// in its constraint. The padding below is the 64-bit one, and the
// descriptors it hands the kernel (Iovec.Len, Controllen) are 64-bit
// fields there; a 32-bit target has neither, and would read every
// message in a batch at the wrong offset rather than fail loudly. Every
// other target takes the portable reader instead.
type mmsgHdr struct {
	hdr  unix.Msghdr
	dlen uint32
	_    [4]byte
}

// The stride the kernel walks must be exactly this struct's size. A
// mismatch would corrupt every message after the first, which no test
// could be relied on to catch, so it is checked where it cannot be
// ignored: a negative array length is a compile error.
var _ [unsafe.Sizeof(mmsgHdr{}) - unsafe.Sizeof(unix.Msghdr{}) - 8]byte

// startBatched arms one batch reader per socket. The send handles were
// resolved at construction; an engine without them takes the portable
// path.
func (e *udpEngine) startBatched() bool {
	if e.txConns == nil {
		return false
	}
	for i, pc := range e.pcs {
		rc := e.txConns[pc]
		if rc == nil {
			return false
		}
		r := newUDPBatchReader(e, i, pc, rc)
		e.readers.Add(1)
		go r.run()
	}
	return true
}

// --- reader ---

type udpBatchReader struct {
	engine *udpEngine
	// idx is this socket's slab shard hint.
	idx int
	pc  *net.UDPConn
	rc  syscall.RawConn

	// permanentErrs counts consecutive errnos that no retry will fix. A
	// seccomp profile that filters recvmmsg answers EPERM or ENOSYS on
	// every call, and a reader that retries forever is a spinning core
	// serving nothing — with shutdown hung behind it in readers.Wait().
	permanentErrs int

	jobs  [udpBatchSize]*udpJob
	hdrs  [udpBatchSize]mmsgHdr
	iovs  [udpBatchSize]unix.Iovec
	names [udpBatchSize][unix.SizeofSockaddrInet6]byte
	oobs  [udpBatchSize][pktinfoSpace]byte
	// scrap absorbs the datagrams shed while the ring is empty.
	scrap [udpJobBufSize]byte

	// readFn is the netpoller callback, bound once so the poll loop does
	// not allocate a closure per cycle. armed/received/rerr carry its
	// arguments and results through the struct.
	readFn   func(fd uintptr) bool
	armed    int
	received int
	rerr     error

	// txBurst stages the replies of inline-served jobs; the receive
	// batch flushes back as one transmit batch at the end of the cycle.
	// Its sender slot lives past the workers' range.
	txBurst udpTXBurst
}

func newUDPBatchReader(e *udpEngine, idx int, pc *net.UDPConn, rc syscall.RawConn) *udpBatchReader {
	r := &udpBatchReader{engine: e, idx: idx, pc: pc, rc: rc}
	r.txBurst.slot = e.workers + idx
	r.readFn = func(fd uintptr) bool {
		n, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&r.hdrs[0])), //nolint:gosec // preallocated array armed for exactly this call
			uintptr(r.armed),                    //nolint:gosec // G115 — armed is 1..udpBatchSize
			0, 0, 0,
		)
		if errno != 0 {
			if errno == unix.EAGAIN {
				return false // netpoller waits for readability
			}
			r.received, r.rerr = 0, errno
			return true
		}
		r.received, r.rerr = int(n), nil //nolint:gosec // G115 — the kernel returns at most vlen
		return true
	}
	return r
}

func (r *udpBatchReader) run() {
	e := r.engine
	// held counts the armed jobs that persist across cycles. A batch
	// rarely fills: the kernel hands back what the queue holds, and the
	// old shape released every unfilled slot just to take it again on
	// the next spin — a full take/release round trip (lease atomics,
	// shard traffic, state transitions) per slot per cycle, priced at
	// wire speed. A job the kernel did not fill stays armed; only what
	// was consumed is re-taken, and every exit path below releases the
	// holdover before returning.
	held := 0
	releaseHeld := func() {
		for i := range held {
			r.jobs[i].release(udpJobReading)
		}
		held = 0
	}
	defer func() {
		// Staged inline replies leave before the holdover is released;
		// the burst releases its jobs on send.
		e.flushTX(&r.txBurst)
		releaseHeld()
		e.readers.Done()
	}()

	for {
		// The lease cap reserves a batch per reader. When it is reached
		// anyway the reader consumes and sheds, exactly as the portable
		// one does: waiting for a slab instead leaves the socket unread,
		// and what overflows then is dropped by the kernel, off our
		// counters and invisible to the operator watching for saturation.
		// It also arrives late — the packets that survive a backed-up
		// receive queue are the oldest ones, whose clients have often
		// stopped waiting. Shedding keeps the loss ours to report and
		// keeps what is served fresh.
		for held < udpBatchSize {
			j := e.take(r.idx)
			if j == nil {
				break
			}
			j.transition(udpJobFree, udpJobReading)
			r.arm(j, held)
			held++
		}
		if held == 0 {
			if !r.shed() {
				return
			}
			continue
		}

		r.armed = held
		err := r.rc.Read(r.readFn)
		if err != nil || r.rerr != nil {
			releaseHeld()
			// A reader is the only consumer of its socket: it exits when
			// the socket is gone and for nothing else. A transient errno
			// drops the cycle, and a poller error that is not a closed
			// socket is loud — silently returning would leave a live
			// socket with no reader, which the engine cannot detect
			// until every other reader has exited too.
			if err != nil {
				if isAdmissionStopErr(err) {
					return
				}
				udpReaderPollErr.Inc()
				zlog.Error("UDP batch reader poll failed",
					"error", err.Error(), "armed", r.armed)
				continue
			}
			if r.rerr == unix.EBADF {
				return
			}
			if r.permanentRerr() {
				return
			}
			udpDropError.Inc()
			continue
		}
		r.permanentErrs = 0

		n := r.received
		now := time.Now()
		for i := range n {
			r.finishRecv(i, now)
		}
		// The receive batch goes back out as one transmit batch: every
		// inline-served reply of this cycle in a single send.
		if r.txBurst.n > 0 {
			e.flushTX(&r.txBurst)
		}
		// The kernel filled slots 0..n-1; the survivors compact to the
		// front and stay armed for the next cycle. arm rebinds the slot's
		// descriptors; the job itself is untouched.
		m := 0
		for i := n; i < held; i++ {
			r.arm(r.jobs[i], m)
			m++
		}
		held = m
	}
}

// shed drains a batch into scratch memory and counts what it dropped, so
// saturation on this path reads the same as on the portable one. It
// returns false when the socket is finished, which is the only reason a
// reader stops.
func (r *udpBatchReader) shed() bool {
	for i := range r.hdrs {
		r.armScrap(i)
	}
	r.armed = udpBatchSize
	err := r.rc.Read(r.readFn)
	if err != nil {
		if isAdmissionStopErr(err) {
			return false
		}
		udpReaderPollErr.Inc()
		zlog.Error("UDP batch reader poll failed while shedding",
			"error", err.Error())
		return true
	}
	if r.rerr != nil {
		if r.rerr == unix.EBADF { //nolint:errorlint // raw errno from the syscall above
			return false
		}
		if r.permanentRerr() {
			return false
		}
		udpDropError.Inc()
		return true
	}
	udpDropFull.Add(int64(r.received))
	return true
}

// armScrap points slot i at the shed buffer. Every slot shares it: the
// bytes are on their way to being discarded, so the kernel overwriting
// one message with the next costs nothing. No sockaddr and no control
// data are collected — nothing here is going to be answered.
func (r *udpBatchReader) armScrap(i int) {
	r.jobs[i] = nil
	r.iovs[i] = unix.Iovec{Base: &r.scrap[0], Len: uint64(len(r.scrap))}
	h := &r.hdrs[i]
	h.dlen = 0
	h.hdr = unix.Msghdr{Iov: &r.iovs[i], Iovlen: 1}
}

// permanentRerr recognizes an errno retries cannot fix and hands the
// socket to the portable reader before returning true. The handoff keeps
// the socket served: exiting alone would silently orphan it, and the
// portable reader uses plain ReadMsgUDPAddrPort, which no recvmmsg
// filter touches.
func (r *udpBatchReader) permanentRerr() bool {
	switch r.rerr { //nolint:errorlint // raw errnos from the syscall
	case unix.ENOSYS, unix.EPERM, unix.EOPNOTSUPP:
	default:
		return false
	}
	r.permanentErrs++
	if r.permanentErrs < 3 {
		return false
	}
	zlog.Error("UDP batched receive unsupported on this system, "+
		"switching this socket to the portable reader",
		"errno", r.rerr.Error())
	e := r.engine
	e.readers.Add(1)
	go e.reader(r.idx, r.pc)
	return true
}

// arm points slot i's iovec and sockaddr/OOB storage at job j and resets
// the kernel-written lengths from the previous cycle.
func (r *udpBatchReader) arm(j *udpJob, i int) {
	r.jobs[i] = j
	r.iovs[i] = unix.Iovec{Base: &j.rx[0], Len: uint64(len(j.rx))}
	h := &r.hdrs[i]
	h.dlen = 0
	h.hdr = unix.Msghdr{
		Name:    &r.names[i][0],
		Namelen: unix.SizeofSockaddrInet6,
		Iov:     &r.iovs[i],
		Iovlen:  1,
	}
	if r.engine.wildcard {
		h.hdr.Control = &r.oobs[i][0]
		h.hdr.SetControllen(pktinfoSpace)
	}
}

// finishRecv copies everything the kernel wrote for message i into the
// job — before the arrays are re-armed — and hands it to the workers.
func (r *udpBatchReader) finishRecv(i int, now time.Time) {
	j := r.jobs[i]
	h := &r.hdrs[i]

	if h.hdr.Flags&unix.MSG_TRUNC != 0 {
		j.release(udpJobReading)
		udpDropTrunc.Inc()
		return
	}
	saLen := h.hdr.Namelen
	if saLen > uint32(len(j.rawSA)) || !j.setRemoteRaw(r.names[i][:saLen]) {
		j.release(udpJobReading)
		udpDropError.Inc()
		return
	}
	copy(j.rawSA[:saLen], r.names[i][:saLen])
	j.rawSALen = saLen

	j.rxLen = int(h.dlen)
	j.readTime = now
	j.pc = r.pc
	j.pktinfoLen = 0
	if r.engine.wildcard {
		if h.hdr.Flags&unix.MSG_CTRUNC != 0 ||
			!preparePktinfoReply(r.oobs[i][:h.hdr.Controllen], j) {
			j.release(udpJobReading)
			udpDropCtrunc.Inc()
			return
		}
	}

	// The inline pass first: a hit finishes here and its reply rides the
	// cycle's transmit batch — no ring, no worker wake, no lone send. A
	// handoff continues on the ring with its in-flight count carried; a
	// handler without the fast path takes the counted enqueue.
	if e := r.engine; e.inline != nil {
		if !e.serveInline(j, &r.txBurst) {
			e.enqueueCounted(j)
		}
		return
	}
	r.engine.enqueue(j)
}

// setRemoteRaw rewrites the cached classic views from a kernel sockaddr.
// The netip view drops an IPv6 scope zone (its string form would
// allocate); the reply never needs it — the batched send answers with the
// verbatim sockaddr.
func (j *udpJob) setRemoteRaw(sa []byte) bool {
	if len(sa) < 2 {
		return false
	}
	// The family is a host-order field; the port that follows it is
	// network order. Reading either with the wrong one silently rejects
	// or misroutes, so both are spelled out.
	family := binary.NativeEndian.Uint16(sa[0:2])
	switch family {
	case unix.AF_INET:
		if len(sa) < unix.SizeofSockaddrInet4 {
			return false
		}
		port := uint16(sa[2])<<8 | uint16(sa[3])
		var a4 [4]byte
		copy(a4[:], sa[4:8])
		j.setRemote(netip.AddrPortFrom(netip.AddrFrom4(a4), port))
		return true
	case unix.AF_INET6:
		if len(sa) < unix.SizeofSockaddrInet6 {
			return false
		}
		port := uint16(sa[2])<<8 | uint16(sa[3])
		var a16 [16]byte
		copy(a16[:], sa[8:24])
		j.setRemote(netip.AddrPortFrom(netip.AddrFrom16(a16), port))
		return true
	}
	return false
}

// --- send ---

// udpTXSender is a worker's sendmmsg state: preallocated headers and
// iovecs, armed from the jobs of one burst. It lives on the worker (via
// the engine's per-worker slot) so a send costs no allocation and no
// handoff — the worker owns every job it is sending for.
type udpTXSender struct {
	hdrs [udpTXMax]mmsgHdr
	iovs [udpTXMax]unix.Iovec
	// jobs mirrors hdrs slot for slot, so a batch the syscall refuses
	// can be retried job by job through the direct sender.
	jobs [udpTXMax]*udpJob

	writeFn func(fd uintptr) bool
	start   int
	count   int
	sent    int
	werr    error
}

// flushTX sends every staged reply in the burst and releases its jobs.
// Replies are grouped by socket, since one sendmmsg carries one socket's
// datagrams; a reuseport group's traffic normally arrives from one socket
// per burst, so the common case is a single call.
func (e *udpEngine) flushTX(b *udpTXBurst) {
	if b.n == 0 {
		return
	}
	s := &e.txSenders[b.slot]
	for start := 0; start < b.n; {
		pc := b.jobs[start].pc
		end := start + 1
		for end < b.n && b.jobs[end].pc == pc {
			end++
		}
		e.sendGroup(s, b.jobs[start:end], pc)
		start = end
	}
	b.release()
}

// sendGroup arms and sends one socket's datagrams, retrying from the
// unsent index on a partial send. A send that fails is counted: the byte
// path already treats a completed Write as "the response left the
// process", and a datagram transport has no delivery contract to unwind.
func (e *udpEngine) sendGroup(s *udpTXSender, jobs []*udpJob, pc *net.UDPConn) {
	rc := e.txConns[pc]
	if rc == nil || e.txRetired.Load() {
		// A socket that never armed the batch path (or a job that arrived
		// before it did), or a system whose sendmmsg proved permanently
		// unusable: send the ordinary way.
		for _, j := range jobs {
			j.sendDirect()
		}
		return
	}
	k := 0
	for _, j := range jobs {
		if j.txLen == 0 {
			continue
		}
		if j.rawSALen == 0 {
			// No raw sockaddr was armed for this job: it was read by the
			// portable reader (a socket that fell back off recvmmsg stays
			// in txConns). sendmmsg would send it nowhere — or, on a
			// recycled slab, to the previous client.
			j.sendDirect()
			continue
		}
		s.iovs[k] = unix.Iovec{Base: &j.tx[0], Len: uint64(j.txLen)} //nolint:gosec // G115 — txLen is a staged reply length, bounded by the TX buffer
		s.jobs[k] = j
		h := &s.hdrs[k]
		h.dlen = 0
		h.hdr = unix.Msghdr{
			Name:    &j.rawSA[0],
			Namelen: j.rawSALen,
			Iov:     &s.iovs[k],
			Iovlen:  1,
		}
		if j.pktinfoLen > 0 {
			h.hdr.Control = &j.pktinfo[0]
			h.hdr.SetControllen(j.pktinfoLen)
		}
		k++
	}
	if k == 0 {
		return
	}

	done := 0
	for done < k {
		s.start, s.count = done, k
		err := rc.Write(s.writeFn)
		if err == nil {
			err = s.werr
		}
		if err != nil || s.sent <= 0 {
			// A batch the syscall refuses falls through to the direct
			// sender, job by job. That isolates a poisoned destination —
			// sendmmsg stops the whole batch at the first refused message
			// (a netfilter EPERM for one client used to drop everyone
			// behind it) — and it is what keeps replies flowing when the
			// syscall itself is denied. An errno retries cannot fix
			// retires batch TX outright; without that, a seccomp policy
			// that permits recvmmsg but not sendmmsg was a server that
			// read every query and answered none, forever.
			switch err { //nolint:errorlint // raw errno from the syscall
			case unix.ENOSYS, unix.EOPNOTSUPP:
				if !e.txRetired.Swap(true) {
					zlog.Error("UDP batched send unsupported on this system, "+
						"switching to direct replies", "errno", err.Error())
				}
			}
			for i := done; i < k; i++ {
				s.jobs[i].sendDirect()
			}
			break
		}
		done += s.sent
	}
	for i := range k {
		s.jobs[i] = nil
	}
}

func newUDPTXSender(s *udpTXSender) {
	s.writeFn = func(fd uintptr) bool {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&s.hdrs[s.start])), //nolint:gosec // preallocated array armed for exactly this call
			uintptr(s.count-s.start),                  //nolint:gosec // G115 — a positive remainder of a 1..udpTXMax burst
			0, 0, 0,
		)
		if errno != 0 {
			if errno == unix.EAGAIN {
				return false // netpoller waits for writability
			}
			s.sent, s.werr = 0, errno
			return true
		}
		s.sent, s.werr = int(n), nil //nolint:gosec // G115 — the kernel returns at most vlen
		return true
	}
}
