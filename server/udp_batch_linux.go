//go:build linux

package server

import (
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

// mmsgHdr mirrors struct mmsghdr (linux/socket.h).
type mmsgHdr struct {
	hdr  unix.Msghdr
	dlen uint32
	_    [4]byte
}

// startBatched arms one batch reader per socket. The send handles were
// resolved at construction; an engine without them takes the portable
// path.
func (e *udpEngine) startBatched() bool {
	if e.txConns == nil {
		return false
	}
	for _, pc := range e.pcs {
		rc := e.txConns[pc]
		if rc == nil {
			return false
		}
		r := newUDPBatchReader(e, pc, rc)
		e.readers.Add(1)
		go r.run()
	}
	return true
}

// --- reader ---

type udpBatchReader struct {
	engine *udpEngine
	pc     *net.UDPConn
	rc     syscall.RawConn

	jobs  [udpBatchSize]*udpJob
	hdrs  [udpBatchSize]mmsgHdr
	iovs  [udpBatchSize]unix.Iovec
	names [udpBatchSize][unix.SizeofSockaddrInet6]byte
	oobs  [udpBatchSize][pktinfoSpace]byte

	// readFn is the netpoller callback, bound once so the poll loop does
	// not allocate a closure per cycle. armed/received/rerr carry its
	// arguments and results through the struct.
	readFn   func(fd uintptr) bool
	armed    int
	received int
	rerr     error
}

func newUDPBatchReader(e *udpEngine, pc *net.UDPConn, rc syscall.RawConn) *udpBatchReader {
	r := &udpBatchReader{engine: e, pc: pc, rc: rc}
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
	defer e.readers.Done()

	for {
		// The ring is sized so every reader can arm a full batch; under
		// transient exhaustion the reader waits for its first job — the
		// kernel's receive buffer is the queue meanwhile — rather than
		// consuming its socket's share of the load just to discard it.
		// Shutdown unblocks this wait: draining workers release their
		// jobs back to the ring, and the next arm fails on the closed
		// socket.
		j0 := <-e.free
		j0.transition(udpJobFree, udpJobReading)
		r.arm(j0, 0)
		k := 1
		for k < udpBatchSize {
			var j *udpJob
			select {
			case j = <-e.free:
			default:
			}
			if j == nil {
				break
			}
			j.transition(udpJobFree, udpJobReading)
			r.arm(j, k)
			k++
		}

		r.armed = k
		err := r.rc.Read(r.readFn)
		if err != nil || r.rerr != nil {
			for i := range k {
				r.jobs[i].release(udpJobReading)
			}
			// A reader is the only consumer of its socket: it exits when
			// the socket is gone and for nothing else. A transient errno
			// drops the cycle, and a poller error that is not a closed
			// socket is loud — silently returning would leave a live
			// socket with no reader, which the engine cannot detect
			// until every other reader has exited too.
			if err != nil {
				if isClosedNetErr(err) {
					return
				}
				udpReaderPollErr.Inc()
				zlog.Error("UDP batch reader poll failed",
					"error", err.Error(), "armed", k)
				continue
			}
			if r.rerr == unix.EBADF {
				return
			}
			udpDropError.Inc()
			continue
		}

		n := r.received
		now := time.Now()
		for i := range n {
			r.finishRecv(i, now)
		}
		for i := n; i < k; i++ {
			r.jobs[i].release(udpJobReading)
		}
	}
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

	j.state = udpJobQueued
	select {
	case r.engine.ready <- j:
	default:
		j.state = udpJobReading
		j.release(udpJobReading)
		udpDropQueue.Inc()
	}
}

// setRemoteRaw rewrites the cached classic views from a kernel sockaddr.
// The netip view drops an IPv6 scope zone (its string form would
// allocate); the reply never needs it — the batched send answers with the
// verbatim sockaddr.
func (j *udpJob) setRemoteRaw(sa []byte) bool {
	if len(sa) < 2 {
		return false
	}
	family := uint16(sa[0]) | uint16(sa[1])<<8
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
	if rc == nil {
		// A socket that never armed the batch path (or a job that arrived
		// before it did): send the ordinary way.
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
		s.iovs[k] = unix.Iovec{Base: &j.tx[0], Len: uint64(j.txLen)} //nolint:gosec // G115 — txLen is a staged reply length, bounded by the TX buffer
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
		if err != nil {
			udpTXError.Add(int64(k - done))
			return
		}
		if s.sent <= 0 {
			udpTXError.Add(int64(k - done))
			return
		}
		done += s.sent
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
