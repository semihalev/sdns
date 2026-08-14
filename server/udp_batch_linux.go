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
// mmsghdr/iovec/sockaddr/OOB arrays, with the iovecs pointing straight
// into the job ring's RX buffers and replies parked until the
// coordinator's sendmmsg carries them. Every descriptor-referenced fact —
// sockaddr, control message, flags — is copied into the job before the
// arrays are re-armed for the next cycle. The netpoller callbacks are
// bound once per reader/sender, so a quiet socket costs a parked
// goroutine and a busy one amortizes syscalls across the batch without
// allocating per packet.

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

// startBatched arms one batch reader and one batch sender per socket.
// Any socket that refuses its raw descriptor sends the whole engine down
// the portable path — mixed modes would split the job ring's assumptions.
func (e *udpEngine) startBatched() bool {
	type pair struct {
		rc syscall.RawConn
		pc *net.UDPConn
	}
	pairs := make([]pair, 0, len(e.pcs))
	for _, pc := range e.pcs {
		rc, err := pc.SyscallConn()
		if err != nil {
			return false
		}
		pairs = append(pairs, pair{rc: rc, pc: pc})
	}
	for _, p := range pairs {
		s := newUDPBatchSender(e, p.rc)
		e.senders = append(e.senders, s)
		e.senderG.Add(1)
		go s.run()

		r := newUDPBatchReader(e, p.pc, p.rc, s)
		e.readers.Add(1)
		go r.run()
	}
	return true
}

// stopBatchSenders closes the coordinators once no worker can send.
func (e *udpEngine) stopBatchSenders() {
	for _, s := range e.senders {
		close(s.queue)
	}
	e.senderG.Wait()
}

// --- reader ---

type udpBatchReader struct {
	engine *udpEngine
	pc     *net.UDPConn
	rc     syscall.RawConn
	sender *udpBatchSender

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

func newUDPBatchReader(e *udpEngine, pc *net.UDPConn, rc syscall.RawConn, s *udpBatchSender) *udpBatchReader {
	r := &udpBatchReader{engine: e, pc: pc, rc: rc, sender: s}
	r.readFn = func(fd uintptr) bool {
		n, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&r.hdrs[0])), //nolint:gosec // preallocated array armed for exactly this call
			uintptr(r.armed),
			0, 0, 0,
		)
		if errno != 0 {
			if errno == unix.EAGAIN {
				return false // netpoller waits for readability
			}
			r.received, r.rerr = 0, errno
			return true
		}
		r.received, r.rerr = int(n), nil
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
	j.sender = r.sender
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

// --- sender ---

// udpBatchSender is the park-until-send coordinator for one socket:
// workers enqueue their finished jobs and park on the job's completion
// slot; the coordinator drains what is queued right now into one
// sendmmsg, retries partial sends, and wakes every parked job exactly
// once with its send's result.
type udpBatchSender struct {
	engine *udpEngine
	rc     syscall.RawConn
	queue  chan *udpJob

	batch [udpBatchSize]*udpJob
	hdrs  [udpBatchSize]mmsgHdr
	iovs  [udpBatchSize]unix.Iovec

	writeFn func(fd uintptr) bool
	start   int
	count   int
	sent    int
	werr    error
}

func newUDPBatchSender(e *udpEngine, rc syscall.RawConn) *udpBatchSender {
	s := &udpBatchSender{
		engine: e,
		rc:     rc,
		queue:  make(chan *udpJob, udpBatchSize),
	}
	s.writeFn = func(fd uintptr) bool {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&s.hdrs[s.start])), //nolint:gosec // preallocated array armed for exactly this call
			uintptr(s.count-s.start),
			0, 0, 0,
		)
		if errno != 0 {
			if errno == unix.EAGAIN {
				return false // netpoller waits for writability
			}
			s.sent, s.werr = 0, errno
			return true
		}
		s.sent, s.werr = int(n), nil
		return true
	}
	return s
}

// send parks the caller until the coordinator has carried b. b must stay
// valid until send returns — on this path it always lives in the job's
// own TX storage.
func (s *udpBatchSender) send(j *udpJob, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	j.txData = b
	s.queue <- j
	err := <-j.txDone
	j.txData = nil
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *udpBatchSender) run() {
	defer s.engine.senderG.Done()
	for first := range s.queue {
		s.batch[0] = first
		k := 1
	fill:
		for k < udpBatchSize {
			select {
			case j, ok := <-s.queue:
				if !ok {
					break fill
				}
				s.batch[k] = j
				k++
			default:
				break fill
			}
		}

		for i := range k {
			j := s.batch[i]
			s.iovs[i] = unix.Iovec{Base: &j.txData[0], Len: uint64(len(j.txData))}
			h := &s.hdrs[i]
			h.dlen = 0
			h.hdr = unix.Msghdr{
				Name:    &j.rawSA[0],
				Namelen: j.rawSALen,
				Iov:     &s.iovs[i],
				Iovlen:  1,
			}
			if j.pktinfoLen > 0 {
				h.hdr.Control = &j.pktinfo[0]
				h.hdr.SetControllen(j.pktinfoLen)
			}
		}

		done := 0
		for done < k {
			s.start, s.count = done, k
			err := s.rc.Write(s.writeFn)
			if err == nil {
				err = s.werr
			}
			if err != nil {
				// The socket is unusable (shutdown among the causes):
				// every remaining parked job learns it and unwinds.
				for i := done; i < k; i++ {
					s.batch[i].txDone <- err
				}
				break
			}
			for i := done; i < done+s.sent; i++ {
				s.batch[i].txDone <- nil
			}
			done += s.sent
		}
	}
}
