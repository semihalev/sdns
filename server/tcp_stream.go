package server

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
)

// The stream burst layer. A pipelining client keeps several queries in
// flight, and answering each one with its own read and write syscall is
// what the profile showed the TCP path spending its time on, the write
// side alone outweighed everything the middleware chain does.
//
// So a connection reads through a fill buffer and writes through a drain
// buffer: one read syscall hands over as many frames as the client sent,
// and their replies leave in one write. The flush point is the moment the
// connection is about to block for more input. Nothing is ever held back
// waiting for a client that has stopped talking, so a single-query
// connection still costs exactly one read and one write, and no reply
// waits on a timer.
//
// Sizes are per connection and bounded: the fill buffer holds a burst of
// queries, the drain buffer a burst of replies, and anything larger than
// either falls back to a direct read or write rather than growing.
//
// Every point where the connection can block is bounded, and bounded
// lazily. The deadline is a field the engine updates per query and a
// syscall only where something is really about to block, so a burst
// answered out of the fill buffer arms nothing and the property the
// buffers exist for, one read and one write for the whole burst,
// survives the bound.

const (
	// tcpFillSize holds a burst of pipelined queries (~30 bytes each);
	// a frame too large for it is read straight into the job.
	tcpFillSize = 4 << 10
	// tcpDrainSize holds a burst of replies. A reply that does not fit
	// flushes first and, if it still does not fit, goes out on its own.
	tcpDrainSize = 8 << 10
	// tcpWriteWait bounds a write the connection makes on its own: an
	// oversized reply going out alone, the staged burst that reply
	// displaces, and the last flush on the way out. A client that never
	// reads fills the socket buffers, and every one of those writes is
	// made with a job slab in hand. It is measured from the write rather
	// than from the query's prefix because the handler in between is the
	// resolver, whose own budget is ten seconds: charging that latency to
	// the reply would drop answers that were merely slow to produce.
	tcpWriteWait = 2 * time.Second
)

// tcpStream is one connection's framing state: the fill buffer it reads
// frames out of, and the drain buffer its replies accumulate in.
type tcpStream struct {
	conn net.Conn

	fill  [tcpFillSize]byte
	start int // first unconsumed byte in fill
	end   int // one past the last valid byte in fill

	drain [tcpDrainSize]byte
	held  int // bytes staged in drain
	werr  error

	// deadline is the bound for whatever the connection does next; armed
	// is the bound it already carries. They are kept apart so a burst
	// stays free: the engine hands over a fresh deadline for every frame,
	// but a frame served out of the fill buffer blocks nowhere, so it
	// never pays for arming one.
	deadline time.Time
	armed    time.Time

	// wait bounds the one place a connection blocks on the server rather
	// than on its peer: waiting for a slab when the ring is empty. It is
	// built at most once per connection and reused, because saturation,
	// the only time it is needed, is the worst moment to be allocating.
	wait *time.Timer
}

func (s *tcpStream) reset(conn net.Conn) {
	s.conn = conn
	s.start, s.end = 0, 0
	s.held = 0
	s.werr = nil
	s.deadline, s.armed = time.Time{}, time.Time{}
	if s.wait == nil && conn != nil {
		// Built here, at connection setup, and never inside a query. A
		// connection's first contended acquire is a served query like any
		// other, and the envelope opens before its slab is taken, so a
		// timer created lazily on that path is an allocation inside it,
		// however few connections ever reach it. It is stopped rather
		// than armed; every wait Resets it.
		s.wait = time.NewTimer(time.Hour)
	}
	if s.wait != nil {
		s.wait.Stop()
	}
}

// waitFor arms the connection's wait timer for d and returns its channel.
// Reset after Stop is safe to reuse without draining: since Go 1.23 a
// timer's channel is unbuffered, so neither can deliver a stale firing
// from the previous wait.
func (s *tcpStream) waitFor(d time.Duration) <-chan time.Time {
	if s.wait == nil {
		// Only a stream that never saw reset(conn), a unit test driving
		// the layer directly. Connections always arrive with one.
		s.wait = time.NewTimer(d)
		return s.wait.C
	}
	s.wait.Stop()
	s.wait.Reset(d)
	return s.wait.C
}

// arm puts the current deadline on the connection. One SetDeadline and
// not two: reads and writes share the bound, and on a DoT connection it
// is also what covers the handshake, which runs inside the first read and
// writes as much as it reads.
func (s *tcpStream) arm() error {
	if s.armed.Equal(s.deadline) {
		return nil
	}
	if err := s.conn.SetDeadline(s.deadline); err != nil {
		return err
	}
	s.armed = s.deadline
	return nil
}

// beforeWrite bounds a write the connection makes with a job slab still
// in hand. Without it a client that stops reading parks the connection in
// the write, slab and all, for as long as it cares to keep the socket
// open.
func (s *tcpStream) beforeWrite() error {
	s.deadline = time.Now().Add(tcpWriteWait)
	return s.arm()
}

// buffered reports whether the fill buffer already holds bytes, the
// signal that another frame is in hand and the replies may keep
// accumulating.
// framePrefixBuffered reports whether a whole length prefix is already in
// hand, which is the question the loop actually has, and not the same as
// whether any bytes are buffered at all. A single buffered byte is half a
// prefix: reading the other half blocks on the client exactly as an empty
// buffer does.
func (s *tcpStream) framePrefixBuffered() bool {
	return s.end-s.start >= dnsclient.FramePrefixLen
}

// fillMore reads once into the fill buffer, compacting first. It is the
// only place a stream blocks on the client.
func (s *tcpStream) fillMore() error {
	if s.start > 0 {
		s.end = copy(s.fill[:], s.fill[s.start:s.end])
		s.start = 0
	}
	if s.end == len(s.fill) {
		// The caller only ever asks for more when it needs bytes it does
		// not have; a full buffer here would mean a frame larger than the
		// buffer, which readFrame handles without this path.
		return io.ErrShortBuffer
	}
	n, err := s.conn.Read(s.fill[s.end:])
	s.end += n
	if n > 0 {
		return nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	return err
}

// next returns the next n buffered bytes, reading more when needed. The
// returned slice points into the fill buffer and is valid until the next
// call.
func (s *tcpStream) next(n int) ([]byte, error) {
	for s.end-s.start < n {
		if err := s.fillMore(); err != nil {
			return nil, err
		}
	}
	b := s.fill[s.start : s.start+n]
	s.start += n
	return b, nil
}

// body fills dst with the announced frame payload. A payload the fill
// buffer cannot hold is read straight into dst, the buffer speeds up
// small frames, it never limits what the transport accepts.
func (s *tcpStream) body(dst []byte) error {
	if s.end-s.start < len(dst) {
		// The frame announced more than the read delivered, so this is
		// where the connection blocks for the rest of it. That wait is the
		// query's, not the session's: a client that announces a frame it
		// never sends is holding a slab, not sitting idle, and the bound
		// says how long that may last.
		//
		// The staged replies deliberately stay staged. Flushing here was
		// tried and cost two fifths of this path's throughput: a body that
		// spans two reads is ordinary for a client that streams, and each
		// split turned the burst's single write into another syscall. It
		// also protects nobody. The drain buffer holds this connection's
		// own replies, so a client that stalls mid-frame delays only
		// itself, unlike a stall between frames, where a correct client
		// is waiting for those very replies before it sends more, and the
		// two of us would wait for each other.
		if err := s.arm(); err != nil {
			return err
		}
	}
	if len(dst) <= len(s.fill) {
		b, err := s.next(len(dst))
		if err != nil {
			return err
		}
		copy(dst, b)
		return nil
	}
	held := copy(dst, s.fill[s.start:s.end])
	s.start += held
	if held < len(dst) {
		if _, err := io.ReadFull(s.conn, dst[held:]); err != nil {
			return err
		}
	}
	return nil
}

// stage adds one framed reply to the drain buffer, flushing first when it
// would not fit. A reply too large for the buffer is framed and written on
// its own. The first error is sticky: once a write fails the connection is
// finished, and the loop above notices at its next flush.
func (s *tcpStream) stage(payload []byte) error {
	if s.werr != nil {
		return s.werr
	}
	if len(payload) > dns.MaxMsgSize {
		return dnsclient.ErrFrameTooLarge
	}
	need := dnsclient.FramePrefixLen + len(payload)
	if need > len(s.drain) {
		if err := s.beforeWrite(); err != nil {
			return err
		}
		if err := s.flush(); err != nil {
			return err
		}
		_, err := dnsclient.WriteFrameFrom(s.conn, payload)
		if err != nil {
			s.werr = err
		}
		return err
	}
	if s.held+need > len(s.drain) {
		if err := s.beforeWrite(); err != nil {
			return err
		}
		if err := s.flush(); err != nil {
			return err
		}
	}
	binary.BigEndian.PutUint16(s.drain[s.held:], uint16(len(payload))) //nolint:gosec // bounded above
	s.held += dnsclient.FramePrefixLen
	s.held += copy(s.drain[s.held:], payload)
	return nil
}

// flush writes everything staged. It is called before the connection
// blocks for more input and once more on the way out.
func (s *tcpStream) flush() error {
	if s.werr != nil {
		return s.werr
	}
	if s.held == 0 {
		return nil
	}
	if err := s.arm(); err != nil {
		s.werr = err
		return err
	}
	_, err := s.conn.Write(s.drain[:s.held])
	s.held = 0
	if err != nil {
		s.werr = err
	}
	return err
}

// beforeRead prepares the connection for the next frame. While the fill
// buffer still holds one, that is all it does, the frames of a burst are
// already in hand, so neither the staged replies nor the deadline need
// touching. When the buffer is empty the connection is about to block:
// the replies go out first, so a waiting client is never held by the
// server's own idle timeout, and the deadline covers the wait.
//
// The bound goes on before the replies leave, not after: that write is
// the other place a client that never reads would park the connection,
// and the read below inherits the same bound at no extra cost.
func (s *tcpStream) beforeRead(d time.Duration) error {
	// A partial prefix is not a served frame waiting, it is a read about
	// to block, and blocking with replies still staged is a deadlock in
	// the making: the client waits for answers it has already earned
	// while the server waits for the byte that would release them.
	if s.framePrefixBuffered() {
		return nil
	}
	s.deadline = time.Now().Add(d)
	if err := s.arm(); err != nil {
		return err
	}
	return s.flush()
}
