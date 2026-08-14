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
// what the profile showed the TCP path spending its time on — the write
// side alone outweighed everything the middleware chain does.
//
// So a connection reads through a fill buffer and writes through a drain
// buffer: one read syscall hands over as many frames as the client sent,
// and their replies leave in one write. The flush point is the moment the
// connection is about to block for more input — nothing is ever held back
// waiting for a client that has stopped talking, so a single-query
// connection still costs exactly one read and one write, and no reply
// waits on a timer.
//
// Sizes are per connection and bounded: the fill buffer holds a burst of
// queries, the drain buffer a burst of replies, and anything larger than
// either falls back to a direct read or write rather than growing.

const (
	// tcpFillSize holds a burst of pipelined queries (~30 bytes each);
	// a frame too large for it is read straight into the job.
	tcpFillSize = 4 << 10
	// tcpDrainSize holds a burst of replies. A reply that does not fit
	// flushes first and, if it still does not fit, goes out on its own.
	tcpDrainSize = 8 << 10
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
}

func (s *tcpStream) reset(conn net.Conn) {
	s.conn = conn
	s.start, s.end = 0, 0
	s.held = 0
	s.werr = nil
}

// buffered reports whether the fill buffer already holds bytes — the
// signal that another frame is in hand and the replies may keep
// accumulating.
func (s *tcpStream) buffered() bool { return s.start < s.end }

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
// buffer cannot hold is read straight into dst — the buffer speeds up
// small frames, it never limits what the transport accepts.
func (s *tcpStream) body(dst []byte) error {
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
	_, err := s.conn.Write(s.drain[:s.held])
	s.held = 0
	if err != nil {
		s.werr = err
	}
	return err
}

// beforeRead prepares the connection for the next frame. While the fill
// buffer still holds one, that is all it does — the frames of a burst are
// already in hand, so neither the staged replies nor the read deadline
// need touching. When the buffer is empty the connection is about to
// block: the replies go out first, so a waiting client is never held by
// the server's own idle timeout, and the deadline is armed for the wait.
func (s *tcpStream) beforeRead(d time.Duration) error {
	if s.buffered() {
		return nil
	}
	if err := s.flush(); err != nil {
		return err
	}
	return s.conn.SetReadDeadline(time.Now().Add(d))
}
