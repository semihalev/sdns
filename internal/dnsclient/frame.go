package dnsclient

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/miekg/dns"
)

// This file is the caller-owned-buffer framing seam: the stream framing
// Conn.ReadMsg/WriteMsg apply, detached from message decoding and from the
// package's buffer pool, so the server's strict path can frame in and out
// of job-owned storage without an allocation.
//
// The framing layer's contract (inherited from Conn, preserved exactly):
//   - It never sets or clears deadlines; the caller owns the conn's
//     deadline, and cancellation interrupts rely on that.
//   - A zero-length frame is accepted here; rejecting sub-header frames is
//     the message layer's job.
//   - A frame longer than the destination returns io.ErrShortBuffer after
//     the prefix was consumed: the stream is desynchronized by design and
//     the caller must discard the connection.

// ErrFrameTooLarge refuses to write a frame the 2-byte length prefix
// cannot describe.
var ErrFrameTooLarge = errors.New("dnsclient: frame exceeds maximum message size")

// FramePrefixLen is the stream frame header size.
const FramePrefixLen = 2

// ReadFrameInto reads one length-prefixed frame into dst and returns the
// payload length. Partial reads are completed. The prefix is staged in
// dst's first bytes and overwritten by the payload, which keeps the read
// allocation-free, a stack prefix array would escape through the reader
// interface. dst therefore needs capacity for at least the prefix.
func ReadFrameInto(conn net.Conn, dst []byte) (int, error) {
	if len(dst) < FramePrefixLen {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(conn, dst[:FramePrefixLen]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(dst[:FramePrefixLen]))
	if length > len(dst) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(conn, dst[:length])
}

// WriteFrameFrom writes p as one length-prefixed frame in a single gathered
// write. The returned count includes the prefix bytes. Callers who own
// prefix headroom in their buffer use WriteFramePrefixed instead, which
// needs no gather and no allocation.
func WriteFrameFrom(conn net.Conn, p []byte) (int, error) {
	if len(p) > dns.MaxMsgSize {
		return 0, ErrFrameTooLarge
	}
	var l [FramePrefixLen]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(p))) //nolint:gosec // bounded above
	buffers := net.Buffers{l[:], p}
	n, err := buffers.WriteTo(conn)
	return int(n), err
}

// WriteFramePrefixed writes buf's payload as one frame using buf's own
// prefix headroom: buf[0:2] is writable scratch and the payload occupies
// buf[2 : 2+payloadLen]. One conn.Write, no gather, no allocation, the
// strict-path TX buffer is laid out with this headroom for exactly this
// call. The returned count includes the prefix bytes.
func WriteFramePrefixed(conn net.Conn, buf []byte, payloadLen int) (int, error) {
	if payloadLen > dns.MaxMsgSize {
		return 0, ErrFrameTooLarge
	}
	if payloadLen < 0 || len(buf) < FramePrefixLen+payloadLen {
		return 0, io.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(buf[:FramePrefixLen], uint16(payloadLen)) //nolint:gosec // bounded above
	return conn.Write(buf[:FramePrefixLen+payloadLen])
}
