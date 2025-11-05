package resolver

// Originally this Client from github.com/miekg/dns
// Adapted for resolver package usage by Semih Alev.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	headerSize = 12
)

// Conn A Conn represents a connection to a DNS server.
type Conn struct {
	net.Conn        // a net.Conn holding the connection
	UDPSize  uint16 // minimum receive buffer for UDP messages
}

// (*Conn).Exchange exchange performs a synchronous query.
func (co *Conn) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {

	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}

	if opt == nil && co.UDPSize < dns.MinMsgSize {
		co.UDPSize = dns.MinMsgSize
	}

	t := time.Now()

	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}

	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = dns.ErrId
	}

	rtt = time.Since(t)

	return r, rtt, err
}

// (*Conn).ReadMsg readMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction signature
// is verified. This method always tries to return the message, however if an
// error is returned there are no guarantees that the returned message is a
// valid representation of the packet read.
func (co *Conn) ReadMsg() (*dns.Msg, error) {
	var (
		p   []byte
		n   int
		err error
	)

	if _, ok := co.Conn.(net.PacketConn); ok {
		p = AcquireBuf(co.UDPSize)
		n, err = co.Read(p)
	} else {
		var length uint16
		if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
			return nil, err
		}

		p = AcquireBuf(length)
		n, err = io.ReadFull(co.Conn, p)
	}

	if err != nil {
		return nil, err
	} else if n < headerSize {
		return nil, dns.ErrShortRead
	}

	defer ReleaseBuf(p)

	m := new(dns.Msg)
	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}
	return m, err
}

// (*Conn).Read read implements the net.Conn read method.
func (co *Conn) Read(p []byte) (n int, err error) {
	if co.Conn == nil {
		return 0, dns.ErrConnEmpty
	}

	if _, ok := co.Conn.(net.PacketConn); ok {
		// UDP connection
		return co.Conn.Read(p)
	}

	var length uint16
	if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(co.Conn, p[:length])
}

// (*Conn).WriteMsg writeMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *dns.Msg) (err error) {
	size := uint16(m.Len()) + 1 //nolint:gosec // G115 - DNS message size is bounded

	out := AcquireBuf(size)
	defer ReleaseBuf(out)

	out, err = m.PackBuffer(out)
	if err != nil {
		return err
	}
	_, err = co.Write(out)
	return err
}

// (*Conn).Write write implements the net.Conn Write method.
func (co *Conn) Write(p []byte) (int, error) {
	if len(p) > dns.MaxMsgSize {
		return 0, errors.New("message too large")
	}

	if _, ok := co.Conn.(net.PacketConn); ok {
		return co.Conn.Write(p)
	}

	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(p))) //nolint:gosec // G115 - DNS message size is bounded

	n, err := (&net.Buffers{l, p}).WriteTo(co.Conn)
	return int(n), err
}

// Size-bucketed buffer pools for efficient memory usage.
var bufferPools = [4]sync.Pool{
	{New: func() any { b := make([]byte, 512); return &b }},   // 0-512 bytes (most DNS over UDP)
	{New: func() any { b := make([]byte, 1232); return &b }},  // 513-1232 bytes (EDNS0 UDP)
	{New: func() any { b := make([]byte, 4096); return &b }},  // 1233-4096 bytes (typical TCP)
	{New: func() any { b := make([]byte, 65535); return &b }}, // 4097-65535 bytes (max DNS)
}

// AcquireBuf returns a buffer from the appropriate pool.
func AcquireBuf(size uint16) []byte {
	var poolIdx int
	switch {
	case size <= 512:
		poolIdx = 0
	case size <= 1232:
		poolIdx = 1
	case size <= 4096:
		poolIdx = 2
	default:
		poolIdx = 3
	}

	x := bufferPools[poolIdx].Get()
	buf := *(x.(*[]byte))
	return buf[:size]
}

// ReleaseBuf returns buf to the appropriate pool.
func ReleaseBuf(buf []byte) {
	c := cap(buf)
	var poolIdx int
	switch {
	case c <= 512:
		poolIdx = 0
	case c <= 1232:
		poolIdx = 1
	case c <= 4096:
		poolIdx = 2
	case c <= 65535:
		poolIdx = 3
	default:
		// Buffer too large, let GC handle it
		return
	}

	bufferPools[poolIdx].Put(&buf)
}
