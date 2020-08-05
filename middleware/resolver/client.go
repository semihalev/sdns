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

// A Conn represents a connection to a DNS server.
type Conn struct {
	net.Conn        // a net.Conn holding the connection
	UDPSize  uint16 // minimum receive buffer for UDP messages
}

// Exchange performs a synchronous query
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

// ReadMsg reads a message from the connection co.
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

// Read implements the net.Conn read method.
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

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *dns.Msg) (err error) {
	size := uint16(m.Len()) + 1

	out := AcquireBuf(size)
	defer ReleaseBuf(out)

	out, err = m.PackBuffer(out)
	if err != nil {
		return err
	}
	_, err = co.Write(out)
	return err
}

// Write implements the net.Conn Write method.
func (co *Conn) Write(p []byte) (int, error) {
	if len(p) > dns.MaxMsgSize {
		return 0, errors.New("message too large")
	}

	if _, ok := co.Conn.(net.PacketConn); ok {
		return co.Conn.Write(p)
	}

	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(p)))

	n, err := (&net.Buffers{l, p}).WriteTo(co.Conn)
	return int(n), err
}

var bufferPool sync.Pool

// AcquireBuf returns an buf from pool
func AcquireBuf(size uint16) []byte {
	x := bufferPool.Get()
	if x == nil {
		return make([]byte, size)
	}
	buf := *(x.(*[]byte))
	if cap(buf) < int(size) {
		return make([]byte, size)
	}
	return buf[:size]
}

// ReleaseBuf returns buf to pool
func ReleaseBuf(buf []byte) {
	bufferPool.Put(&buf)
}
