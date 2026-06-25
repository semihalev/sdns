// Package dnsclient owns SDNS's upstream DNS transport: wire framing,
// buffer pooling, dialing, deadlines and exchange policy (ID match,
// question-section guard, UDP->TCP truncation fallback). It is written
// clean-room and depends on github.com/miekg/dns only as the message
// codec (dns.Msg / Pack / Unpack), not as a transport.
package dnsclient

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const headerSize = 12

// ErrQuestion is returned by (*Conn).Exchange when the response's
// question section does not match the outstanding request. Accepting a
// mismatched question lets a malicious upstream plant a cache entry
// under an unrelated name (issue #469).
var ErrQuestion = errors.New("dns: response question did not match request")

// Conn represents a connection to a DNS server. It wraps a net.Conn
// (either a connected UDP socket or a TCP/TLS stream) and tracks the
// negotiated UDP receive size.
type Conn struct {
	net.Conn        // underlying connection
	UDPSize  uint16 // minimum receive buffer for UDP messages
}

// Exchange performs a synchronous query over co: it writes m, reads the
// response, and validates the transaction ID and question section. The
// caller is responsible for dialing co and setting any deadline before
// calling Exchange.
func (co *Conn) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	opt := m.IsEdns0()
	// If EDNS0 advertises a receive size, honour it for the UDP buffer.
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

	if _, ok := co.Conn.(net.PacketConn); ok {
		// UDP: a connected socket can still surface a stray or late
		// datagram — a reply to an earlier query that already timed out,
		// or a packet spoofed from the peer address. Skip mismatched IDs
		// and keep reading until the matching response or the read
		// deadline, matching miekg/dns.Client so a single stray packet
		// can't fail a healthy upstream. The caller's read deadline bounds
		// the loop.
		for {
			r, err = co.ReadMsg()
			if err != nil || r.Id == m.Id {
				break
			}
		}
	} else {
		// TCP/TLS is a stream with a single in-flight response, so a
		// mismatched ID is a genuine protocol error, not a stray packet.
		r, err = co.ReadMsg()
		if err == nil && r.Id != m.Id {
			err = dns.ErrId
		}
	}
	if err == nil && len(m.Question) > 0 && !QuestionMatches(m.Question[0], r.Question) {
		err = ErrQuestion
	}

	rtt = time.Since(t)

	return r, rtt, err
}

// QuestionMatches reports whether the response's question section
// answers the outstanding request question. DNS names are compared
// case-insensitively because they are not case-sensitive on the wire.
func QuestionMatches(req dns.Question, resp []dns.Question) bool {
	if len(resp) != 1 {
		return false
	}
	r := resp[0]
	return r.Qtype == req.Qtype && r.Qclass == req.Qclass && strings.EqualFold(r.Name, req.Name)
}

// ReadMsg reads a single DNS message from co. The buffer is always
// returned to the pool, even on a timed-out UDP read or a truncated
// TCP read, so failed upstream reads never leak the buffer. On success
// only the bytes actually read are unpacked — feeding Unpack the
// trailing capacity of a pooled UDP buffer would let stale bytes from a
// previous use bleed into the parsed message.
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
		length, err = readUint16(co.Conn)
		if err != nil {
			return nil, err
		}
		p = AcquireBuf(length)
		n, err = io.ReadFull(co.Conn, p)
	}

	if err != nil {
		ReleaseBuf(p)
		return nil, err
	} else if n < headerSize {
		ReleaseBuf(p)
		return nil, dns.ErrShortRead
	}

	m := new(dns.Msg)
	if err := m.Unpack(p[:n]); err != nil {
		ReleaseBuf(p)
		// Still hand the message back so a caller that only checks err
		// can ignore it; a caller that wants the partial result has it.
		return m, err
	}
	ReleaseBuf(p)
	return m, nil
}

// Read implements net.Conn. For a UDP connection it reads a single
// datagram. For a stream connection it reads the 2-byte length prefix
// (RFC 1035 §4.2.2) and then exactly that many bytes into p.
func (co *Conn) Read(p []byte) (n int, err error) {
	if co.Conn == nil {
		return 0, dns.ErrConnEmpty
	}

	if _, ok := co.Conn.(net.PacketConn); ok {
		return co.Conn.Read(p)
	}

	length, err := readUint16(co.Conn)
	if err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(co.Conn, p[:length])
}

// WriteMsg packs m into a pooled buffer and writes it to co.
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

// Write implements net.Conn. For UDP it writes p as a single datagram.
// For a stream connection it prefixes p with its 2-byte length.
func (co *Conn) Write(p []byte) (int, error) {
	if len(p) > dns.MaxMsgSize {
		return 0, errors.New("message too large")
	}

	if _, ok := co.Conn.(net.PacketConn); ok {
		return co.Conn.Write(p)
	}

	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(p))) //nolint:gosec // G115 - DNS message size is bounded

	buffers := net.Buffers{l[:], p}
	n, err := buffers.WriteTo(co.Conn)
	return int(n), err
}

func readUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
