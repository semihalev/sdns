package doq

import (
	"encoding/binary"
	"net"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ResponseWriter implements dns.ResponseWriter for DNS-over-QUIC.
type ResponseWriter struct {
	dns.ResponseWriter

	Conn   *quic.Conn
	Stream *quic.Stream
}

func (w *ResponseWriter) LocalAddr() net.Addr {
	return w.Conn.LocalAddr()
}

func (w *ResponseWriter) RemoteAddr() net.Addr {
	return w.Conn.RemoteAddr()
}

func (w *ResponseWriter) Close() error {
	return w.Stream.Close()
}

// (*ResponseWriter).Hijack hijack implements dns.ResponseWriter.Hijack.
func (w *ResponseWriter) Hijack() {
	// No-op for QUIC as connection management is handled differently
}

func (w *ResponseWriter) Write(m []byte) (int, error) {
	return w.Stream.Write(addPrefixLen(m))
}

func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	// DoQ spec requires ID to be 0
	m.Id = 0

	packed, err := m.Pack()
	if err != nil {
		return err
	}

	_, err = w.Write(packed)
	return err
}

func addPrefixLen(msg []byte) []byte {
	// Pre-allocate exact size needed
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	return buf
}
