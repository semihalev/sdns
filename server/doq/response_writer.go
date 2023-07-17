package doq

import (
	"encoding/binary"
	"net"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type ResponseWriter struct {
	dns.ResponseWriter

	Conn   quic.Connection
	Stream quic.Stream
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

func (w *ResponseWriter) Write(m []byte) (int, error) {
	return w.Stream.Write(addPrefixLen(m))
}

func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	m.Id = 0

	packed, err := m.Pack()
	if err != nil {
		_ = w.Conn.CloseWithError(0x1, err.Error())
		return err
	}

	_, err = w.Stream.Write(addPrefixLen(packed))
	if err != nil {
		return err
	}

	return nil
}

func addPrefixLen(msg []byte) (buf []byte) {
	buf = make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)

	return buf
}
