package ctx

import (
	"errors"
	"net"

	"github.com/miekg/dns"
)

// ResponseWriter implement of dns.ResponseWriter
type ResponseWriter interface {
	dns.ResponseWriter
	Msg() *dns.Msg
	Rcode() int
	Written() bool
	Reset(dns.ResponseWriter)
	Proto() string
}

type responseWriter struct {
	dns.ResponseWriter
	msg   *dns.Msg
	size  int
	rcode int
	proto string
}

var _ ResponseWriter = &responseWriter{}
var errAlreadyWritten = errors.New("msg already written")

func (w *responseWriter) Msg() *dns.Msg {
	return w.msg
}

func (w *responseWriter) Reset(writer dns.ResponseWriter) {
	w.ResponseWriter = writer
	w.size = -1
	w.msg = nil
	w.rcode = dns.RcodeSuccess

	switch writer.LocalAddr().(type) {
	case (*net.TCPAddr):
		w.proto = "tcp"
	case (*net.UDPAddr):
		w.proto = "udp"
	}
}

func (w *responseWriter) Proto() string {
	return w.proto
}

func (w *responseWriter) Rcode() int {
	return w.rcode
}

func (w *responseWriter) Written() bool {
	return w.size != -1
}

func (w *responseWriter) Write(m []byte) (int, error) {
	if w.Written() {
		return 0, errAlreadyWritten
	}

	w.msg = new(dns.Msg)
	err := w.msg.Unpack(m)
	if err != nil {
		return 0, err
	}
	w.rcode = w.msg.Rcode

	n, err := w.ResponseWriter.Write(m)
	w.size = n
	return n, err
}

func (w *responseWriter) WriteMsg(m *dns.Msg) error {
	if w.Written() {
		return errAlreadyWritten
	}

	w.msg = m
	w.rcode = m.Rcode
	w.size = 0

	return w.ResponseWriter.WriteMsg(m)
}
