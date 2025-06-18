package middleware

import (
	"errors"
	"net"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/server/doq"
)

// ResponseWriter implement of dns.ResponseWriter.
type ResponseWriter interface {
	dns.ResponseWriter
	Msg() *dns.Msg
	Rcode() int
	Written() bool
	Reset(dns.ResponseWriter)
	Proto() string
	RemoteIP() net.IP
	Internal() bool
}

type responseWriter struct {
	dns.ResponseWriter
	msg      *dns.Msg
	size     int
	rcode    int
	proto    string
	remoteip net.IP
	internal bool
}

var _ ResponseWriter = &responseWriter{}
var errAlreadyWritten = errors.New("msg already written")

func (w *responseWriter) Msg() *dns.Msg {
	return w.msg
}

func (w *responseWriter) Reset(rw dns.ResponseWriter) {
	w.ResponseWriter = rw
	w.size = -1
	w.msg = nil
	w.rcode = dns.RcodeSuccess

	switch rw.LocalAddr().(type) {
	case (*net.TCPAddr):
		w.proto = "tcp"
		w.remoteip = w.RemoteAddr().(*net.TCPAddr).IP
	case (*net.UDPAddr):
		w.proto = "udp"
		w.remoteip = w.RemoteAddr().(*net.UDPAddr).IP
	}

	switch writer := rw.(type) {
	case (*mock.Writer):
		w.proto = writer.Proto()
	case (*doq.ResponseWriter):
		w.proto = "doq"
	}

	w.internal = w.RemoteAddr().String() == "127.0.0.255:0"
}

func (w *responseWriter) RemoteIP() net.IP {
	return w.remoteip
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

// (*responseWriter).Internal internal func.
func (w *responseWriter) Internal() bool { return w.internal }
