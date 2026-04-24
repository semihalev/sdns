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

// internalIP is the sentinel loopback address that marks a synthesised
// internal query (e.g. a recursion kicked off by the resolver itself
// rather than arriving from a real client). We compare against it by
// IP+port rather than formatting to "127.0.0.255:0" on every chain
// Reset — RemoteAddr().String() goes through net.JoinHostPort +
// net.IP.String and allocates ~32 bytes per query.
var internalIP = net.IPv4(127, 0, 0, 255)

func (w *responseWriter) Msg() *dns.Msg {
	return w.msg
}

func (w *responseWriter) Reset(rw dns.ResponseWriter) {
	w.ResponseWriter = rw
	w.size = -1
	w.msg = nil
	w.rcode = dns.RcodeSuccess
	w.proto = ""
	w.remoteip = nil
	w.internal = false

	switch a := rw.RemoteAddr().(type) {
	case *net.UDPAddr:
		w.proto = "udp"
		w.remoteip = a.IP
		w.internal = a.Port == 0 && a.IP.Equal(internalIP)
	case *net.TCPAddr:
		w.proto = "tcp"
		w.remoteip = a.IP
		w.internal = a.Port == 0 && a.IP.Equal(internalIP)
	}

	switch writer := rw.(type) {
	case *mock.Writer:
		w.proto = writer.Proto()
	case *doq.ResponseWriter:
		w.proto = "doq"
	}

	// Propagate an Internal() signal from any writer that exposes it.
	// Today that's the mock.Writer-with-sentinel path plus the
	// queryer.BufferWriter used by the internal sub-pipeline. The
	// sentinel comparison above stays as fallback for plugin compat;
	// this interface check is the supported channel for new code.
	if w.internal {
		return
	}
	if i, ok := rw.(interface{ Internal() bool }); ok {
		w.internal = i.Internal()
	}
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
