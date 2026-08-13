package middleware

import (
	"errors"
	"net"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/internal/wire"
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
	wire     []byte
	size     int
	rcode    int
	proto    string
	remoteip net.IP
	internal bool

	// directPack records that the transport beneath this writer is an
	// SDNS-owned UDP, TCP or DoT sink whose Write sends raw wire bytes
	// unchanged. It is a declaration, never an inference: the server's
	// owned-listener ingress is the only caller of AllowDirectPack, so a
	// plugin writer that merely looks like a datagram transport — same
	// RemoteAddr type, same proto string — never receives packed bytes it
	// might re-decode or reshape. Reset clears it, so a pooled chain
	// cannot carry the capability to a writer that did not declare it.
	directPack bool
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

func (w *responseWriter) Reset(rw dns.ResponseWriter) {
	w.ResponseWriter = rw
	w.size = -1
	w.msg = nil
	w.wire = nil
	w.rcode = dns.RcodeSuccess
	w.proto = ""
	w.remoteip = nil
	w.internal = false
	w.directPack = false

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
	// Record the DNS payload's own length, not the transport's return
	// value: stream transports prepend a two-byte length prefix and count
	// it, which would overstate every TCP and DoQ response. Measuring the
	// decoded message instead would overstate compressed ones, because
	// Unpack does not restore the Compress flag. The caller owns m, so only
	// its length is kept.
	w.size = len(m)
	return n, err
}

func (w *responseWriter) WriteMsg(m *dns.Msg) error {
	if w.Written() {
		return errAlreadyWritten
	}

	// The direct path: pack in pooled storage and hand the transport raw
	// bytes, skipping the library's per-message dictionary and buffer. Only
	// on a declared SDNS-owned sink — see directPack — and never for an
	// internal sub-query, whose consumer wants the message, not bytes.
	//
	// The bookkeeping runs inside the consumer, before the transport write:
	// the size marks the response written even if the transport then
	// errors, so nothing retries a wire that may be partially out. Msg()
	// keeps returning the caller's message, pointer identity included —
	// request-local provenance is keyed on it. A message TryPack cannot
	// handle falls through untouched to the library path below, which is
	// byte-identical by TryPack's contract.
	if w.directPack && !w.internal {
		handled, err := wire.TryPack(m, func(body []byte) error {
			w.msg = m
			w.rcode = m.Rcode
			w.size = len(body)
			_, werr := w.ResponseWriter.Write(body)
			return werr
		})
		if handled {
			return err
		}
	}

	w.msg = m
	w.rcode = m.Rcode
	w.size = 0

	return w.ResponseWriter.WriteMsg(m)
}

// (*responseWriter).Internal internal func.
func (w *responseWriter) Internal() bool { return w.internal }
