package middleware

import (
	"errors"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
)

// ErrWireFallback tells a wire-serving caller to retake the ordinary
// *dns.Msg path. It is a routing signal, not a failure: an implementation
// MUST return it before any bytes reach the transport, so the caller can
// re-serve the same response without a double write.
var ErrWireFallback = errors.New("middleware: wire path unavailable, use WriteMsg")

// WireInfo carries the response facts observers and shaping layers need
// when a response travels as packed bytes. It replaces the field reads
// they would otherwise perform on a *dns.Msg.
type WireInfo struct {
	// Rcode of the packed response.
	Rcode int
	// AuthenticatedData mirrors the AD bit currently set in the body.
	AuthenticatedData bool
	// HasDNSSEC reports whether the body carries RRSIG/NSEC/NSEC3
	// records — the fact the edns layer needs for its DO=0 decision.
	HasDNSSEC bool
}

// WireWriter is the optional byte-serving contract. A response written
// through WriteWire carries no OPT record; the edns layer appends the
// per-client OPT it would have attached on the Msg path. Implementations
// either shape-and-forward, or return ErrWireFallback untouched.
//
// Every wrapper between the caller and the transport must implement
// WireWriter for the write to proceed; the first non-implementing layer
// turns the attempt into a fallback.
type WireWriter interface {
	WriteWire(body []byte, info WireInfo) error
}

// ClearWireAD clears the AD bit in a packed message header in place.
func ClearWireAD(body []byte) {
	wire.ClearAD(body)
}

// WriteWire on the base response writer sends the bytes straight to the
// transport. Observability fields are taken from info instead of an
// unpack; Msg() reads after a wire write decode lazily from the retained
// bytes, preserving the post-write contract for callers that need it.
func (w *responseWriter) WriteWire(body []byte, info WireInfo) error {
	if w.Written() {
		return errAlreadyWritten
	}

	w.msg = nil
	w.wire = body
	w.rcode = info.Rcode

	n, err := w.ResponseWriter.Write(body)
	w.size = n
	return err
}

// Msg returns the written message. After a wire-path write the packed
// bytes are decoded on first use — post-write readers (DoH assembly,
// tests) are cold paths and must not tax the hot serve.
func (w *responseWriter) Msg() *dns.Msg {
	if w.msg == nil && w.wire != nil {
		msg := new(dns.Msg)
		if err := msg.Unpack(w.wire); err == nil {
			w.msg = msg
		}
	}
	return w.msg
}
