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

// WireCapability is what the writer chain reports about serving bytes for
// the request in flight. It is gathered before any body is produced, so a
// request that cannot take the byte path never pays for it.
type WireCapability struct {
	// DO is the client's own DNSSEC-OK bit. It cannot be read from the
	// request at serve time: the edns layer sets DO on the request's OPT
	// so upstream validation happens regardless of what the client asked
	// for, and only the writer still remembers the original.
	DO bool
	// Reserve is how many bytes the chain will append below this point
	// (the per-client OPT).
	Reserve int
	// MaxSize caps the reply the transport accepts; 0 means unbounded.
	MaxSize int
}

// WireWriter is the optional byte-serving contract. A response written
// through WriteWire carries no OPT record; the edns layer appends the
// per-client OPT it would have attached on the Msg path.
//
// WireReady is the allocation-free preflight: it walks the whole chain and
// reports both whether every layer can shape bytes and the facts the caller
// needs to decide. Callers must consult it before building a body — a late
// refusal would mean paying for both paths.
//
// WriteWire keeps ErrWireFallback as a defensive backstop for conditions a
// preflight cannot foresee; it must still return before writing any byte.
type WireWriter interface {
	WireReady() (WireCapability, bool)
	WriteWire(body []byte, info WireInfo) error
}

// ClearWireAD clears the AD bit in a packed message header in place.
func ClearWireAD(body []byte) {
	wire.ClearAD(body)
}

// WireReady reports whether this transport is a true byte sink. DoQ needs
// its reply ID normalized to zero (RFC 9250 §4.2.1), a rewrite its raw
// Write does not perform, and the DoH assembly path unpacks whatever bytes
// it is handed only to pack them again — both are excluded until they can
// carry bytes natively.
func (w *responseWriter) WireReady() (WireCapability, bool) {
	switch w.proto {
	case "udp", "tcp":
		return WireCapability{}, true
	default:
		return WireCapability{}, false
	}
}

// Size reports the response's length on the wire. Observers ask for it
// instead of measuring a parsed message: on the byte path that measurement
// would force an unpack, and a message decoded from bytes reports an
// inflated uncompressed length because Unpack does not restore Compress.
func (w *responseWriter) Size() int {
	if w.wire != nil {
		return len(w.wire)
	}
	if w.msg != nil {
		return w.msg.Len()
	}
	return 0
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
