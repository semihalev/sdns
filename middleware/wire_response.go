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

// WireBodyLeaser is the pre-build lease contract: a caller that knows the
// response size asks the writer for the buffer the body will be built in,
// so the bytes are born where the transport wants them (the server's job
// slab on the strict path) instead of being allocated by the producer.
//
// BeginWire returns a zero-length slice with capacity size+reserve, or nil
// when the writer cannot lease (the caller falls back to building its own
// body for WriteWire). Exactly one of CommitWire or AbortWire must follow
// every successful BeginWire, before any other write on this writer.
// CommitWire has WriteWire's semantics — including the lazy post-write
// Msg() retention, which is why the lease belongs to the writer until the
// request finishes, never returning to any pool at commit time (the #558
// lesson). AbortWire releases the lease without a send; the caller may then
// still answer through the ordinary Msg path.
type WireBodyLeaser interface {
	BeginWire(size, reserve int) []byte
	CommitWire(body []byte, info WireInfo) error
	AbortWire()
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

// ResponseSizer is implemented by writers that can report a response's wire
// length without decoding it. It is deliberately separate from
// ResponseWriter: adding a method to that interface would break any plugin
// writer that implements it directly rather than by embedding.
type ResponseSizer interface {
	Size() int
}

// ResponseSize returns the response's length on the wire. Observers ask for
// it instead of measuring a parsed message: on the byte path that
// measurement would force an unpack, and a message decoded from bytes
// reports an inflated uncompressed length because Unpack does not restore
// Compress. A writer that cannot answer falls back to that measurement.
func ResponseSize(w ResponseWriter) int {
	if sizer, ok := w.(ResponseSizer); ok {
		return sizer.Size()
	}
	if msg := w.Msg(); msg != nil {
		return msg.Len()
	}
	return 0
}

// Size reports the bytes this response occupies on the wire: counted
// exactly whenever the response reached the transport as bytes, and
// computed from the message only when it did not.
func (w *responseWriter) Size() int {
	if len(w.wire) > 0 {
		return len(w.wire)
	}
	// WriteMsg marks itself written with a zero size; a raw write records
	// the real count, so a positive value is authoritative.
	if w.size > 0 {
		return w.size
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

	// Size comes from len(w.wire); the transport's count would include a
	// stream length prefix. A zero here only marks the response written.
	_, err := w.ResponseWriter.Write(body)
	w.size = 0
	return err
}

// BeginWire on the base response writer leases a fresh buffer. The server's
// strict-path writer overrides the backing with its job slab; here the lease
// semantics are what matters: the body is built in a buffer the writer
// handed out, and the writer keeps it after CommitWire for the lazy
// post-write Msg() contract.
func (w *responseWriter) BeginWire(size, reserve int) []byte {
	if w.Written() {
		return nil
	}
	return make([]byte, 0, size+reserve)
}

// CommitWire sends a body obtained from BeginWire; it has WriteWire's exact
// semantics, retention included.
func (w *responseWriter) CommitWire(body []byte, info WireInfo) error {
	return w.WriteWire(body, info)
}

// AbortWire releases a BeginWire lease without a send. The base writer's
// lease is garbage-collected storage, so there is nothing to return.
func (w *responseWriter) AbortWire() {}

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
