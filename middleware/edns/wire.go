package edns

import (
	"encoding/binary"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// TCPKeepaliveTimeout is the idle timeout this server advertises to
// stream clients that sent the RFC 7828 edns-tcp-keepalive option. It
// must state what the engine actually enforces, the server package's
// per-connection idle wait, and a test over there pins the two
// together, since neither package can import the other's constant.
const TCPKeepaliveTimeout = 8 * time.Second

// tcpKeepaliveUnits is the same timeout in the option's wire unit of
// 100 milliseconds.
const tcpKeepaliveUnits = uint16(TCPKeepaliveTimeout / (100 * time.Millisecond))

// Size forwards the response's wire length from the writer beneath. The
// wrapper embeds the narrow ResponseWriter interface, which deliberately
// does not carry Size, so without this an observer above this layer, the
// access log is one, would fall back to decoding the response just to
// measure it, which on the byte path is the whole cost this path avoids.
func (w *ResponseWriter) Size() int {
	return middleware.ResponseSize(w.ResponseWriter)
}

// ResponseBudget reports, for a writer above this layer with optional
// records to leave out rather than overflow into truncation, the largest
// response the client takes and how much of it the OPT this layer appends
// will use. limit is 0 over a stream, which bounds nothing here. ok is false
// when the OPT's length cannot be known, and the caller should then add
// nothing optional to a bounded response.
func (w *ResponseWriter) ResponseBudget() (limit, reserve int, ok bool) {
	reserve, ok = w.wireOPTLen()
	if w.Proto() == "udp" {
		limit = w.size
	}
	return limit, reserve, ok
}

// WireReady reports what the byte path may produce for this client. It
// allocates nothing: the OPT's contribution is arithmetic, so a request the
// caller ends up refusing has cost only field reads. The record itself is
// built once, later, in WriteWire.
//
// It answers with the client's own DO bit, which the request no longer
// carries, SetEdns0 turns DO on so upstream validation happens regardless
// of what the client asked for, and only the writer remembers the original.
func (w *ResponseWriter) WireReady() (middleware.WireCapability, bool) {
	next, ok := w.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.WireCapability{}, false
	}
	capability, ok := next.WireReady()
	if !ok {
		return middleware.WireCapability{}, false
	}

	reserve, ok := w.wireOPTLen()
	if !ok {
		return middleware.WireCapability{}, false
	}
	capability.DO = w.do
	capability.Reserve += reserve
	// A UDP client's advertised size bounds the reply; exceeding it means
	// truncation, which reshapes the message and belongs to the Msg path.
	if w.Proto() == "udp" && (capability.MaxSize == 0 || w.size < capability.MaxSize) {
		capability.MaxSize = w.size
	}
	return capability, true
}

// wireOPTLen is the exact encoded length of the OPT this layer appends.
// On the Msg path SetEdns0 has already stripped every client option except
// a possibly forwarded ECS, which a reply never carries; any other
// leftover option is one this layer has no encoder for, so it declines
// rather than guess. On the wire branch there is no mutated request OPT at
// all (opt stays nil): the reply carries exactly what this layer appends,
// and the cookie/NSID flags below are the complete inventory.
func (w *ResponseWriter) wireOPTLen() (int, bool) {
	if w.noedns {
		return 0, true
	}
	length := wire.OPTFixedLen
	if w.opt != nil {
		for _, option := range w.opt.Option {
			if _, isECS := option.(*dns.EDNS0_SUBNET); isECS {
				continue
			}
			return 0, false
		}
	}
	if w.cookie != nil {
		if cookie, ok := w.serverCookie(); ok {
			length += wire.OPTOptionHdrLen + len(cookie)
		}
	}
	if w.nsidstr != "" && w.nsid {
		length += wire.OPTOptionHdrLen + len(w.nsidstr)
	}
	if w.keepalive {
		length += wire.OPTOptionHdrLen + 2
	}
	if w.pad {
		// The most a reply can need, known exactly only once it is built.
		length += wire.OPTOptionHdrLen + paddingBlock - 1
	}
	return length, true
}

// paddingZeros is the payload every padding option is cut from.
var paddingZeros [paddingBlock]byte

// BeginWire delegates the pre-build lease down the writer chain; edns has
// no buffer of its own, its OPT lands in the reserve the lease carries.
func (w *ResponseWriter) BeginWire(size, reserve int) []byte {
	if leaser, ok := w.ResponseWriter.(middleware.WireBodyLeaser); ok {
		return leaser.BeginWire(size, reserve)
	}
	return nil
}

// CommitWire sends a leased body through this layer's WriteWire, so the
// per-client OPT is appended exactly as on the unleased wire path.
func (w *ResponseWriter) CommitWire(body []byte, info middleware.WireInfo) error {
	return w.WriteWire(body, info)
}

// AbortWire releases the lease without a send.
func (w *ResponseWriter) AbortWire() {
	if leaser, ok := w.ResponseWriter.(middleware.WireBodyLeaser); ok {
		leaser.AbortWire()
	}
}

// appendWireOPT encodes the per-client OPT, the same record WriteMsg
// attaches, directly into the reply's reserved tail. Nothing is
// materialized: no OPT record, no option objects, and no text form for
// options the library holds as hex only to decode again while packing.
// An Extended DNS Error carried by info (a cached entry's provenance)
// rides the same record, sized into the lease by the cache.
func (w *ResponseWriter) appendWireOPT(body []byte, info middleware.WireInfo) ([]byte, bool) {
	body, rdlenOff := wire.AppendOPTHeader(body, w.respUDPSize, w.do)

	if w.cookie != nil {
		if cookie, ok := w.serverCookie(); ok {
			body = wire.AppendOption(body, dns.EDNS0COOKIE, cookie)
		}
	}
	if w.nsidstr != "" && w.nsid {
		body = wire.AppendOptionString(body, dns.EDNS0NSID, w.nsidstr)
	}
	if w.keepalive {
		var timeout [2]byte
		binary.BigEndian.PutUint16(timeout[:], tcpKeepaliveUnits)
		body = wire.AppendOption(body, dns.EDNS0TCPKEEPALIVE, timeout[:])
	}
	if info.HasEDE {
		body = wire.AppendOptionEDE(body, info.EDECode, info.EDEText)
	}
	if w.pad {
		if n, ok := paddingLen(len(body)); ok {
			body = wire.AppendOption(body, dns.EDNS0PADDING, paddingZeros[:n])
		}
	}

	return wire.FinishOPT(body, rdlenOff), true
}

// WriteWire appends the per-client OPT and forwards the bytes. The guards
// here are backstops: WireReady already settled DO, size, and chain
// support, so reaching a fallback means an assumption broke rather than an
// ordinary refusal.
func (w *ResponseWriter) WriteWire(body []byte, info middleware.WireInfo) error {
	next, ok := w.ResponseWriter.(middleware.WireWriter)
	if !ok || len(body) < wire.HeaderLen {
		return middleware.ErrWireFallback
	}
	if !w.do && info.HasDNSSEC {
		return middleware.ErrWireFallback
	}
	if w.noad && info.AuthenticatedData {
		wire.ClearAD(body)
		info.AuthenticatedData = false
	}

	if w.noedns {
		if w.Proto() == "udp" && len(body) > w.size {
			return middleware.ErrWireFallback
		}
		return next.WriteWire(body, info)
	}

	// The stored body may carry real additional records; the OPT joins
	// them rather than replacing the count.
	header, ok := wire.ParseHeader(body)
	if !ok {
		return middleware.ErrWireFallback
	}

	// The caller sized the body with WireReady's reserve, so this appends
	// into the existing capacity.
	withOPT, ok := w.appendWireOPT(body, info)
	if !ok {
		return middleware.ErrWireFallback
	}

	if w.Proto() == "udp" && len(withOPT) > w.size {
		return middleware.ErrWireFallback
	}
	wire.SetARCount(withOPT, header.ARCount+1)

	return next.WriteWire(withOPT, info)
}
