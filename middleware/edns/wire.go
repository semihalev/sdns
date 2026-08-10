package edns

import (
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// WireReady reports what the byte path may produce for this client and
// reserves room for the OPT this layer appends. It answers with the
// client's own DO bit — the request's OPT no longer carries it, because
// SetEdns0 turns DO on for upstream validation regardless of what the
// client asked for.
//
// The OPT is composed here, into the pooled record, so the reservation is
// exact and WriteWire adds no further work.
func (w *ResponseWriter) WireReady() (middleware.WireCapability, bool) {
	next, ok := w.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.WireCapability{}, false
	}
	capability, ok := next.WireReady()
	if !ok {
		return middleware.WireCapability{}, false
	}

	capability.DO = w.do
	if !w.noedns {
		capability.Reserve += dns.Len(w.buildWireOPT())
	}
	// A UDP client's advertised size bounds the reply; exceeding it means
	// truncation, which reshapes the message and belongs to the Msg path.
	if w.Proto() == "udp" && (capability.MaxSize == 0 || w.size < capability.MaxSize) {
		capability.MaxSize = w.size
	}
	return capability, true
}

// buildWireOPT composes the per-client OPT into the pooled record: the
// same one WriteMsg would attach (DO, UDP size, cookie, NSID), minus every
// ECS option. Writer state is untouched, so a fallback after this point
// cannot leave a duplicated option behind.
func (w *ResponseWriter) buildWireOPT() *dns.OPT {
	opt := &w.wireOPT
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Hdr.Ttl = 0
	opt.Option = opt.Option[:0]
	opt.SetUDPSize(w.opt.UDPSize())
	opt.SetDo(w.do)
	for _, option := range w.opt.Option {
		if _, isECS := option.(*dns.EDNS0_SUBNET); isECS {
			continue
		}
		opt.Option = append(opt.Option, option)
	}
	if option, ok := w.cookieOption(); ok {
		opt.Option = append(opt.Option, option)
	}
	if option, ok := w.nsidOption(); ok {
		opt.Option = append(opt.Option, option)
	}
	return opt
}

// WriteWire appends the per-client OPT composed during the preflight and
// forwards the bytes. The guards here are backstops: WireReady already
// established DO, size, and chain support, so a fallback at this point
// means an assumption broke rather than an ordinary refusal.
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

	opt := &w.wireOPT
	buf := body
	if need := len(body) + dns.Len(opt); cap(buf) < need {
		buf = append(make([]byte, 0, need), body...)
	}
	buf = buf[:cap(buf)]
	off, err := dns.PackRR(opt, buf, len(body), nil, false)
	if err != nil {
		return middleware.ErrWireFallback
	}
	withOPT := buf[:off]

	if w.Proto() == "udp" && len(withOPT) > w.size {
		return middleware.ErrWireFallback
	}
	wire.SetARCount(withOPT, 1)

	return next.WriteWire(withOPT, info)
}
