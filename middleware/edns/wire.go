package edns

import (
	"encoding/binary"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// WriteWire shapes a packed, OPT-less response body exactly as WriteMsg
// shapes a *dns.Msg: DNSSEC records are withheld from DO=0 clients (by
// falling back — stripping records is Msg-path work), the AD policy is
// applied, and the per-client OPT (DO, UDP size, cookie, NSID; never ECS)
// is appended. Anything the byte path cannot reproduce faithfully returns
// ErrWireFallback before any state or bytes change, so the Msg path can
// re-serve the identical response.
func (w *ResponseWriter) WriteWire(body []byte, info middleware.WireInfo) error {
	next, ok := w.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.ErrWireFallback
	}
	if len(body) < 12 {
		return middleware.ErrWireFallback
	}

	// DO=0 responses must not carry DNSSEC records; removing them reshapes
	// the body, which is the Msg path's job.
	if !w.do && info.HasDNSSEC {
		return middleware.ErrWireFallback
	}

	if w.noedns {
		// The stored body already carries no OPT — a legacy client's
		// response is complete as-is.
		if w.Proto() == "udp" && len(body) > w.size {
			return middleware.ErrWireFallback
		}
		if w.noad && info.AuthenticatedData {
			middleware.ClearWireAD(body)
			info.AuthenticatedData = false
		}
		return next.WriteWire(body, info)
	}

	// Compose the same per-client OPT the Msg path would attach, without
	// touching writer state: a later fallback must not leave a duplicate
	// cookie or NSID behind. ECS options are excluded from the reply
	// exactly as WriteMsg's strip does.
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

	buf := body
	if need := len(body) + dns.Len(opt) + 4; cap(buf) < need {
		buf = append(make([]byte, 0, need), body...)
	}
	buf = buf[:cap(buf)]
	off, err := dns.PackRR(opt, buf, len(body), nil, false)
	if err != nil {
		return middleware.ErrWireFallback
	}
	withOPT := buf[:off]

	// RFC 1035 truncation for UDP clients whose advertised size the reply
	// exceeds: the Msg path empties the sections and sets TC — reshaping,
	// so the byte path steps aside.
	if w.Proto() == "udp" && len(withOPT) > w.size {
		return middleware.ErrWireFallback
	}

	if w.noad && info.AuthenticatedData {
		middleware.ClearWireAD(withOPT)
		info.AuthenticatedData = false
	}
	binary.BigEndian.PutUint16(withOPT[10:12], 1) // ARCOUNT: the appended OPT

	return next.WriteWire(withOPT, info)
}
