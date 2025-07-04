package edns

import (
	"context"
	"encoding/hex"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
)

// EDNS type.
type EDNS struct {
	cookiesecret string
	nsidstr      string
}

// New return edns.
func New(cfg *config.Config) *EDNS {
	return &EDNS{cookiesecret: cfg.CookieSecret, nsidstr: cfg.NSID}
}

// (*EDNS).Name name return middleware name.
func (e *EDNS) Name() string { return name }

// ResponseWriter implement of ctx.ResponseWriter.
type ResponseWriter struct {
	middleware.ResponseWriter
	*EDNS

	opt    *dns.OPT
	size   int
	do     bool
	cookie string
	nsid   bool
	noedns bool
	noad   bool
}

// (*EDNS).ServeDNS serveDNS implements the Handle interface.
func (e *EDNS) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if req.Opcode > 0 {
		_ = util.NotSupported(w, req)

		ch.Cancel()
		return
	}

	noedns := req.IsEdns0() == nil

	opt, size, cookie, nsid, do := util.SetEdns0(req)
	if opt.Version() != 0 {
		opt.SetVersion(0)

		ch.CancelWithRcode(dns.RcodeBadVers, do)

		return
	}

	switch w.Proto() {
	case "tcp", "doq", "doh":
		size = dns.MaxMsgSize
	}

	if noedns {
		size = dns.MinMsgSize
	}

	ch.Writer = &ResponseWriter{
		ResponseWriter: w,
		EDNS:           e,

		opt:    opt,
		size:   size,
		do:     do,
		cookie: cookie,
		noedns: noedns,
		nsid:   nsid,
		noad:   !req.AuthenticatedData && !do,
	}

	ch.Next(ctx)

	ch.Writer = w
}

// (*ResponseWriter).WriteMsg writeMsg implements the ctx.ResponseWriter interface.
func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	m.Compress = true

	if !w.do {
		m = util.ClearDNSSEC(m)
	}

	if !w.noedns {
		// Get or create OPT record
		opt := m.IsEdns0()
		if opt == nil {
			// No OPT in response, use ours
			opt = w.opt
			m.Extra = append(m.Extra, opt)
		}

		// Set common OPT parameters
		opt.SetDo(w.do)
		opt.SetUDPSize(w.opt.UDPSize())

		// Add server options if not already present
		w.setCookie()
		w.setNSID()

		// Only add our options if they're not already in the response OPT
		if opt == w.opt {
			// This is our OPT, options already added by setCookie/setNSID
		} else {
			// This is response OPT, need to merge our options
			opt.Option = append(opt.Option, w.opt.Option...)
		}
	} else {
		// EDNS disabled, remove all OPT records
		m = util.ClearOPT(m)
	}

	if w.noad {
		m.AuthenticatedData = false
	}

	if w.Proto() == "udp" && m.Len() > w.size {
		m.Truncated = true
		m.Answer = []dns.RR{}
		m.Ns = []dns.RR{}
		m.AuthenticatedData = false
	}

	return w.ResponseWriter.WriteMsg(m)
}

func (w *ResponseWriter) setCookie() {
	if w.cookie == "" {
		return
	}

	w.opt.Option = append(w.opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: util.GenerateServerCookie(w.cookiesecret, w.RemoteIP().String(), w.cookie),
	})
}

func (w *ResponseWriter) setNSID() {
	if w.nsidstr == "" || !w.nsid {
		return
	}

	w.opt.Option = append(w.opt.Option, &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
		Nsid: hex.EncodeToString([]byte(w.nsidstr)),
	})
}

const name = "edns"
