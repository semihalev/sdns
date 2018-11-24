package edns

import (
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// EDNS type
type EDNS struct {
}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})
}

// New return edns
func New(cfg *config.Config) *EDNS {
	return &EDNS{}
}

// Name return middleware name
func (e *EDNS) Name() string { return name }

// DNSResponseWriter implement of ctx.ResponseWriter
type DNSResponseWriter struct {
	ctx.ResponseWriter
	opt    *dns.OPT
	size   int
	do     bool
	noedns bool
	noad   bool
}

// ServeDNS implements the Handle interface.
func (e *EDNS) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	noedns := req.IsEdns0() == nil

	opt, size, do := dnsutil.SetEdns0(req)
	if opt.Version() != 0 {
		opt.SetVersion(0)
		opt.SetExtendedRcode(dns.RcodeBadVers)

		w.WriteMsg(dnsutil.HandleFailed(req, dns.RcodeBadVers, do))

		dc.Abort()
		return
	}

	if w.Proto() == "tcp" {
		size = dns.MaxMsgSize
	}

	dc.DNSWriter = &DNSResponseWriter{ResponseWriter: w, opt: opt, size: size, do: do, noedns: noedns, noad: !req.AuthenticatedData}

	dc.NextDNS()

	dc.DNSWriter = w
}

// WriteMsg implements the ctx.ResponseWriter interface
func (w *DNSResponseWriter) WriteMsg(m *dns.Msg) error {
	if !w.do {
		m = dnsutil.ClearDNSSEC(m)
	}
	m = dnsutil.ClearOPT(m)

	if !w.noedns {
		w.opt.SetDo(w.do)
		m.Extra = append(m.Extra, w.opt)
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

const name = "edns"
