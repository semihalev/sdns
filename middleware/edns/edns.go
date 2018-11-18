package edns

import (
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
)

// EDNS type
type EDNS struct {
}

// New return edns
func New(cfg *config.Config) *EDNS {
	return &EDNS{}
}

// Name return middleware name
func (e *EDNS) Name() string {
	return "edns"
}

// DNSResponseWriter implement of ctx.ResponseWriter
type DNSResponseWriter struct {
	ctx.ResponseWriter
	do  bool
	opt *dns.OPT
}

// ServeDNS implements the Handle interface.
func (e *EDNS) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	opt, do := dnsutil.SetEdns0(req)
	if opt.Version() != 0 {
		opt.SetVersion(0)
		opt.SetExtendedRcode(dns.RcodeBadVers)

		w.WriteMsg(dnsutil.HandleFailed(req, dns.RcodeBadVers, do))

		dc.Abort()
		return
	}

	dc.DNSWriter = &DNSResponseWriter{ResponseWriter: w, do: do, opt: opt}

	dc.NextDNS()

	dc.DNSWriter = w
}

func (e *EDNS) ServeHTTP(dc *ctx.Context) {
	dc.NextHTTP()
}

// WriteMsg implements the ctx.ResponseWriter interface
func (w *DNSResponseWriter) WriteMsg(m *dns.Msg) error {
	if !w.do {
		m = dnsutil.ClearDNSSEC(m)
	}
	m = dnsutil.ClearOPT(m)
	w.opt.SetDo(w.do)
	m.Extra = append(m.Extra, w.opt)

	return w.ResponseWriter.WriteMsg(m)
}
