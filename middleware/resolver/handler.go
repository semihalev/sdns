package resolver

import (
	"os"

	"github.com/semihalev/sdns/middleware"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
)

// DNSHandler type
type DNSHandler struct {
	r   *Resolver
	cfg *config.Config
}

var debugns bool

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})

	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

// New returns a new Handler
func New(cfg *config.Config) *DNSHandler {
	return &DNSHandler{
		r:   NewResolver(cfg),
		cfg: cfg,
	}
}

// Name return middleware name
func (h *DNSHandler) Name() string { return name }

// ServeDNS implements the Handle interface.
func (h *DNSHandler) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	msg := h.handle(w.Proto(), req)

	w.WriteMsg(msg)
}

func (h *DNSHandler) handle(Net string, req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	do := false
	opt := req.IsEdns0()
	if opt != nil {
		do = opt.Do()
	}

	if q.Qtype == dns.TypeANY {
		return dnsutil.HandleFailed(req, dns.RcodeNotImplemented, do)
	}

	// debug ns stats
	if debugns && q.Qtype == dns.TypeHINFO {
		return h.nsStats(req)
	}

	if q.Name != rootzone && req.RecursionDesired == false {
		return dnsutil.HandleFailed(req, dns.RcodeServerFailure, do)
	}

	log.Debug("Lookup", "net", Net, "query", formatQuestion(q), "do", do, "cd", req.CheckingDisabled)

	depth := h.cfg.Maxdepth
	resp, err := h.r.Resolve(Net, req, h.r.rootservers, true, depth, 0, false, nil)
	if err != nil {
		log.Warn("Resolve query failed", "query", formatQuestion(q), "error", err.Error())

		resp = dnsutil.HandleFailed(req, dns.RcodeServerFailure, do)
	}

	if resp.Truncated && Net == "udp" {
		return resp
	} else if resp.Truncated && Net == "https" {
		return h.handle("tcp", req)
	}

	resp = h.additionalAnswer(Net, req, resp)

	return resp
}

func (h *DNSHandler) additionalAnswer(Net string, req, msg *dns.Msg) *dns.Msg {
	if req.Question[0].Qtype != dns.TypeA &&
		req.Question[0].Qtype != dns.TypeAAAA {
		return msg
	}

	cnameReq := new(dns.Msg)
	cnameReq.Extra = req.Extra
	cnameReq.RecursionDesired = true
	cnameReq.CheckingDisabled = req.CheckingDisabled

	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == req.Question[0].Qtype {
			return msg
		}

		if answer.Header().Rrtype == dns.TypeCNAME {
			cr := answer.(*dns.CNAME)
			if cr.Target == req.Question[0].Name {
				return dnsutil.HandleFailed(req, dns.RcodeServerFailure, false)
			}
			cnameReq.SetQuestion(cr.Target, req.Question[0].Qtype)
		}
	}

	if len(cnameReq.Question) > 0 {
		respCname, err := dnsutil.ExchangeInternal(Net, cnameReq)
		if err == nil && len(respCname.Answer) > 0 {
			for _, r := range respCname.Answer {
				if respCname.Question[0].Name == cnameReq.Question[0].Name {
					msg.Answer = append(msg.Answer, dns.Copy(r))
				}
			}
		}
	}

	return msg
}

func (h *DNSHandler) nsStats(req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	msg := new(dns.Msg)
	msg.SetReply(req)

	msg.Authoritative = false
	msg.RecursionAvailable = true

	servers := h.r.rootservers
	ttl := uint32(3600)
	name := rootzone

	if q.Name != rootzone {
		nsKey := cache.Hash(dns.Question{Name: q.Name, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, msg.CheckingDisabled)
		ns, err := h.r.Ncache.Get(nsKey)
		if err == nil {
			servers = ns.Servers
			name = q.Name
		}
	}

	rrHeader := dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeHINFO,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}

	servers.RLock()
	for _, server := range servers.List {
		hinfo := &dns.HINFO{Hdr: rrHeader, Cpu: "ns", Os: server.String()}
		msg.Ns = append(msg.Ns, hinfo)
	}
	servers.RUnlock()

	return msg
}

const name = "resolver"
