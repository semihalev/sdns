package resolver

import (
	"net"
	"net/http"
	"os"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/doh"
	mcache "github.com/semihalev/sdns/middleware/cache"
)

// DNSHandler type
type DNSHandler struct {
	r   *Resolver
	cfg *config.Config
}

var debugns bool

func init() {
	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

// New returns a new Handler
func New(cfg *config.Config, cache *mcache.Cache) *DNSHandler {
	return &DNSHandler{
		r:   NewResolver(cfg, cache),
		cfg: cfg,
	}
}

// Name return middleware name
func (h *DNSHandler) Name() string {
	return "resolver"
}

// ServeDNS implements the Handle interface.
func (h *DNSHandler) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	var Net string
	switch w.LocalAddr().(type) {
	case (*net.TCPAddr):
		Net = "tcp"
	case (*net.UDPAddr):
		Net = "udp"
	}

	msg := h.handle(Net, req)

	w.WriteMsg(msg)
}

func (h *DNSHandler) ServeHTTP(dc *ctx.Context) {
	w, r := dc.HTTPWriter, dc.HTTPRequest

	var f func(http.ResponseWriter, *http.Request) bool
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		f = doh.HandleJSON(h.handle)
	} else {
		f = doh.HandleWireFormat(h.handle)
	}

	f(w, r)
}

func (h *DNSHandler) handle(Net string, req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	resolverNet := Net
	if Net == "https" {
		resolverNet = "udp"
	}

	opt, do := dnsutil.SetEdns0(req)
	if opt.Version() != 0 {
		opt.SetVersion(0)
		opt.SetExtendedRcode(dns.RcodeBadVers)

		return dnsutil.HandleFailed(req, dns.RcodeBadVers, do)
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

	log.Debug("Lookup", "query", formatQuestion(q), "ds", do)

	key := cache.Hash(q, req.CheckingDisabled)

	h.r.cache.LookupQueue.Wait(key)

	mesg, rl, err := h.r.cache.GetP(key, req)
	if err == nil {
		if h.cfg.RateLimit > 0 && rl.Limit() {
			return dnsutil.HandleFailed(req, dns.RcodeRefused, do)
		}

		mesg.SetReply(req)
		mesg = h.additionalAnswer(resolverNet, req, mesg)
		if !do {
			mesg = dnsutil.ClearDNSSEC(mesg)
		}
		mesg = dnsutil.ClearOPT(mesg)
		opt.SetDo(do)
		mesg.Extra = append(mesg.Extra, opt)

		return mesg
	}

	h.r.cache.LookupQueue.Add(key)
	defer h.r.cache.LookupQueue.Done(key)

	depth := h.cfg.Maxdepth
	mesg, err = h.r.Resolve(resolverNet, req, h.r.rootservers, true, depth, 0, false, nil)
	if err != nil {
		log.Warn("Resolve query failed", "query", formatQuestion(q), "error", err.Error())

		mesg = dnsutil.HandleFailed(req, dns.RcodeServerFailure, do)
	}

	if mesg.Truncated && Net == "udp" {
		return mesg
	} else if mesg.Truncated && Net == "https" {
		opt.SetDo(do)

		h.r.cache.LookupQueue.Done(key)
		return h.handle("tcp", req)
	}

	h.r.cache.Set(key, mesg)

	m := mesg.Copy()
	m = h.additionalAnswer(resolverNet, req, m)
	if !do {
		m = dnsutil.ClearDNSSEC(m)
	}
	m = dnsutil.ClearOPT(m)
	opt.SetDo(do)
	m.Extra = append(m.Extra, opt)

	return m
}

func (h *DNSHandler) additionalAnswer(Net string, req, msg *dns.Msg) *dns.Msg {
	//check cname response
	answerFound := false

	cnameReq := new(dns.Msg)
	cnameReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	cnameReq.RecursionDesired = true
	cnameReq.CheckingDisabled = req.CheckingDisabled

	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == req.Question[0].Qtype &&
			(req.Question[0].Qtype == dns.TypeA || req.Question[0].Qtype == dns.TypeAAAA) {
			answerFound = true
		}

		if answer.Header().Rrtype == dns.TypeCNAME {
			cr := answer.(*dns.CNAME)
			cnameReq.SetQuestion(cr.Target, req.Question[0].Qtype)
		}
	}

	cnameDepth := 5

	if !answerFound && len(cnameReq.Question) > 0 {
	lookup:
		q := cnameReq.Question[0]
		child := false

		key := cache.Hash(q, cnameReq.CheckingDisabled)
		respCname, _, err := h.r.cache.GetP(key, cnameReq)
		if err == nil {
			for _, r := range respCname.Answer {
				msg.Answer = append(msg.Answer, dns.Copy(r))

				if r.Header().Rrtype == dns.TypeCNAME {
					cr := r.(*dns.CNAME)
					cnameReq.Question[0].Name = cr.Target
					child = true
				}
			}
		} else {
			depth := h.cfg.Maxdepth
			respCname, err := h.r.Resolve(Net, cnameReq, h.r.rootservers, true, depth, 0, false, nil)
			if err == nil && len(respCname.Answer) > 0 {
				for _, r := range respCname.Answer {
					msg.Answer = append(msg.Answer, dns.Copy(r))

					if r.Header().Rrtype == dns.TypeCNAME {
						cr := r.(*dns.CNAME)
						cnameReq.Question[0].Name = cr.Target
						child = true
					}
				}

				h.r.cache.Set(key, respCname)
			}
		}

		cnameDepth--

		if child && cnameDepth > 0 {
			goto lookup
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
