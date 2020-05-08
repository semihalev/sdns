package resolver

import (
	"context"
	"os"
	"time"

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
	resolver *Resolver
	cfg      *config.Config
}

type ctxKey string

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
		resolver: NewResolver(cfg),
		cfg:      cfg,
	}
}

// Name return middleware name
func (h *DNSHandler) Name() string { return name }

// ServeDNS implements the Handle interface.
func (h *DNSHandler) ServeDNS(ctx context.Context, dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	ctx = context.WithValue(ctx, ctxKey("query"), req.Question[0])
	msg := h.handle(ctx, w.Proto(), req)

	w.WriteMsg(msg)
}

func (h *DNSHandler) handle(ctx context.Context, proto string, req *dns.Msg) *dns.Msg {
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

	// check purge query
	if q.Qtype == dns.TypeNULL {
		if qname, qtype, ok := dnsutil.ParsePurgeQuestion(req); ok {
			if qtype == dns.TypeNS {
				h.purge(qname)
			}

			resp := dnsutil.HandleFailed(req, dns.RcodeSuccess, do)
			txt, _ := dns.NewRR(q.Name + ` 20 IN TXT "cache purged"`)

			resp.Extra = append(resp.Extra, txt)

			return resp
		}
	}

	if q.Name != rootzone && req.RecursionDesired == false {
		return dnsutil.HandleFailed(req, dns.RcodeServerFailure, do)
	}

	// we shouldn't send rd flag to aa servers
	req.RecursionDesired = false

	//TODO (semihalev): config setable after this
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
	defer cancel()

	depth := h.cfg.Maxdepth
	resp, err := h.resolver.Resolve(ctx, proto, req, h.resolver.rootservers, true, depth, 0, false, nil)
	if err != nil {
		log.Warn("Resolve query failed", "query", formatQuestion(q), "error", err.Error())

		resp = dnsutil.HandleFailed(req, dns.RcodeServerFailure, do)
	}

	if resp.Truncated && proto == "udp" {
		return resp
	} else if resp.Truncated && proto == "https" {
		return h.handle(ctx, "tcp", req)
	}

	resp = h.additionalAnswer(ctx, proto, req, resp)

	return resp
}

func (h *DNSHandler) additionalAnswer(ctx context.Context, proto string, req, msg *dns.Msg) *dns.Msg {
	if req.Question[0].Qtype == dns.TypeCNAME {
		return msg
	}

	cnameReq := new(dns.Msg)
	cnameReq.Extra = req.Extra
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
		respCname, err := dnsutil.ExchangeInternal(ctx, proto, cnameReq)
		if err == nil && (len(respCname.Answer) > 0 || len(respCname.Answer) > 0) {
			for _, rr := range respCname.Answer {
				if respCname.Question[0].Name == cnameReq.Question[0].Name {
					msg.Answer = append(msg.Answer, dns.Copy(rr))
				}
			}

			for _, rr := range respCname.Ns {
				if respCname.Question[0].Name == cnameReq.Question[0].Name {
					msg.Ns = append(msg.Ns, dns.Copy(rr))
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

	servers := h.resolver.rootservers
	ttl := uint32(5)
	name := rootzone

	if q.Name != rootzone {
		nsKey := cache.Hash(dns.Question{Name: q.Name, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, msg.CheckingDisabled)
		ns, err := h.resolver.ncache.Get(nsKey)
		if err != nil {
			nsKey = cache.Hash(dns.Question{Name: q.Name, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, !msg.CheckingDisabled)
			ns, err := h.resolver.ncache.Get(nsKey)
			if err == nil {
				servers = ns.Servers
				name = q.Name
			}
		} else {
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

func (h *DNSHandler) purge(qname string) {
	q := dns.Question{Name: qname, Qtype: dns.TypeNS, Qclass: dns.ClassINET}

	key := cache.Hash(q, false)
	h.resolver.ncache.Remove(key)

	key = cache.Hash(q, true)
	h.resolver.ncache.Remove(key)
}

const name = "resolver"
