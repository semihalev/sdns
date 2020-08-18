package resolver

import (
	"context"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// DNSHandler type
type DNSHandler struct {
	resolver *Resolver
	cfg      *config.Config
}

type ctxKey string

var debugns bool

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})

	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

// New returns a new Handler
func New(cfg *config.Config) *DNSHandler {
	if cfg.Maxdepth == 0 {
		cfg.Maxdepth = 30
	}

	return &DNSHandler{
		resolver: NewResolver(cfg),
		cfg:      cfg,
	}
}

// Name return middleware name
func (h *DNSHandler) Name() string { return name }

// ServeDNS implements the Handle interface.
func (h *DNSHandler) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if v := ctx.Value(ctxKey("reqid")); v == nil {
		ctx = context.WithValue(ctx, ctxKey("reqid"), req.Id)
	}
	msg := h.handle(ctx, req)

	_ = w.WriteMsg(msg)
}

func (h *DNSHandler) handle(ctx context.Context, req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	do := false
	opt := req.IsEdns0()
	if opt != nil {
		do = opt.Do()
	}

	if q.Qtype == dns.TypeANY {
		return dnsutil.SetRcode(req, dns.RcodeNotImplemented, do)
	}

	// debug ns stats
	if debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO {
		return h.nsStats(req)
	}

	// check purge query
	if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL {
		if qname, qtype, ok := dnsutil.ParsePurgeQuestion(req); ok {
			if qtype == dns.TypeNS {
				h.purge(qname)
			}

			resp := dnsutil.SetRcode(req, dns.RcodeSuccess, do)
			txt, _ := dns.NewRR(q.Name + ` 20 IN TXT "cache purged"`)

			resp.Extra = append(resp.Extra, txt)

			return resp
		}
	}

	if q.Name != rootzone && !req.RecursionDesired {
		return dnsutil.SetRcode(req, dns.RcodeServerFailure, do)
	}

	// we shouldn't send rd and ad flag to aa servers
	req.RecursionDesired = false
	req.AuthenticatedData = false

	//TODO (semihalev): config setable after this
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
	defer cancel()

	depth := h.cfg.Maxdepth
	resp, err := h.resolver.Resolve(ctx, req, h.resolver.rootservers, true, depth, 0, false, nil)
	if err != nil {
		log.Info("Resolve query failed", "query", formatQuestion(q), "error", err.Error())

		return dnsutil.SetRcode(req, dns.RcodeServerFailure, do)
	}

	if resp.Rcode == dns.RcodeRefused {
		log.Info("Resolve query refused", "query", formatQuestion(q))

		return dnsutil.SetRcode(req, dns.RcodeServerFailure, do)
	}

	resp = h.additionalAnswer(ctx, req, resp)

	return resp
}

func (h *DNSHandler) additionalAnswer(ctx context.Context, req, msg *dns.Msg) *dns.Msg {
	if req.Question[0].Qtype == dns.TypeCNAME ||
		req.Question[0].Qtype == dns.TypeDS {
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
				return dnsutil.SetRcode(req, dns.RcodeServerFailure, false)
			}
			cnameReq.SetQuestion(cr.Target, req.Question[0].Qtype)
		}
	}

	if len(cnameReq.Question) > 0 {
		respCname, err := dnsutil.ExchangeInternal(ctx, cnameReq)
		if err == nil && (len(respCname.Answer) > 0 || len(respCname.Ns) > 0) {
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
	ttl := uint32(0)
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

	var serversList []*authcache.AuthServer

	servers.RLock()
	serversList = append(serversList, servers.List...)
	servers.RUnlock()

	authcache.Sort(serversList, 1)

	rrHeader := dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeHINFO,
		Class:  dns.ClassCHAOS,
		Ttl:    ttl,
	}

	for _, server := range serversList {
		hinfo := &dns.HINFO{Hdr: rrHeader, Cpu: "Host", Os: server.String()}
		msg.Ns = append(msg.Ns, hinfo)
	}

	return msg
}

func (h *DNSHandler) purge(qname string) {
	q := dns.Question{Name: qname, Qtype: dns.TypeNS}

	key := cache.Hash(q, false)
	h.resolver.ncache.Remove(key)

	key = cache.Hash(q, true)
	h.resolver.ncache.Remove(key)
}

const name = "resolver"
