package main

import (
	"net"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
)

const (
	// DefaultMsgSize EDNS0 message size
	DefaultMsgSize = 1536
)

// DNSHandler type
type DNSHandler struct {
	r *Resolver
}

var debugns bool

func init() {
	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

// NewHandler returns a new DNSHandler
func NewHandler() *DNSHandler {
	return &DNSHandler{
		r: NewResolver(),
	}
}

// TCP begins a tcp query
func (h *DNSHandler) TCP(w dns.ResponseWriter, req *dns.Msg) {
	go h.handle("tcp", w, req)
}

// UDP begins a udp query
func (h *DNSHandler) UDP(w dns.ResponseWriter, req *dns.Msg) {
	go h.handle("udp", w, req)
}

func (h *DNSHandler) handle(proto string, w dns.ResponseWriter, req *dns.Msg) {
	client, _, _ := net.SplitHostPort(h.remoteAddr(w))
	allowed, _ := AccessList.Contains(net.ParseIP(client))

	if !allowed {
		log.Debug("Client denied to make new query", "client", client, "net", proto)
		return
	}

	msg := h.query(proto, req)

	h.writeMsg(w, msg)

	h.r.Qmetrics.With(
		prometheus.Labels{
			"qtype": dns.TypeToString[req.Question[0].Qtype],
			"rcode": dns.RcodeToString[msg.Rcode],
		}).Inc()
}

func (h *DNSHandler) query(proto string, req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	resolverProto := proto
	if proto == "https" {
		resolverProto = "udp"
	}

	opt, dsReq := h.setEdns0(req)
	if opt.Version() != 0 {
		opt.SetVersion(0)
		opt.SetExtendedRcode(dns.RcodeBadVers)

		return h.handleFailed(req, dns.RcodeBadVers, dsReq)
	}

	if q.Qtype == dns.TypeANY {
		return h.handleFailed(req, dns.RcodeNotImplemented, dsReq)
	}

	// debug ns stats
	if debugns && q.Qtype == dns.TypeHINFO {
		return h.nsStats(req)
	}

	if q.Name != rootzone && req.RecursionDesired == false {
		return h.handleFailed(req, dns.RcodeServerFailure, dsReq)
	}

	log.Debug("Lookup", "query", formatQuestion(q), "dsreq", dsReq)

	key := cache.Hash(q, req.CheckingDisabled)

	h.r.Lqueue.Wait(key)

	mesg, rl, err := h.r.Qcache.Get(key, req)
	if err == nil {
		log.Debug("Cache hit", "key", key, "query", formatQuestion(q))

		if Config.RateLimit > 0 && rl.Limit() {
			return h.handleFailed(req, dns.RcodeRefused, dsReq)
		}

		msg := mesg.Copy()
		msg.Id = req.Id
		msg = h.additionalAnswer(resolverProto, req, msg)
		if !dsReq {
			msg = clearDNSSEC(msg)
		}
		msg = clearOPT(msg)
		opt.SetDo(dsReq)
		msg.Extra = append(msg.Extra, opt)

		return msg
	}

	err = h.r.Ecache.Get(key)
	if err == nil {
		log.Debug("Error cache hit", "key", key, "query", formatQuestion(q))

		return h.handleFailed(req, dns.RcodeServerFailure, dsReq)
	}

	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		if BlockList.Exists(q.Name) {
			return h.blockEntry(req, key, dsReq)
		}
	}

	h.r.Lqueue.Add(key)
	defer h.r.Lqueue.Done(key)

	depth := Config.Maxdepth
	mesg, err = h.r.Resolve(resolverProto, req, rootservers, true, depth, 0, false, nil)
	if err != nil {
		log.Warn("Resolve query failed", "query", formatQuestion(q), "error", err.Error())

		h.r.Ecache.Set(key)

		return h.handleFailed(req, dns.RcodeServerFailure, dsReq)
	}

	if mesg.Truncated && proto == "udp" {
		return mesg
	} else if mesg.Truncated && proto == "https" {
		opt.SetDo(dsReq)

		h.r.Lqueue.Done(key)
		return h.query("tcp", req)
	}

	if mesg.Rcode == dns.RcodeSuccess &&
		len(mesg.Answer) == 0 && len(mesg.Ns) == 0 {

		rr, _ := dns.NewRR(req.Question[0].Name + " " + strconv.Itoa(int(Config.Expire)) +
			" IN HINFO comment \"no answer found on authoritative server\"")
		mesg.Ns = append(mesg.Ns, rr)
	}

	//ignore auths TTL for caching, replace with default expire
	if mesg.Rcode == dns.RcodeNameError {
		for _, rr := range mesg.Ns {
			rr.Header().Ttl = Config.Expire
		}
	}

	if mesg.Rcode != dns.RcodeSuccess &&
		len(mesg.Answer) == 0 && len(mesg.Ns) == 0 {

		h.r.Ecache.Set(key)

		return h.handleFailed(req, mesg.Rcode, dsReq)
	}

	msg := mesg.Copy()
	msg = h.additionalAnswer(resolverProto, req, msg)
	if !dsReq {
		msg = clearDNSSEC(msg)
	}
	msg = clearOPT(msg)
	opt.SetDo(dsReq)
	msg.Extra = append(msg.Extra, opt)

	h.r.Qcache.Set(key, mesg)

	log.Debug("Set msg into cache", "query", formatQuestion(q))
	return msg
}

func (h *DNSHandler) additionalAnswer(proto string, req, msg *dns.Msg) *dns.Msg {
	//check cname response
	answerFound := false

	cnameReq := new(dns.Msg)
	cnameReq.SetEdns0(DefaultMsgSize, true)
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
		respCname, _, err := h.r.Qcache.Get(key, cnameReq)
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
			depth := Config.Maxdepth
			respCname, err := h.r.Resolve(proto, cnameReq, rootservers, true, depth, 0, false, nil)
			if err == nil && len(respCname.Answer) > 0 {
				for _, r := range respCname.Answer {
					msg.Answer = append(msg.Answer, dns.Copy(r))

					if r.Header().Rrtype == dns.TypeCNAME {
						cr := r.(*dns.CNAME)
						cnameReq.Question[0].Name = cr.Target
						child = true
					}
				}

				h.r.Qcache.Set(key, respCname)
			}
		}

		cnameDepth--

		if child && cnameDepth > 0 {
			goto lookup
		}
	}

	return msg
}

func (h *DNSHandler) handleFailed(msg *dns.Msg, rcode int, dsf bool) *dns.Msg {
	m := new(dns.Msg)
	m.Extra = msg.Extra
	m.SetRcode(msg, rcode)
	m.RecursionAvailable = true

	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(dsf)
	}

	return m
}

func (h *DNSHandler) setEdns0(req *dns.Msg) (*dns.OPT, bool) {
	dsReq := false
	opt := req.IsEdns0()

	if opt != nil {
		opt.SetUDPSize(DefaultMsgSize)
		if opt.Version() != 0 {
			return opt, false
		}

		ops := opt.Option

		opt.Option = []dns.EDNS0{}

		for _, option := range ops {
			if option.Option() == dns.EDNS0SUBNET {
				opt.Option = append(opt.Option, option)
			}
		}

		dsReq = opt.Do()

		opt.Header().Ttl = 0
		opt.SetDo()
	} else {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(DefaultMsgSize)
		opt.SetDo()

		req.Extra = append(req.Extra, opt)
	}

	return opt, dsReq
}

func (h *DNSHandler) nsStats(req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	msg := new(dns.Msg)
	msg.SetReply(req)

	msg.Authoritative = false
	msg.RecursionAvailable = true

	if q.Name == rootzone {
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeHINFO,
			Class:  dns.ClassINET,
			Ttl:    0,
		}

		rootservers.RLock()
		for _, server := range rootservers.List {
			hinfo := &dns.HINFO{Hdr: rrHeader, Cpu: "ns", Os: server.String()}
			msg.Ns = append(msg.Ns, hinfo)
		}
		rootservers.RUnlock()
	} else {
		nsKey := cache.Hash(dns.Question{Name: q.Name, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, msg.CheckingDisabled)
		ns, err := h.r.Ncache.Get(nsKey)
		if err == nil {
			rrHeader := dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeHINFO,
				Class:  dns.ClassINET,
				Ttl:    ns.TTL,
			}

			ns.Servers.RLock()
			for _, server := range ns.Servers.List {
				hinfo := &dns.HINFO{Hdr: rrHeader, Cpu: "ns", Os: server.String()}
				msg.Ns = append(msg.Ns, hinfo)
			}
			ns.Servers.RUnlock()
		}
	}

	return msg
}

func (h *DNSHandler) blockEntry(req *dns.Msg, key uint64, dsf bool) *dns.Msg {
	q := req.Question[0]

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Extra = req.Extra

	if opt := msg.IsEdns0(); opt != nil {
		opt.SetDo(dsf)
	}

	nullroute := net.ParseIP(Config.Nullroute)
	nullroutev6 := net.ParseIP(Config.Nullroutev6)

	switch q.Qtype {
	case dns.TypeA:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    Config.Expire,
		}
		a := &dns.A{Hdr: rrHeader, A: nullroute}
		msg.Answer = append(msg.Answer, a)
	case dns.TypeAAAA:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    Config.Expire,
		}
		a := &dns.AAAA{Hdr: rrHeader, AAAA: nullroutev6}
		msg.Answer = append(msg.Answer, a)
	}

	msg.AuthenticatedData = true
	msg.Authoritative = false
	msg.RecursionAvailable = true

	h.r.Qcache.Set(key, msg)

	return msg
}

func (h *DNSHandler) remoteAddr(w dns.ResponseWriter) string {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Recovered in remoteAddr", "recover", r)
		}
	}()

	return w.RemoteAddr().String()
}

func (h *DNSHandler) writeMsg(w dns.ResponseWriter, msg *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Recovered in WriteReplyMsg", "recover", r)
		}
	}()

	if w == nil {
		return
	}

	err := w.WriteMsg(msg)
	if err != nil {
		log.Error("Message writing failed", "error", err.Error())
	}
}
