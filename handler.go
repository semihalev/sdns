package main

import (
	"net"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Question type
type Question struct {
	Qname  string `json:"name"`
	Qtype  string `json:"type"`
	Qclass string `json:"class"`
}

// String formats a question
func (q *Question) String() string {
	return q.Qname + " " + q.Qclass + " " + q.Qtype
}

// DNSHandler type
type DNSHandler struct {
	resolver *Resolver
	cache    Cache
}

// NewHandler returns a new DNSHandler
func NewHandler() *DNSHandler {
	var (
		clientConfig *dns.ClientConfig
		resolver     *Resolver
		cache        Cache
	)

	resolver = &Resolver{clientConfig}

	cache = NewMemoryCache(Config.Maxcount)

	return &DNSHandler{resolver, cache}
}

// TCP begins a tcp query
func (h *DNSHandler) TCP(w dns.ResponseWriter, req *dns.Msg) {
	go h.do("tcp", w, req)
}

// UDP begins a udp query
func (h *DNSHandler) UDP(w dns.ResponseWriter, req *dns.Msg) {
	go h.do("udp", w, req)
}

func (h *DNSHandler) do(proto string, w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	Q := Question{unFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}

	log.Debug("Lookup", "query", Q.String())

	key := keyGen(Q)

	mesg, err := h.cache.Get(key)
	if err == nil {
		log.Debug("Cache hit", "query", Q.String())

		// we need this copy against concurrent modification of Id
		msg := *mesg
		msg.Id = req.Id
		h.writeReplyMsg(w, &msg)
		return
	}

	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		if blockCache.Exists(Q.Qname) {
			m := new(dns.Msg)
			m.SetReply(req)

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
				m.Answer = append(m.Answer, a)
			case dns.TypeAAAA:
				rrHeader := dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    Config.Expire,
				}
				a := &dns.AAAA{Hdr: rrHeader, AAAA: nullroutev6}
				m.Answer = append(m.Answer, a)
			}

			h.writeReplyMsg(w, m)

			log.Debug("Found in blocklist", "name", Q.Qname)

			err := h.cache.Set(key, m)
			if err != nil {
				log.Error("Set block cache failed", "query", Q.String(), "error", err.Error())
			}

			return
		}
	}

	mesg, err = h.resolver.Lookup(proto, req)
	if err != nil {
		log.Warn("Resolve query failed", "query", Q.String())
		h.handleFailed(w, req)
		return
	}

	if mesg.Truncated && proto == "udp" {
		h.writeReplyMsg(w, mesg)
		return
	}

	if mesg.Rcode == dns.RcodeSuccess && len(mesg.Answer) == 0 {
		h.handleFailed(w, req)
		return
	}

	ttl := Config.Expire
	var candidateTTL uint32

	for index, answer := range mesg.Answer {
		log.Debug("Message answer", "index", index, "answer", answer.String())

		candidateTTL = answer.Header().Ttl
		if candidateTTL > 0 {
			ttl = candidateTTL
		}
	}

	h.writeReplyMsg(w, mesg)

	err = h.cache.Set(key, mesg)
	if err != nil {
		log.Error("Set query cache failed", "query", Q.String(), "error", err.Error())
		return
	}

	log.Debug("Set query into cache with ttl", "query", Q.String(), "ttl", ttl)
}

func (h *DNSHandler) handleFailed(w dns.ResponseWriter, message *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(message, dns.RcodeServerFailure)
	h.writeReplyMsg(w, m)
}

func (h *DNSHandler) writeReplyMsg(w dns.ResponseWriter, message *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Recovered in WriteReplyMsg", "recover", r)
		}
	}()

	err := w.WriteMsg(message)
	if err != nil {
		log.Error("Message writing failed", "error", err.Error())
	}
}
