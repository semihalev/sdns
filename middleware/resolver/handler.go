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

// contextKey is a type-safe key for context values (Go 1.21+ pattern)
type contextKey int

const (
	contextKeyRequestID contextKey = iota
	contextKeyNSL                  // nameserver lookup marker
	contextKeyNSList               // nameserver list prefix
)

// debugns is initialized once at startup
var debugns = func() bool {
	_, ok := os.LookupEnv("SDNS_DEBUGNS")
	return ok
}()

// New returns a new Handler
func New(cfg *config.Config) *DNSHandler {
	if cfg.Maxdepth == 0 {
		cfg.Maxdepth = 30
	}

	if cfg.QueryTimeout.Duration == 0 {
		cfg.QueryTimeout.Duration = 10 * time.Second
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
	if len(h.cfg.ForwarderServers) > 0 {
		ch.Next(ctx)
		return
	}

	w, req := ch.Writer, ch.Request

	if ctx.Value(contextKeyRequestID) == nil {
		ctx = context.WithValue(ctx, contextKeyRequestID, req.Id)
	}
	msg := h.handle(ctx, req)

	_ = w.WriteMsg(msg)
}

func (h *DNSHandler) handle(ctx context.Context, req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return dnsutil.SetRcode(req, dns.RcodeFormatError, false)
	}

	q := req.Question[0]

	// Extract DNSSEC OK bit from EDNS0
	do := false
	if opt := req.IsEdns0(); opt != nil {
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

	// Prepare request for authoritative servers
	// Clear RD and AD flags as we're querying authoritative servers
	req.RecursionDesired = false
	req.AuthenticatedData = false

	// Set CD flag based on DNSSEC support
	originalCD := req.CheckingDisabled
	if !req.CheckingDisabled {
		req.CheckingDisabled = !h.resolver.dnssec
	}

	// Set query timeout
	deadline := time.Now().Add(h.cfg.QueryTimeout.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Perform recursive resolution
	depth := h.cfg.Maxdepth
	isRootQuery := q.Name == rootzone
	resp, err := h.resolver.Resolve(ctx, req, h.resolver.rootservers, true, depth, 0, false, nil, isRootQuery)

	// Restore original CD flag if DNSSEC is not supported
	if !h.resolver.dnssec {
		req.CheckingDisabled = originalCD
		if resp != nil {
			resp.CheckingDisabled = originalCD
		}
	}

	if err != nil {
		log.Info("Resolve query failed", "query", formatQuestion(q), "error", err.Error())

		return dnsutil.SetRcode(req, dns.RcodeServerFailure, do)
	}

	// Convert certain response codes to SERVFAIL
	switch resp.Rcode {
	case dns.RcodeRefused, dns.RcodeNotZone:
		return dnsutil.SetRcode(req, dns.RcodeServerFailure, do)
	}

	return resp
}

func (h *DNSHandler) nsStats(req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	msg := new(dns.Msg)
	msg.SetReply(req)

	msg.Authoritative = false
	msg.RecursionAvailable = true

	// Default to root servers
	servers := h.resolver.rootservers
	const ttl = uint32(0)
	name := rootzone

	// Try to get cached nameservers for the query name
	if q.Name != rootzone {
		nsQuestion := dns.Question{Name: q.Name, Qtype: dns.TypeNS, Qclass: dns.ClassINET}

		// Try with current CD flag first
		if ns, err := h.resolver.ncache.Get(cache.Hash(nsQuestion, msg.CheckingDisabled)); err == nil {
			servers = ns.Servers
			name = q.Name
		} else if ns, err := h.resolver.ncache.Get(cache.Hash(nsQuestion, !msg.CheckingDisabled)); err == nil {
			// Try with opposite CD flag
			servers = ns.Servers
			name = q.Name
		}
	}

	// Copy server list under read lock
	servers.RLock()
	serversList := make([]*authcache.AuthServer, len(servers.List))
	copy(serversList, servers.List)
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

// purge removes nameserver cache entries for the given domain name
func (h *DNSHandler) purge(qname string) {
	nsQuestion := dns.Question{Name: qname, Qtype: dns.TypeNS, Qclass: dns.ClassINET}

	// Remove entries for both CD flag states
	h.resolver.ncache.Remove(cache.Hash(nsQuestion, false))
	h.resolver.ncache.Remove(cache.Hash(nsQuestion, true))
}

const name = "resolver"
