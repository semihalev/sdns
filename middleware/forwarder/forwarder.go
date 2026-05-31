package forwarder

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

var (
	// forwarderFailures counts upstream exchanges that returned an
	// error (timeout, connection refused, TLS handshake failure,
	// etc). Bumped per upstream tried, so an SDNS configured with
	// two forwarders that both fail increments by 2 for one client
	// query. That matches "operator wants to know upstream health"
	// better than a per-client increment would.
	forwarderFailures = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_forwarder_failures_total",
		Help: "Total upstream forwarder exchange failures",
	})

	// forwarderResponseMismatch counts responses whose question
	// section did not match the outstanding query. A non-zero rate
	// is a security signal — a real upstream never returns a
	// mismatched question, so persistent counts here suggest a
	// poisoning attempt or a broken upstream.
	forwarderResponseMismatch = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_forwarder_response_mismatch_total",
		Help: "Total upstream responses dropped due to question-section mismatch (potential poisoning signal)",
	})
)

type server struct {
	Addr  string
	Proto string // "udp" | "tcp-tls" | "doh"

	// DoH-only fields. Populated by newDoHServer when Proto=="doh";
	// nil for plain UDP and DoT entries.
	DoHURL    string
	DoHClient *http.Client
}

// Forwarder type.
type Forwarder struct {
	servers   []*server
	dnssec    bool
	tlsConfig *tls.Config

	// queryTimeout caps the total time ServeDNS spends across every
	// configured upstream — mirroring how the resolver handler
	// enforces cfg.QueryTimeout. Without it, three slow upstreams
	// could take ~3 * per-upstream-timeout, which contradicts the
	// README description of querytimeout as the maximum time for
	// any one client-facing query.
	queryTimeout time.Duration
}

// New return forwarder.
//
// Accepted forwarder_servers formats:
//   - "1.1.1.1:53"                         — plain UDP (TCP fallback on TC)
//   - "tls://1.1.1.1:853"                  — DoT (RFC 7858) over TCP-TLS
//   - "https://1.1.1.1/dns-query"          — DoH (RFC 8484) with IP literal
//   - "https://dns.example.com/dns-query"  — DoH with hostname (bootstrapped
//     via the system resolver once at startup; resolved IPs are pinned for
//     the process lifetime, no per-query DNS dependency)
//
// DoH servers honour cfg.Timeout (per-IP dial budget) and
// cfg.QueryTimeout (full request budget) — operators tune both via
// the existing top-level config keys, no DoH-specific knob.
//
// Each entry is parsed independently; a malformed or unreachable
// entry is logged and skipped so one bad upstream does not abort
// startup if others are usable.
func New(cfg *config.Config) *Forwarder {
	dialTimeout := cfg.Timeout.Duration
	if dialTimeout <= 0 {
		dialTimeout = 2 * time.Second
	}
	requestTimeout := cfg.QueryTimeout.Duration
	if requestTimeout <= 0 {
		requestTimeout = 10 * time.Second
	}

	forwarderservers := []*server{}
	for _, s := range cfg.ForwarderServers {
		switch {
		case strings.HasPrefix(s, "https://"):
			srv, err := newDoHServer(s, dialTimeout, requestTimeout)
			if err != nil {
				zlog.Error("Forwarder DoH server not usable", "server", s, "error", err.Error())
				continue
			}
			forwarderservers = append(forwarderservers, srv)

		case strings.HasPrefix(s, "tls://"):
			addr := strings.TrimPrefix(s, "tls://")
			if !validForwarderAddr(addr) {
				zlog.Error("Forwarder server is not correct. Check your config.", "server", s)
				continue
			}
			forwarderservers = append(forwarderservers, &server{Addr: addr, Proto: "tcp-tls"})

		default:
			if !validForwarderAddr(s) {
				zlog.Error("Forwarder server is not correct. Check your config.", "server", s)
				continue
			}
			forwarderservers = append(forwarderservers, &server{Addr: s, Proto: "udp"})
		}
	}

	return &Forwarder{
		servers:      forwarderservers,
		dnssec:       cfg.DNSSEC == "on",
		queryTimeout: requestTimeout,
	}
}

// validForwarderAddr reports whether addr is a host:port string with
// an IPv4 or IPv6 host literal. Preserves the pre-DoH validation
// (which only accepted IP literals for UDP / DoT).
func validForwarderAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// (*Forwarder).Name name return middleware name.
func (f *Forwarder) Name() string { return name }

// (*Forwarder).ServeDNS serveDNS implements the Handle interface.
func (f *Forwarder) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 || len(f.servers) == 0 {
		ch.CancelWithRcode(dns.RcodeServerFailure, true)
		return
	}

	// Wrap ctx with the shared per-query budget so the dispatch
	// loop below cannot exceed cfg.QueryTimeout regardless of how
	// many upstreams are configured. Each individual call still
	// respects its own per-upstream timeout (dns.Client default for
	// UDP/DoT, http.Client.Timeout for DoH); ctx cancellation
	// short-circuits the loop when the overall budget is gone.
	//
	// Guard against zero queryTimeout — that would create an
	// already-expired context. Production goes through New() which
	// always sets a positive value; this branch keeps the package
	// robust if a Forwarder is constructed directly (mostly tests).
	if f.queryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.queryTimeout)
		defer cancel()
	}

	// Preserve the client's CD bit. We may set CD=1 on the
	// upstream query when this server isn't doing DNSSEC, but
	// the response written back to the client must reflect
	// what the client asked for — otherwise the cache dedup
	// key (CD=client) and the stored entry's CD diverge, and
	// CD=1 clients re-miss every lookup in forwarder mode.
	clientCD := req.CheckingDisabled
	if !clientCD && !f.dnssec {
		req.CheckingDisabled = true
	}
	defer func() { req.CheckingDisabled = clientCD }()

	for _, server := range f.servers {
		var (
			resp *dns.Msg
			err  error
		)
		if server.Proto == "doh" {
			resp, err = dohExchange(ctx, server, req)
		} else {
			reqClient := &dns.Client{Net: server.Proto}
			if server.Proto == "tcp-tls" {
				reqClient.TLSConfig = f.tlsConfig
			}
			resp, err = dnsutil.Exchange(ctx, req, server.Addr, server.Proto, reqClient)
		}
		if err != nil {
			forwarderFailures.Inc()
			zlog.Info("forwarder query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		// Reject responses whose question section does not match the
		// outstanding query. A malicious or misbehaving upstream that
		// returns a different name/type/class would otherwise be cached
		// under that question, poisoning lookups for unrelated names.
		if !questionMatches(req.Question[0], resp.Question) {
			forwarderResponseMismatch.Inc()
			zlog.Info("forwarder dropped response with mismatched question",
				"query", formatQuestion(req.Question[0]))
			continue
		}

		resp.Id = req.Id
		resp.CheckingDisabled = clientCD

		_ = w.WriteMsg(resp)
		return
	}

	// Restore the client's CD before synthesising the
	// all-upstreams-failed SERVFAIL. CancelWithRcode calls
	// SetReply under the hood, which copies
	// req.CheckingDisabled into the response; leaving the
	// overridden CD in place would hand the cache a SERVFAIL
	// stored under CD=true while the lookup keyed on CD=false.
	// The deferred restore above still covers the early
	// return on success.
	req.CheckingDisabled = clientCD
	ch.CancelWithRcode(dns.RcodeServerFailure, true)
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

// questionMatches reports whether the response's question section answers the
// outstanding request question. The name comparison is case-insensitive
// because DNS names are not case-sensitive on the wire.
func questionMatches(req dns.Question, resp []dns.Question) bool {
	if len(resp) != 1 {
		return false
	}
	r := resp[0]
	return r.Qtype == req.Qtype && r.Qclass == req.Qclass && strings.EqualFold(r.Name, req.Name)
}

const name = "forwarder"
