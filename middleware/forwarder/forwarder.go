package forwarder

import (
	"context"
	"fmt"
//	"net"
	"net/http"
	"strings"
	"bytes"
	"io"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

type server struct {
	Addr  string
	Proto string
}

// Forwarder type
type Forwarder struct {
	servers []*server
}

// New return forwarder
func New(cfg *config.Config) *Forwarder {
	forwarderServers := []*server{}
	for _, s := range cfg.ForwarderServers {
		srv := &server{Proto: "udp"}

		if strings.HasPrefix(s, "tls://") {
			s = strings.TrimPrefix(s, "tls://")
			srv.Proto = "tcp-tls"
		} else if strings.HasPrefix(s, "https://") {
			s = strings.TrimPrefix(s, "https://")
			srv.Proto = "doh"
		}

		if strings.HasPrefix(s, "doh://") {
			s = strings.TrimPrefix(s, "doh://")
			srv.Proto = "doh"
		}

		srv.Addr = s
		forwarderServers = append(forwarderServers, srv)
	}

	return &Forwarder{servers: forwarderServers}
}

// Name return middleware name
func (f *Forwarder) Name() string { return name }

// ServeDNS implements the Handle interface.
func (f *Forwarder) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 || len(f.servers) == 0 {
		ch.CancelWithRcode(dns.RcodeServerFailure, true)
		return
	}

	fReq := new(dns.Msg)
	fReq.SetQuestion(req.Question[0].Name, req.Question[0].Qtype)
	fReq.Question[0].Qclass = req.Question[0].Qclass
	fReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	fReq.CheckingDisabled = req.CheckingDisabled

	for _, server := range f.servers {
		var resp *dns.Msg
		var err error

		switch server.Proto {
		case "doh":
			resp, err = dohExchange(ctx, req, server.Addr)
		default:
			resp, err = dnsutil.Exchange(ctx, req, server.Addr, server.Proto)
		}

		if err != nil {
			log.Warn("forwarder query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		resp.Id = req.Id

		// Write the response to the client
		if err := w.WriteMsg(resp); err != nil {
			log.Warn("failed to write DNS response", "error", err.Error())
		}

		return
	}

	ch.CancelWithRcode(dns.RcodeServerFailure, true)
}


// dohExchange sends a DNS query using DoH (POST method over HTTPS)
func dohExchange(ctx context.Context, req *dns.Msg, serverAddr string) (*dns.Msg, error) {
	// Check if the serverAddr contains the scheme, if not, add "https://" prefix
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "https://" + serverAddr
	}

	// Send the DoH request as a POST request with the DNS message in the request body
	msgBytes, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to encode DNS query: %w", err)
	}

	resp, err := http.Post(serverAddr, "application/dns-message", bytes.NewBuffer(msgBytes))
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Parse the response body into a DNS message
	dnsResp := new(dns.Msg)
	err = dnsResp.Unpack(responseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DoH response: %w", err)
	}

	return dnsResp, nil
}




func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const name = "forwarder"
