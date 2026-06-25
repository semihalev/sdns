package dnsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dohResponseFor builds a wire-format reply to req. mismatchName, when
// non-empty, swaps the question section to trigger the question guard.
func dohResponseFor(t *testing.T, req *dns.Msg, mismatchName string) []byte {
	t.Helper()
	resp := new(dns.Msg)
	resp.SetReply(req)
	if mismatchName != "" {
		resp.Question = []dns.Question{{Name: dns.Fqdn(mismatchName), Qtype: req.Question[0].Qtype, Qclass: dns.ClassINET}}
	}
	if rr, err := dns.NewRR(req.Question[0].Name + " 60 IN A 93.184.216.34"); err == nil {
		resp.Answer = []dns.RR{rr}
	}
	b, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b
}

// startDoHTestServer launches a TLS DoH server and returns a Client
// wired to trust it.
func startDoHTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*Client, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(handler))
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test-only self-signed cert
		},
	}
	c := &Client{Proto: "doh", DoHURL: srv.URL + "/dns-query", DoHClient: httpClient}
	return c, srv.Close
}

func TestClientExchange_DoH(t *testing.T) {
	req := newReq()
	c, stop := startDoHTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		in := new(dns.Msg)
		if err := in.Unpack(body); err != nil {
			t.Errorf("unpack request: %v", err)
		}
		w.Header().Set("Content-Type", contentTypeDNS)
		_, _ = w.Write(dohResponseFor(t, in, ""))
	})
	defer stop()

	resp, _, err := c.Exchange(context.Background(), req, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}

func TestClientExchange_DoHQuestionMismatch(t *testing.T) {
	req := newReq()
	c, stop := startDoHTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		in := new(dns.Msg)
		_ = in.Unpack(body)
		w.Header().Set("Content-Type", contentTypeDNS)
		_, _ = w.Write(dohResponseFor(t, in, "victim.test"))
	})
	defer stop()

	_, _, err := c.Exchange(context.Background(), req, "")
	if !errors.Is(err, ErrQuestion) {
		t.Fatalf("expected ErrQuestion, got %v", err)
	}
}

func TestClientExchange_DoHBadStatus(t *testing.T) {
	c, stop := startDoHTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	defer stop()

	_, _, err := c.Exchange(context.Background(), newReq(), "")
	if err == nil {
		t.Fatal("expected an error for non-200 status, got nil")
	}
}
