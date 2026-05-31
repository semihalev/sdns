package forwarder

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// dohAnswerFor builds a wire-format DNS response with a single A
// record. mismatchName, if non-empty, swaps the question section so
// the question-mismatch path in ServeDNS triggers.
func dohAnswerFor(t *testing.T, req *dns.Msg, ip string, mismatchName string) []byte {
	t.Helper()
	resp := new(dns.Msg)
	resp.SetReply(req)
	if mismatchName != "" {
		resp.Question = []dns.Question{{
			Name: dns.Fqdn(mismatchName), Qtype: req.Question[0].Qtype, Qclass: dns.ClassINET,
		}}
	}
	if req.Question[0].Qtype == dns.TypeA {
		rr, err := dns.NewRR(req.Question[0].Name + " 60 IN A " + ip)
		if err != nil {
			t.Fatalf("build A RR: %v", err)
		}
		resp.Answer = []dns.RR{rr}
	}
	b, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return b
}

// readDoHRequest decodes a DoH request body (POST). Returns the
// parsed *dns.Msg so handlers can inspect the question section.
func readDoHRequest(t *testing.T, r *http.Request) *dns.Msg {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Fatalf("expected POST, got %s", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != contentTypeDNS {
		t.Fatalf("expected Content-Type %s, got %s", contentTypeDNS, ct)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, dohMaxResponseSize))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		t.Fatalf("unpack body: %v", err)
	}
	return msg
}

// startDoHServer launches a TLS test server that answers DoH POSTs
// according to handler. Returns the URL (https://127.0.0.1:PORT/path)
// and a stop function. The test server uses a self-signed cert, so
// callers must override TLSClientConfig.InsecureSkipVerify in the
// returned *server's transport (see configureForTest below).
func startDoHServer(t *testing.T, path string, handler func(*http.Request) (status int, body []byte, contentType string)) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		status, body, ct := handler(r)
		if ct == "" {
			ct = contentTypeDNS
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	srv := httptest.NewTLSServer(mux)
	return srv.URL + path, srv.Close
}

// dohServerWithSkipVerify builds a *server pointing at testURL but
// with TLS verification skipped — httptest.NewTLSServer uses a self-
// signed cert that the production newDoHServer rejects.
func dohServerWithSkipVerify(t *testing.T, testURL string) *server {
	t.Helper()
	u, err := url.Parse(testURL)
	if err != nil {
		t.Fatalf("parse test url: %v", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("test url host %q is not an IP", host)
	}
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test-only — httptest TLS cert is self-signed
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &server{
		Addr:      testURL,
		Proto:     "doh",
		DoHURL:    testURL,
		DoHClient: &http.Client{Transport: tr, Timeout: 5 * time.Second},
	}
}

func TestNewDoHServer_IPLiteral(t *testing.T) {
	srv, err := newDoHServer("https://1.1.1.1/dns-query", 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("newDoHServer: %v", err)
	}
	if srv.Proto != "doh" {
		t.Errorf("Proto = %q, want doh", srv.Proto)
	}
	if srv.DoHURL != "https://1.1.1.1/dns-query" {
		t.Errorf("DoHURL = %q", srv.DoHURL)
	}
	if srv.DoHClient == nil {
		t.Fatal("DoHClient is nil")
	}
	// SNI must be the URL host (matches cert), not stripped.
	if sn := srv.DoHClient.Transport.(*http.Transport).TLSClientConfig.ServerName; sn != "1.1.1.1" {
		t.Errorf("ServerName = %q, want 1.1.1.1", sn)
	}
}

func TestNewDoHServer_CustomPort(t *testing.T) {
	srv, err := newDoHServer("https://1.1.1.1:8443/q", 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("newDoHServer: %v", err)
	}
	if srv.DoHURL != "https://1.1.1.1:8443/q" {
		t.Errorf("DoHURL = %q", srv.DoHURL)
	}
}

func TestNewDoHServer_RejectsNonHTTPS(t *testing.T) {
	if _, err := newDoHServer("http://1.1.1.1/dns-query", 2*time.Second, 5*time.Second); err == nil {
		t.Error("expected error for non-https scheme")
	}
}

func TestNewDoHServer_RejectsMissingHost(t *testing.T) {
	if _, err := newDoHServer("https:///dns-query", 2*time.Second, 5*time.Second); err == nil {
		t.Error("expected error for missing host")
	}
}

// stubResolver implements ipResolver for deterministic, offline
// hostname-bootstrap testing.
type stubResolver struct {
	ips     []net.IP
	err     error
	queried atomic.Int32
}

func (s *stubResolver) LookupIP(_ context.Context, _, _ string) ([]net.IP, error) {
	s.queried.Add(1)
	return s.ips, s.err
}

// TestNewDoHServer_HostnameSuccess exercises the full hostname
// bootstrap path through the swap-in resolver hook: resolver IS
// consulted, resolved IPs end up pinned in the transport, SNI is the
// URL hostname (not the resolved IP), Proto/DoHURL are correct.
func TestNewDoHServer_HostnameSuccess(t *testing.T) {
	orig := resolver
	t.Cleanup(func() { resolver = orig })

	stub := &stubResolver{ips: []net.IP{net.IPv4(192, 0, 2, 55), net.ParseIP("2001:db8::1")}}
	resolver = stub

	srv, err := newDoHServer("https://dns.test/dns-query", 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("newDoHServer: %v", err)
	}
	if stub.queried.Load() != 1 {
		t.Errorf("stub LookupIP calls = %d, want 1", stub.queried.Load())
	}
	if srv.Proto != "doh" {
		t.Errorf("Proto = %q, want doh", srv.Proto)
	}
	if srv.DoHURL != "https://dns.test/dns-query" {
		t.Errorf("DoHURL = %q", srv.DoHURL)
	}
	// SNI is the original hostname so cert SAN validation works
	// when we dial the resolved IP.
	tr := srv.DoHClient.Transport.(*http.Transport)
	if sn := tr.TLSClientConfig.ServerName; sn != "dns.test" {
		t.Errorf("ServerName = %q, want dns.test", sn)
	}
}

func TestNewDoHServer_HostnameBootstrapFails(t *testing.T) {
	orig := resolver
	t.Cleanup(func() { resolver = orig })
	resolver = &stubResolver{err: fmt.Errorf("nxdomain")}

	if _, err := newDoHServer("https://dns.test/q", 2*time.Second, 5*time.Second); err == nil {
		t.Error("expected bootstrap failure")
	}
}

// TestNewDoHServer_HostnameBootstrapEmpty covers the edge case
// where the resolver returns nil/empty without error — newDoHServer
// must reject this rather than build a client with no IPs.
func TestNewDoHServer_HostnameBootstrapEmpty(t *testing.T) {
	orig := resolver
	t.Cleanup(func() { resolver = orig })
	resolver = &stubResolver{ips: nil}

	if _, err := newDoHServer("https://dns.test/q", 2*time.Second, 5*time.Second); err == nil {
		t.Error("expected error on empty IP list")
	}
}

// TestForwarder_DoH_Success drives the full ServeDNS path against a
// local TLS DoH server.
func TestForwarder_DoH_Success(t *testing.T) {
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", ""), ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	resp := runForwarderQuery(t, f, "example.com.", dns.TypeA)

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer len = %d, want 1", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.5" {
		t.Errorf("wrong A record: %v", resp.Answer[0])
	}
}

func TestForwarder_DoH_ServerError(t *testing.T) {
	var hits atomic.Int32
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		hits.Add(1)
		return http.StatusInternalServerError, []byte("oops"), "text/plain"
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)

	if hits.Load() != 1 {
		t.Errorf("doh server hits = %d, want 1", hits.Load())
	}
}

func TestForwarder_DoH_BadContentType(t *testing.T) {
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		return http.StatusOK, []byte("not dns"), "text/plain"
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)
}

// TestForwarder_DoH_MismatchedQuestion exercises the
// dns_forwarder_response_mismatch_total path.
func TestForwarder_DoH_MismatchedQuestion(t *testing.T) {
	beforeMismatch := forwarderResponseMismatch.Value()

	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", "attacker.example."), ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)

	if got := forwarderResponseMismatch.Value() - beforeMismatch; got != 1 {
		t.Errorf("mismatch counter delta = %d, want 1", got)
	}
}

// TestForwarder_DoH_FallthroughOnError exercises the "first server
// fails, second succeeds" path. The first DoH server returns 500;
// the second answers OK. The client should get the second answer.
func TestForwarder_DoH_FallthroughOnError(t *testing.T) {
	failURL, stopFail := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		return http.StatusBadGateway, []byte("nope"), "text/plain"
	})
	defer stopFail()

	okURL, stopOK := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "198.51.100.7", ""), ""
	})
	defer stopOK()

	f := &Forwarder{servers: []*server{
		dohServerWithSkipVerify(t, failURL),
		dohServerWithSkipVerify(t, okURL),
	}, dnssec: false}

	resp := runForwarderQuery(t, f, "example.com.", dns.TypeA)
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %+v", resp)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "198.51.100.7" {
		t.Errorf("expected fallback answer, got %v", resp.Answer[0])
	}
}

// TestDoHGETBase64Ignored confirms that we POST, not GET — sending a
// GET-formatted request to our handler shouldn't happen.
func TestDoHRequestIsPOST(t *testing.T) {
	var sawMethod string
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		sawMethod = r.Method
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", ""), ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	runForwarderQuery(t, f, "example.com.", dns.TypeA)

	if sawMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", sawMethod)
	}
}

// TestDoHAcceptsBase64Path ensures URL path with characters that
// base64url uses doesn't break Pack/Unpack.
func TestDoHAcceptsBase64Path(t *testing.T) {
	_ = base64.RawURLEncoding // satisfy import
	dohURL, stop := startDoHServer(t, "/abc-_123/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", ""), ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	if resp := runForwarderQuery(t, f, "example.com.", dns.TypeA); resp == nil {
		t.Fatal("nil response")
	}
}

func TestForwarder_DoH_Timeout(t *testing.T) {
	// Handler that sleeps past the client's timeout.
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		time.Sleep(200 * time.Millisecond)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", ""), ""
	})
	defer stop()

	srv := dohServerWithSkipVerify(t, dohURL)
	srv.DoHClient.Timeout = 50 * time.Millisecond

	f := &Forwarder{servers: []*server{srv}, dnssec: false}
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)
}

// TestForwarder_DoH_CaseInsensitiveContentType checks that an
// upstream returning "Application/DNS-Message" (mixed case, RFC 7231
// §3.1.1.1 allows it) is still accepted. The old strings.HasPrefix
// check rejected it.
func TestForwarder_DoH_CaseInsensitiveContentType(t *testing.T) {
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", ""), "Application/DNS-Message"
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	resp := runForwarderQuery(t, f, "example.com.", dns.TypeA)
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer with mixed-case Content-Type, got %+v", resp)
	}
}

// TestForwarder_DoH_ContentTypeWithParams ensures that
// "application/dns-message; charset=utf-8" (parameters per RFC 7231)
// parses correctly.
func TestForwarder_DoH_ContentTypeWithParams(t *testing.T) {
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		return http.StatusOK, dohAnswerFor(t, req, "203.0.113.5", ""), "application/dns-message; charset=utf-8"
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	if resp := runForwarderQuery(t, f, "example.com.", dns.TypeA); resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer with parameterised Content-Type, got %+v", resp)
	}
}

// TestForwarder_DoH_MismatchedID ensures a response whose TXID is
// neither an echo of req.Id nor 0 (the RFC 8484-blessed normalized
// value) is rejected. Matches the UDP/DoT behaviour enforced by
// miekg's dns.Client.ExchangeContext.
func TestForwarder_DoH_MismatchedID(t *testing.T) {
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		resp := new(dns.Msg)
		resp.SetReply(req)
		// Forge a bogus TXID — neither echoed nor 0.
		resp.Id = req.Id ^ 0x5555
		if resp.Id == 0 { // vanishingly unlikely but cover it
			resp.Id = 0x1234
		}
		rr, err := dns.NewRR(req.Question[0].Name + " 60 IN A 203.0.113.5")
		if err != nil {
			t.Fatalf("build RR: %v", err)
		}
		resp.Answer = []dns.RR{rr}
		body, err := resp.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		return http.StatusOK, body, ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)
}

// TestForwarder_DoH_ZeroIDAccepted ensures the RFC 8484
// normalisation case (server returns ID=0 regardless of request ID)
// is accepted — otherwise we'd break interop with RFC-strict DoH
// servers.
func TestForwarder_DoH_ZeroIDAccepted(t *testing.T) {
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Id = 0
		rr, err := dns.NewRR(req.Question[0].Name + " 60 IN A 203.0.113.5")
		if err != nil {
			t.Fatalf("build RR: %v", err)
		}
		resp.Answer = []dns.RR{rr}
		body, err := resp.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		return http.StatusOK, body, ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	resp := runForwarderQuery(t, f, "example.com.", dns.TypeA)
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer when upstream returned ID=0, got %+v", resp)
	}
}

// TestForwarder_SharedQueryBudget proves that three slow upstreams
// don't take 3 * per-upstream-timeout. With queryTimeout set on the
// Forwarder, the whole loop bounds at queryTimeout regardless of
// how many upstreams are tried.
func TestForwarder_SharedQueryBudget(t *testing.T) {
	// Each upstream sleeps for 500ms before returning an error so
	// the next upstream is tried. Without a shared budget, three
	// upstreams = 1.5s. With queryTimeout=300ms, the loop must
	// bail well before that.
	slowHandler := func(r *http.Request) (int, []byte, string) {
		time.Sleep(500 * time.Millisecond)
		return http.StatusInternalServerError, []byte("slow"), "text/plain"
	}
	url1, stop1 := startDoHServer(t, "/dns-query", slowHandler)
	defer stop1()
	url2, stop2 := startDoHServer(t, "/dns-query", slowHandler)
	defer stop2()
	url3, stop3 := startDoHServer(t, "/dns-query", slowHandler)
	defer stop3()

	f := &Forwarder{
		servers: []*server{
			dohServerWithSkipVerify(t, url1),
			dohServerWithSkipVerify(t, url2),
			dohServerWithSkipVerify(t, url3),
		},
		dnssec:       false,
		queryTimeout: 300 * time.Millisecond,
	}

	start := time.Now()
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)
	elapsed := time.Since(start)

	// 3 upstreams * 500ms would be 1.5s. With the shared 300ms
	// budget we should bail well before 1 second — pick a generous
	// upper bound that still proves the budget worked.
	if elapsed > time.Second {
		t.Errorf("elapsed = %v, want < 1s (shared budget was 300ms; 3 sequential 500ms calls would be 1.5s)", elapsed)
	}
}

// TestForwarder_DoH_OversizedBody ensures an upstream returning a
// body larger than dohMaxResponseSize is rejected (SERVFAIL) rather
// than silently truncated to a parseable prefix.
func TestForwarder_DoH_OversizedBody(t *testing.T) {
	// Build a body that is a valid DNS message prefix followed by
	// junk bytes so total length exceeds the limit. The prefix is
	// the legitimate response; trailing bytes are padding.
	dohURL, stop := startDoHServer(t, "/dns-query", func(r *http.Request) (int, []byte, string) {
		req := readDoHRequest(t, r)
		legitimate := dohAnswerFor(t, req, "203.0.113.5", "")
		// Pad past dohMaxResponseSize so io.LimitReader's +1 byte
		// detection trips.
		body := make([]byte, 0, len(legitimate)+dohMaxResponseSize)
		body = append(body, legitimate...)
		body = append(body, make([]byte, dohMaxResponseSize)...)
		return http.StatusOK, body, ""
	})
	defer stop()

	f := &Forwarder{servers: []*server{dohServerWithSkipVerify(t, dohURL)}, dnssec: false}
	runForwarderQueryExpectSERVFAIL(t, f, "example.com.", dns.TypeA)
}

// runForwarderQuery drives a single A query through the forwarder
// and returns the response the chain wrote. nil on SERVFAIL/cancel.
func runForwarderQuery(t *testing.T, f *Forwarder, qname string, qtype uint16) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.RecursionDesired = true

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f})
	ch.Reset(mw, req)

	f.ServeDNS(context.Background(), ch)

	if mw.Msg() == nil {
		return nil
	}
	return mw.Msg()
}

// runForwarderQueryExpectSERVFAIL is runForwarderQuery's twin for
// the explicit failure path — when every server errors out the
// forwarder issues CancelWithRcode(SERVFAIL).
func runForwarderQueryExpectSERVFAIL(t *testing.T, f *Forwarder, qname string, qtype uint16) {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.RecursionDesired = true

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f})
	ch.Reset(mw, req)

	f.ServeDNS(context.Background(), ch)

	if msg := mw.Msg(); msg == nil || msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %+v", msg)
	}
}

func TestNew_DoH_ConfigParse(t *testing.T) {
	cfg := stubConfig([]string{
		"1.1.1.1:53",
		"tls://1.1.1.1:853",
		"https://1.1.1.1/dns-query",
	})
	f := New(cfg)
	if len(f.servers) != 3 {
		t.Fatalf("len(servers) = %d, want 3", len(f.servers))
	}
	wantProto := []string{"udp", "tcp-tls", "doh"}
	for i, w := range wantProto {
		if f.servers[i].Proto != w {
			t.Errorf("server %d proto = %q, want %q", i, f.servers[i].Proto, w)
		}
	}
}

func TestNew_DoH_SkipsBadEntries(t *testing.T) {
	cfg := stubConfig([]string{
		"https:///dns-query", // missing host
		"https://not-a-real-hostname-zzz-xyz-9999.invalid/q", // bootstrap fails
		"1.1.1.1:53", // valid — must survive
	})
	f := New(cfg)
	if len(f.servers) != 1 {
		t.Fatalf("len(servers) = %d, want 1 (only the udp entry should survive)", len(f.servers))
	}
	if f.servers[0].Proto != "udp" {
		t.Errorf("surviving server proto = %q, want udp", f.servers[0].Proto)
	}
}

// stubConfig builds a config.Config with only the fields New touches.
func stubConfig(forwarders []string) *config.Config {
	return &config.Config{ForwarderServers: forwarders}
}

var _ = strings.ToLower // satisfy import in test refactors
