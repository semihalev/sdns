package forwarder

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// dohMaxResponseSize bounds the response body read so a misbehaving
// upstream can't OOM us with a huge body. DNS messages can't exceed
// 64 KiB on the wire (RFC 1035 length field is uint16), so this
// limit is a tight ceiling on legitimate traffic.
const dohMaxResponseSize = 65535

// contentTypeDNS is the RFC 8484 wire-format media type. Set on both
// the Content-Type of the POST body and the Accept header so an
// upstream that supports multiple media types knows which one we
// want back. Compared case-insensitively against parsed responses
// (RFC 7231 §3.1.1.1).
const contentTypeDNS = "application/dns-message"

// ipResolver is the subset of net.Resolver this package uses for
// hostname bootstrap. The interface indirection lets tests swap in
// a deterministic stub instead of standing up a real DNS listener.
type ipResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// resolver is the resolver used for bootstrap of DoH hostnames.
// Production always uses net.DefaultResolver, which itself defers
// to the system resolver (/etc/resolv.conf on Unix, the configured
// DNS suffixes on Windows).
var resolver ipResolver = net.DefaultResolver

// newDoHServer parses a DoH upstream URL, resolves the hostname (if
// any) via the system resolver, and returns a server entry ready to
// be added to Forwarder.servers. Hostname resolution happens once at
// boot — there is no per-query DNS dependency. The resolved IPs are
// pinned into a custom DialContext on the returned http.Client so
// Go's transport never re-resolves at connect time.
//
// dialTimeout bounds a single per-IP TCP dial — sourced from
// cfg.Timeout so operators tune all upstream timeouts through one
// knob. A blackholed pinned IP gets bypassed in dialTimeout
// instead of consuming the entire requestTimeout, which keeps the
// rotation effective even when a hostname resolves to mixed A/AAAA
// on a host with broken v6.
//
// requestTimeout caps the full POST round-trip — sourced from
// cfg.QueryTimeout. Zero on either disables that ceiling; production
// callers should always pass non-zero values.
//
// TLS ServerName is set to the original hostname even when we dial
// an IP literal — this preserves SNI and cert-chain validation.
//
// Returns an error if the URL is malformed, the scheme is not https,
// the URL has no host, or the hostname fails to resolve at boot
// (no usable IPs). The caller treats those failures as "skip this
// entry, keep going" to match the existing tls:// behaviour in
// New().
func newDoHServer(rawURL string, dialTimeout, requestTimeout time.Duration) (*server, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		// IP literal — no bootstrap needed.
		ips = []net.IP{ip}
	} else {
		// Hostname — bootstrap via the system resolver. Short
		// timeout so a broken /etc/resolv.conf can't block startup
		// for minutes.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, err = resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("bootstrap %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("bootstrap %s: no addresses returned", host)
		}
	}

	// Snapshot the IPs into a fresh slice we own, then the custom
	// DialContext below closes over it. We don't refresh — DoH
	// provider IPs rarely move, and a refresh ticker is more
	// complexity than the MVP warrants. If the IPs ever drift,
	// restart picks them up.
	pinned := append([]net.IP(nil), ips...)

	// nextStart rotates the starting position in the pinned list
	// per dial so consecutive dial attempts don't always hit the
	// same first IP. Without this a blackholed address at index 0
	// would burn its full per-IP timeout on every request before
	// failing over.
	var nextStart atomic.Uint32

	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: requestTimeout,
		// Custom DialContext: ignore the addr Go's transport would
		// have computed (which would re-resolve the hostname) and
		// dial the pinned IPs in rotation order, returning the
		// first successful connection. Each dial is capped by
		// dialTimeout so a blackholed address bounces in that
		// budget instead of consuming the full request timeout.
		// The port comes from the URL.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			n := len(pinned)
			start := int(nextStart.Add(1)-1) % n
			var lastErr error
			for i := range n {
				ip := pinned[(start+i)%n]
				d := net.Dialer{Timeout: dialTimeout}
				conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr == nil {
				lastErr = errors.New("no pinned IPs available")
			}
			return nil, lastErr
		},
		TLSClientConfig: &tls.Config{
			// ServerName is the original hostname so SNI is sent
			// correctly and the cert is validated against the
			// name the operator typed, not against the IP. For
			// IP-literal URLs, host == ip.String() — the cert
			// must have a matching SAN.
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		},
	}

	return &server{
		Addr:      rawURL,
		Proto:     "doh",
		DoHURL:    rawURL,
		DoHClient: &http.Client{Transport: tr, Timeout: requestTimeout},
	}, nil
}

// dohExchange POSTs req to the DoH endpoint and decodes the wire-
// format response. Mirrors the (msg, error) contract of
// dnsutil.Exchange so the dispatch site in ServeDNS can treat DoH
// identically to UDP / DoT.
func dohExchange(ctx context.Context, srv *server, req *dns.Msg) (*dns.Msg, error) {
	body, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.DoHURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeDNS)
	httpReq.Header.Set("Accept", contentTypeDNS)

	httpResp, err := srv.DoHClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh exchange: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// Drain a small amount of the body so the connection can
		// be reused (Go's http.Transport requires the body be read
		// before the conn returns to the pool).
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 1024))
		return nil, fmt.Errorf("doh status %d", httpResp.StatusCode)
	}

	// RFC 7231 §3.1.1.1: media types are case-insensitive and may
	// carry parameters (charset=, boundary=, ...). mime.ParseMediaType
	// strips parameters and lowercases the type for us.
	rawCT := httpResp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(rawCT)
	if err != nil || !strings.EqualFold(mediaType, contentTypeDNS) {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 1024))
		return nil, fmt.Errorf("doh unexpected content-type %q", rawCT)
	}

	// Read one byte past the size cap so we can distinguish "body
	// fits within limit" from "body exceeded limit and was
	// truncated". Without this dns.Msg.Unpack would happily decode
	// the parseable prefix of an oversized response and silently
	// ignore the rest.
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, dohMaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(respBody) > dohMaxResponseSize {
		return nil, fmt.Errorf("doh response exceeds %d bytes", dohMaxResponseSize)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBody); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	// Validate the response transaction ID. miekg/dns's
	// Client.ExchangeContext does this for UDP/DoT; on the DoH
	// path we have to do it ourselves before the caller rewrites
	// resp.Id = req.Id. RFC 8484 §4.1 says DoH clients SHOULD use
	// DNS ID 0 for cache friendliness, and several compliant
	// servers normalise the response ID to 0 regardless of what
	// the request carried — so accept either an exact echo or a
	// zero. Anything else is a buggy or hostile upstream.
	if resp.Id != req.Id && resp.Id != 0 {
		return nil, fmt.Errorf("doh response ID mismatch: got %d, want %d or 0", resp.Id, req.Id)
	}
	return resp, nil
}
