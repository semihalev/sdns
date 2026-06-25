package dnsclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// dohMaxResponseSize bounds the response body read so a misbehaving
// upstream can't OOM us with a huge body. DNS messages can't exceed
// 64 KiB on the wire (RFC 1035 length field is uint16), so this limit
// is a tight ceiling on legitimate traffic.
const dohMaxResponseSize = 65535

// contentTypeDNS is the RFC 8484 wire-format media type. Set on both
// the Content-Type of the POST body and the Accept header so an
// upstream that supports multiple media types knows which one we want
// back. Compared case-insensitively against parsed responses
// (RFC 7231 §3.1.1.1).
const contentTypeDNS = "application/dns-message"

// dohExchange POSTs req to a DoH endpoint (RFC 8484) and decodes the
// wire-format response. The http.Client is supplied by the caller and
// reused across queries — it carries the pinned-IP transport / HTTP2
// connection pool, so it must never be constructed per call.
func dohExchange(ctx context.Context, req *dns.Msg, url string, client *http.Client) (*dns.Msg, error) {
	body, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeDNS)
	httpReq.Header.Set("Accept", contentTypeDNS)

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh exchange: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// Drain a small amount of the body so the connection can be
		// reused (Go's http.Transport requires the body be read before
		// the conn returns to the pool).
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 1024))
		return nil, fmt.Errorf("doh status %d", httpResp.StatusCode)
	}

	// RFC 7231 §3.1.1.1: media types are case-insensitive and may carry
	// parameters (charset=, boundary=, ...). mime.ParseMediaType strips
	// parameters and lowercases the type for us.
	rawCT := httpResp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(rawCT)
	if err != nil || !strings.EqualFold(mediaType, contentTypeDNS) {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 1024))
		return nil, fmt.Errorf("doh unexpected content-type %q", rawCT)
	}

	// Read one byte past the size cap so we can distinguish "body fits
	// within limit" from "body exceeded limit and was truncated".
	// Without this dns.Msg.Unpack would happily decode the parseable
	// prefix of an oversized response and silently ignore the rest.
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

	// Validate the response transaction ID. RFC 8484 §4.1 says DoH
	// clients SHOULD use DNS ID 0 for cache friendliness, and several
	// compliant servers normalise the response ID to 0 regardless of
	// what the request carried — so accept either an exact echo or a
	// zero. Anything else is a buggy or hostile upstream.
	if resp.Id != req.Id && resp.Id != 0 {
		return nil, fmt.Errorf("doh response ID mismatch: got %d, want %d or 0", resp.Id, req.Id)
	}
	return resp, nil
}
