package middleware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// RFC 9520 section 3.1 limits a single resolution to three attempts for the
// same question, server endpoint, and transport tuple.
const maxResolutionAttempts = 3

// ErrResolutionAttemptLimit identifies a request-tree retry-guard rejection.
// It is request-local: callers must not treat it as evidence that the upstream
// server is unhealthy.
var ErrResolutionAttemptLimit = errors.New("resolution attempt limit exceeded")

// ResolutionAttemptLimitError records the tuple rejected by the RFC 9520
// request-tree attempt guard.
type ResolutionAttemptLimitError struct {
	Question  dns.Question
	Endpoint  string
	Transport string
}

func (e *ResolutionAttemptLimitError) Error() string {
	return fmt.Sprintf(
		"%s for %s %s %s via %s/%s",
		ErrResolutionAttemptLimit,
		dns.CanonicalName(e.Question.Name),
		dns.ClassToString[e.Question.Qclass],
		dns.TypeToString[e.Question.Qtype],
		e.Endpoint,
		e.Transport,
	)
}

// Unwrap lets callers classify a limit error with errors.Is.
func (e *ResolutionAttemptLimitError) Unwrap() error { return ErrResolutionAttemptLimit }

type resolutionAttemptKey struct {
	qname     string
	qtype     uint16
	qclass    uint16
	endpoint  string
	transport string
}

// ResolutionAttemptGuard owns retry state for one complete client request
// tree. A mutex keeps the check-and-increment atomic across resolver fan-out.
type ResolutionAttemptGuard struct {
	mu       sync.Mutex
	attempts map[resolutionAttemptKey]uint8
}

// NewResolutionAttemptGuard returns an empty request-tree retry guard.
func NewResolutionAttemptGuard() *ResolutionAttemptGuard {
	return new(ResolutionAttemptGuard)
}

// Begin records one actual network attempt, rejecting the fourth attempt for
// an identical RFC 9520 tuple. Call it immediately before other accounting and
// before dialing so a rejected attempt consumes neither work budget nor wire
// resources.
func (g *ResolutionAttemptGuard) Begin(q dns.Question, endpoint, transport string) error {
	if g == nil {
		return nil
	}

	key := resolutionAttemptKey{
		qname:     dns.CanonicalName(q.Name),
		qtype:     q.Qtype,
		qclass:    q.Qclass,
		endpoint:  CanonicalResolutionEndpoint(endpoint),
		transport: canonicalResolutionTransport(transport),
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.attempts == nil {
		g.attempts = make(map[resolutionAttemptKey]uint8)
	}
	if g.attempts[key] >= maxResolutionAttempts {
		return &ResolutionAttemptLimitError{
			Question:  dns.Question{Name: key.qname, Qtype: key.qtype, Qclass: key.qclass},
			Endpoint:  key.endpoint,
			Transport: key.transport,
		}
	}
	g.attempts[key]++
	return nil
}

// CanonicalResolutionEndpoint normalizes endpoint spellings before they are
// used as attempt-guard or duplicate-suppression identities.
func CanonicalResolutionEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if addrPort, err := netip.ParseAddrPort(endpoint); err == nil {
		return addrPort.String()
	}

	if parsed, err := url.Parse(endpoint); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		hostname := canonicalResolutionHost(parsed.Hostname())
		port := parsed.Port()
		if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
			port = ""
		}
		if port == "" {
			if strings.Contains(hostname, ":") {
				parsed.Host = "[" + hostname + "]"
			} else {
				parsed.Host = hostname
			}
		} else {
			parsed.Host = net.JoinHostPort(hostname, canonicalResolutionPort(port))
		}
		parsed.Fragment = ""
		return parsed.String()
	}

	if host, port, err := net.SplitHostPort(endpoint); err == nil {
		return net.JoinHostPort(canonicalResolutionHost(host), canonicalResolutionPort(port))
	}
	return strings.ToLower(endpoint)
}

func canonicalResolutionHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return host
}

func canonicalResolutionPort(port string) string {
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		return strconv.FormatUint(n, 10)
	}
	return strings.ToLower(port)
}

func canonicalResolutionTransport(transport string) string {
	transport = strings.ToLower(strings.TrimSpace(transport))
	if transport == "" {
		return "udp"
	}
	return transport
}

type resolutionAttemptKeyType struct{}

var resolutionAttemptContextKey = &resolutionAttemptKeyType{}

// WithResolutionAttemptGuard pins guard into ctx. Pinning is required for
// detached work because its originating ResponseMeta can be reset and reused.
func WithResolutionAttemptGuard(ctx context.Context, guard *ResolutionAttemptGuard) context.Context {
	return context.WithValue(ctx, resolutionAttemptContextKey, guard)
}

// ResolutionAttemptGuardFrom returns the request tree's retry guard.
func ResolutionAttemptGuardFrom(ctx context.Context) *ResolutionAttemptGuard {
	if guard, _ := ctx.Value(resolutionAttemptContextKey).(*ResolutionAttemptGuard); guard != nil {
		return guard
	}
	if meta := ResponseMetaFrom(ctx); meta != nil {
		return meta.ResolutionAttemptGuard()
	}
	return nil
}

// EnsureResolutionAttemptGuard establishes and pins the request tree's retry
// guard. Unlike recursion-work accounting, this RFC safeguard is always on.
func EnsureResolutionAttemptGuard(ctx context.Context) (context.Context, *ResolutionAttemptGuard) {
	if guard := ResolutionAttemptGuardFrom(ctx); guard != nil {
		if pinned, _ := ctx.Value(resolutionAttemptContextKey).(*ResolutionAttemptGuard); pinned != guard {
			ctx = WithResolutionAttemptGuard(ctx, guard)
		}
		return ctx, guard
	}

	meta := ResponseMetaFrom(ctx)
	if meta == nil {
		meta = new(ResponseMeta)
		ctx = WithResponseMeta(ctx, meta)
	}
	guard := meta.EnsureResolutionAttemptGuard()
	return WithResolutionAttemptGuard(ctx, guard), guard
}

// BeginResolutionAttempt records an attempt in the current request tree. A
// missing guard is tolerated for low-level callers that intentionally operate
// outside a middleware request.
func BeginResolutionAttempt(ctx context.Context, q dns.Question, endpoint, transport string) error {
	if guard := ResolutionAttemptGuardFrom(ctx); guard != nil {
		return guard.Begin(q, endpoint, transport)
	}
	return nil
}
