package dnsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// Client is a high-level, dial-per-Exchange DNS client for callers that
// don't maintain their own connection pool — the forwarder, failover,
// and the config IPv6 probe. The resolver hot path uses Conn directly
// so it keeps its own pooling, circuit breaker and retry policy.
//
// The zero value with Proto unset behaves as plain UDP. The question-
// section guard is on by default; the response transaction ID is always
// validated.
type Client struct {
	Proto     string        // "udp" | "tcp" | "tcp-tls" | "doh"; empty means "udp"
	Timeout   time.Duration // per-exchange dial+read+write budget; 0 means none
	TLSConfig *tls.Config   // DoT (tcp-tls) server config
	DoHURL    string        // DoH endpoint URL
	DoHClient *http.Client  // DoH HTTP client (reused transport / HTTP2 pool)

	// SkipQuestionCheck disables the response question-section guard.
	// The guard is on by default; leave this false unless a caller has
	// a specific reason to accept mismatched questions.
	SkipQuestionCheck bool
}

// Exchange sends req to addr over c.Proto and returns the validated
// response. A truncated UDP answer transparently retries over TCP.
func (c *Client) Exchange(ctx context.Context, req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	proto := c.Proto
	if proto == "" {
		proto = "udp"
	}

	if proto == "doh" {
		t := time.Now()
		resp, err := dohExchange(ctx, req, c.DoHURL, c.DoHClient)
		rtt := time.Since(t)
		if err != nil {
			return nil, rtt, err
		}
		if !c.SkipQuestionCheck && len(req.Question) > 0 && !QuestionMatches(req.Question[0], resp.Question) {
			return resp, rtt, ErrQuestion
		}
		return resp, rtt, nil
	}

	co, err := c.dial(ctx, proto, addr)
	if err != nil {
		return nil, 0, err
	}

	c.setDeadline(ctx, co)

	resp, rtt, err := co.Exchange(req)
	_ = co.Close()
	// (*Conn).Exchange already enforces the question guard. When a caller
	// opts out, tolerate only that specific error and keep the response;
	// every other error (ID mismatch, read failure) is still fatal.
	toleratedQuestionMismatch := c.SkipQuestionCheck && errors.Is(err, ErrQuestion)
	if err != nil && !toleratedQuestionMismatch {
		return nil, rtt, err
	}

	if resp != nil && resp.Truncated && proto == "udp" {
		tcp := *c
		tcp.Proto = "tcp"
		return tcp.Exchange(ctx, req, addr)
	}

	return resp, rtt, nil
}

// dial opens a connection to addr for proto and wraps it in a Conn.
func (c *Client) dial(ctx context.Context, proto, addr string) (*Conn, error) {
	d := net.Dialer{Timeout: c.Timeout}

	switch proto {
	case "tcp-tls":
		conn, err := (&tls.Dialer{NetDialer: &d, Config: c.TLSConfig}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn}, nil
	case "tcp":
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn}, nil
	default: // udp
		conn, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn}, nil
	}
}

// setDeadline applies the tighter of c.Timeout and the context deadline
// to the connection's read/write operations.
func (c *Client) setDeadline(ctx context.Context, co *Conn) {
	var deadline time.Time
	if c.Timeout > 0 {
		deadline = time.Now().Add(c.Timeout)
	}
	if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
		deadline = d
	}
	if !deadline.IsZero() {
		_ = co.SetDeadline(deadline)
	}
}
