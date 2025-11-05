package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// Chaos provides system information via CHAOS class queries
// Unlike traditional implementations, we provide extended telemetry.
type Chaos struct {
	mu sync.RWMutex

	// Dynamic fields that can change
	startTime  time.Time
	queryCount uint64

	// Static fields initialized once
	enabled     bool
	identity    string
	version     string
	platform    string
	fingerprint string
}

// New creates a new Chaos middleware with extended telemetry.
func New(cfg *config.Config) *Chaos {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "sdns-server"
	}

	// Create a unique server fingerprint
	h := sha256.New()
	h.Write([]byte(hostname))
	h.Write([]byte(cfg.ServerVersion()))
	fmt.Fprintf(h, "%d", os.Getpid())
	fingerprint := hex.EncodeToString(h.Sum(nil))[:16]

	return &Chaos{
		enabled:     cfg.Chaos,
		startTime:   time.Now(),
		identity:    hostname,
		version:     cfg.ServerVersion(),
		platform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		fingerprint: fingerprint,
	}
}

// (*Chaos).Name name returns the middleware name.
func (c *Chaos) Name() string { return name }

// (*Chaos).ServeDNS serveDNS handles CHAOS class queries with extended information.
func (c *Chaos) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if !c.enabled {
		ch.Next(ctx)
		return
	}

	w, req := ch.Writer, ch.Request

	// We only handle CHAOS TXT queries
	if len(req.Question) == 0 || req.Question[0].Qclass != dns.ClassCHAOS {
		ch.Next(ctx)
		return
	}

	q := req.Question[0]
	if q.Qtype != dns.TypeTXT {
		ch.Next(ctx)
		return
	}

	// Increment query counter
	c.mu.Lock()
	c.queryCount++
	c.mu.Unlock()

	var answer *dns.TXT

	switch q.Name {
	case "version.bind.", "version.server.":
		answer = c.makeVersion(q.Name)

	case "hostname.bind.", "id.server.":
		answer = c.makeIdentity(q.Name)

	case "uptime.bind.", "uptime.server.":
		answer = c.makeUptime(q.Name)

	case "platform.bind.", "platform.server.":
		answer = c.makePlatform(q.Name)

	case "fingerprint.bind.", "fingerprint.server.":
		answer = c.makeFingerprint(q.Name)

	case "stats.bind.", "stats.server.":
		answer = c.makeStats(q.Name)

	default:
		// Unknown CHAOS query - pass through
		ch.Next(ctx)
		return
	}

	// Build and send response
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Answer = []dns.RR{answer}

	_ = w.WriteMsg(resp)
	ch.Cancel()
}

// makeVersion creates version response.
func (c *Chaos) makeVersion(name string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    0,
		},
		Txt: []string{fmt.Sprintf("SDNS v%s", c.version)},
	}
}

// makeIdentity creates hostname/identity response.
func (c *Chaos) makeIdentity(name string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    0,
		},
		Txt: []string{c.identity},
	}
}

// makeUptime creates uptime response.
func (c *Chaos) makeUptime(name string) *dns.TXT {
	uptime := time.Since(c.startTime)
	uptimeStr := fmt.Sprintf("%dd%dh%dm%ds",
		int(uptime.Hours())/24,
		int(uptime.Hours())%24,
		int(uptime.Minutes())%60,
		int(uptime.Seconds())%60,
	)

	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    0,
		},
		Txt: []string{uptimeStr},
	}
}

// makePlatform creates platform information response.
func (c *Chaos) makePlatform(name string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    0,
		},
		Txt: []string{c.platform},
	}
}

// makeFingerprint creates unique server fingerprint response.
func (c *Chaos) makeFingerprint(name string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    0,
		},
		Txt: []string{c.fingerprint},
	}
}

// makeStats creates statistics response.
func (c *Chaos) makeStats(name string) *dns.TXT {
	c.mu.RLock()
	count := c.queryCount
	c.mu.RUnlock()

	stats := fmt.Sprintf("queries:%d uptime:%.0fs", count, time.Since(c.startTime).Seconds())

	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    0,
		},
		Txt: []string{stats},
	}
}

const name = "chaos"
