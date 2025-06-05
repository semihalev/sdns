package chaos

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfig creates a config with the given version for testing
func testConfig(chaos bool, version string) *config.Config {
	cfg := &config.Config{
		Chaos: chaos,
	}
	// Use reflection to set private sVersion field for testing
	v := reflect.ValueOf(cfg).Elem()
	f := v.FieldByName("sVersion")
	if f.IsValid() {
		// Make the field settable by using unsafe
		reflect.NewAt(f.Type(), f.Addr().UnsafePointer()).Elem().SetString(version)
	}
	return cfg
}

func TestNew(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)
	require.NotNil(t, c)
	assert.True(t, c.enabled)
	assert.Equal(t, "1.5.0", c.version)
	assert.NotEmpty(t, c.identity)
	assert.NotEmpty(t, c.platform)
	assert.NotEmpty(t, c.fingerprint)
	assert.Equal(t, 16, len(c.fingerprint)) // SHA256 truncated to 16 chars
	assert.Equal(t, "chaos", c.Name())
}

func TestServeDNS_NotEnabled(t *testing.T) {
	cfg := testConfig(false, "1.5.0")

	c := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("version.bind.", dns.TypeTXT)
	req.Question[0].Qclass = dns.ClassCHAOS

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(w, req)

	c.ServeDNS(context.Background(), ch)
	assert.False(t, w.Written())
}

func TestServeDNS_NonChaosClass(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("version.bind.", dns.TypeTXT)
	// Default class is IN, not CHAOS

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(w, req)

	c.ServeDNS(context.Background(), ch)
	assert.False(t, w.Written())
}

func TestServeDNS_NonTXTType(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("version.bind.", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(w, req)

	c.ServeDNS(context.Background(), ch)
	assert.False(t, w.Written())
}

func TestServeDNS_Version(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	tests := []string{"version.bind.", "version.server."}

	for _, qname := range tests {
		t.Run(qname, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			assert.Equal(t, qname, txt.Header().Name)
			assert.Equal(t, uint16(dns.ClassCHAOS), txt.Header().Class)
			assert.Equal(t, uint32(0), txt.Header().Ttl)
			assert.Len(t, txt.Txt, 1)
			assert.Equal(t, "SDNS v1.5.0", txt.Txt[0])
			assert.True(t, resp.Authoritative)
		})
	}
}

func TestServeDNS_Identity(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	tests := []string{"hostname.bind.", "id.server."}

	for _, qname := range tests {
		t.Run(qname, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			assert.Equal(t, qname, txt.Header().Name)
			assert.Len(t, txt.Txt, 1)
			assert.NotEmpty(t, txt.Txt[0])
		})
	}
}

func TestServeDNS_Uptime(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)
	c.startTime = time.Now().Add(-25 * time.Hour) // Set start time to 25 hours ago

	tests := []string{"uptime.bind.", "uptime.server."}

	for _, qname := range tests {
		t.Run(qname, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			assert.Equal(t, qname, txt.Header().Name)
			assert.Len(t, txt.Txt, 1)
			// Should contain days, hours, minutes, seconds format
			assert.Contains(t, txt.Txt[0], "d")
			assert.Contains(t, txt.Txt[0], "h")
			assert.Contains(t, txt.Txt[0], "m")
			assert.Contains(t, txt.Txt[0], "s")
		})
	}
}

func TestServeDNS_Platform(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	tests := []string{"platform.bind.", "platform.server."}

	for _, qname := range tests {
		t.Run(qname, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			assert.Equal(t, qname, txt.Header().Name)
			assert.Len(t, txt.Txt, 1)
			// Should contain OS/ARCH format
			assert.Contains(t, txt.Txt[0], "/")
		})
	}
}

func TestServeDNS_Fingerprint(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	tests := []string{"fingerprint.bind.", "fingerprint.server."}

	for _, qname := range tests {
		t.Run(qname, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			assert.Equal(t, qname, txt.Header().Name)
			assert.Len(t, txt.Txt, 1)
			assert.Equal(t, 16, len(txt.Txt[0]))
		})
	}
}

func TestServeDNS_Stats(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	tests := []string{"stats.bind.", "stats.server."}

	for _, qname := range tests {
		t.Run(qname, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			assert.Equal(t, qname, txt.Header().Name)
			assert.Len(t, txt.Txt, 1)
			// Should contain queries and uptime
			assert.Contains(t, txt.Txt[0], "queries:")
			assert.Contains(t, txt.Txt[0], "uptime:")
		})
	}
}

func TestServeDNS_UnknownQuery(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("unknown.bind.", dns.TypeTXT)
	req.Question[0].Qclass = dns.ClassCHAOS

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(w, req)

	c.ServeDNS(context.Background(), ch)
	assert.False(t, w.Written())
}

func TestServeDNS_EmptyQuestion(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	req := new(dns.Msg)
	// No question set

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(w, req)

	c.ServeDNS(context.Background(), ch)
	assert.False(t, w.Written())
}

func TestQueryCounting(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	// Run multiple queries concurrently
	var wg sync.WaitGroup
	queries := 100

	for i := 0; i < queries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := new(dns.Msg)
			req.SetQuestion("version.bind.", dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
		}()
	}

	wg.Wait()

	// Check query count
	c.mu.RLock()
	count := c.queryCount
	c.mu.RUnlock()

	assert.Equal(t, uint64(queries), count)
}

func TestUptimeFormatting(t *testing.T) {
	cfg := testConfig(true, "1.5.0")

	c := New(cfg)

	// Test various uptime durations
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "0d0h0m30s"},
		{90 * time.Second, "0d0h1m30s"},
		{1 * time.Hour, "0d1h0m0s"},
		{25 * time.Hour, "1d1h0m0s"},
		{49*time.Hour + 30*time.Minute + 45*time.Second, "2d1h30m45s"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			c.startTime = time.Now().Add(-tt.duration)

			req := new(dns.Msg)
			req.SetQuestion("uptime.bind.", dns.TypeTXT)
			req.Question[0].Qclass = dns.ClassCHAOS

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{c})
			ch.Reset(w, req)

			c.ServeDNS(context.Background(), ch)
			require.True(t, w.Written())

			resp := w.Msg()
			require.Len(t, resp.Answer, 1)

			txt := resp.Answer[0].(*dns.TXT)
			// Check that the format matches expected pattern
			uptimeStr := txt.Txt[0]
			assert.True(t, strings.HasSuffix(uptimeStr, "s"))
			assert.Contains(t, uptimeStr, "d")
			assert.Contains(t, uptimeStr, "h")
			assert.Contains(t, uptimeStr, "m")
		})
	}
}
