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
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// testConfig creates a config with the given version for testing.
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
	if c == nil {
		t.Fatalf("c is nil")
	}
	if !(c.enabled) {
		t.Errorf("c.enabled is false")
	}
	if !reflect.DeepEqual("1.5.0", c.version) {
		t.Errorf("c.version = %v, want %v", c.version, "1.5.0")
	}
	if len(c.identity) == 0 {
		t.Errorf("c.identity is empty")
	}
	if len(c.platform) == 0 {
		t.Errorf("c.platform is empty")
	}
	if len(c.fingerprint) == 0 {
		t.Errorf("c.fingerprint is empty")
	}
	if !reflect.DeepEqual(16, len(c.fingerprint)) {
		t.Errorf("len(c.fingerprint) = %v, want %v", len(c.fingerprint), 16)
	} // SHA256 truncated to 16 chars
	if !reflect.DeepEqual("chaos", c.Name()) {
		t.Errorf("c.Name() = %v, want %v", c.Name(), "chaos")
	}
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
	if w.Written() {
		t.Errorf("w.Written() is true")
	}
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
	if w.Written() {
		t.Errorf("w.Written() is true")
	}
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
	if w.Written() {
		t.Errorf("w.Written() is true")
	}
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			if !reflect.DeepEqual(qname, txt.Header().Name) {
				t.Errorf("txt.Header().Name = %v, want %v", txt.Header().Name, qname)
			}
			if !reflect.DeepEqual(uint16(dns.ClassCHAOS), txt.Header().Class) {
				t.Errorf("txt.Header().Class = %v, want %v", txt.Header().Class, uint16(dns.ClassCHAOS))
			}
			if !reflect.DeepEqual(uint32(0), txt.Header().Ttl) {
				t.Errorf("txt.Header().Ttl = %v, want %v", txt.Header().Ttl, uint32(0))
			}
			if len(txt.Txt) != 1 {
				t.Errorf("len(txt.Txt) = %d, want %d", len(txt.Txt), 1)
			}
			if !reflect.DeepEqual("SDNS v1.5.0", txt.Txt[0]) {
				t.Errorf("txt.Txt[0] = %v, want %v", txt.Txt[0], "SDNS v1.5.0")
			}
			if !(resp.Authoritative) {
				t.Errorf("resp.Authoritative is false")
			}
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			if !reflect.DeepEqual(qname, txt.Header().Name) {
				t.Errorf("txt.Header().Name = %v, want %v", txt.Header().Name, qname)
			}
			if len(txt.Txt) != 1 {
				t.Errorf("len(txt.Txt) = %d, want %d", len(txt.Txt), 1)
			}
			if len(txt.Txt[0]) == 0 {
				t.Errorf("txt.Txt[0] is empty")
			}
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			if !reflect.DeepEqual(qname, txt.Header().Name) {
				t.Errorf("txt.Header().Name = %v, want %v", txt.Header().Name, qname)
			}
			if len(txt.Txt) != 1 {
				t.Errorf("len(txt.Txt) = %d, want %d", len(txt.Txt), 1)
			}
			// Should contain days, hours, minutes, seconds format
			if !strings.Contains(txt.Txt[0], "d") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "d")
			}
			if !strings.Contains(txt.Txt[0], "h") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "h")
			}
			if !strings.Contains(txt.Txt[0], "m") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "m")
			}
			if !strings.Contains(txt.Txt[0], "s") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "s")
			}
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			if !reflect.DeepEqual(qname, txt.Header().Name) {
				t.Errorf("txt.Header().Name = %v, want %v", txt.Header().Name, qname)
			}
			if len(txt.Txt) != 1 {
				t.Errorf("len(txt.Txt) = %d, want %d", len(txt.Txt), 1)
			}
			// Should contain OS/ARCH format
			if !strings.Contains(txt.Txt[0], "/") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "/")
			}
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			if !reflect.DeepEqual(qname, txt.Header().Name) {
				t.Errorf("txt.Header().Name = %v, want %v", txt.Header().Name, qname)
			}
			if len(txt.Txt) != 1 {
				t.Errorf("len(txt.Txt) = %d, want %d", len(txt.Txt), 1)
			}
			if !reflect.DeepEqual(16, len(txt.Txt[0])) {
				t.Errorf("len(txt.Txt[0]) = %v, want %v", len(txt.Txt[0]), 16)
			}
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			if !reflect.DeepEqual(qname, txt.Header().Name) {
				t.Errorf("txt.Header().Name = %v, want %v", txt.Header().Name, qname)
			}
			if len(txt.Txt) != 1 {
				t.Errorf("len(txt.Txt) = %d, want %d", len(txt.Txt), 1)
			}
			// Should contain queries and uptime
			if !strings.Contains(txt.Txt[0], "queries:") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "queries:")
			}
			if !strings.Contains(txt.Txt[0], "uptime:") {
				t.Errorf("%q does not contain %q", txt.Txt[0], "uptime:")
			}
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
	if w.Written() {
		t.Errorf("w.Written() is true")
	}
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
	if w.Written() {
		t.Errorf("w.Written() is true")
	}
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

	if !reflect.DeepEqual(uint64(queries), count) {
		t.Errorf("count = %v, want %v", count, uint64(queries))
	} //nolint:gosec // G115 - test value, queries is small
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
			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}

			resp := w.Msg()
			if len(resp.Answer) != 1 {
				t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
			}

			txt := resp.Answer[0].(*dns.TXT)
			// Check that the format matches expected pattern
			uptimeStr := txt.Txt[0]
			if !(strings.HasSuffix(uptimeStr, "s")) {
				t.Errorf("strings.HasSuffix(uptimeStr, 's') is false")
			}
			if !strings.Contains(uptimeStr, "d") {
				t.Errorf("%q does not contain %q", uptimeStr, "d")
			}
			if !strings.Contains(uptimeStr, "h") {
				t.Errorf("%q does not contain %q", uptimeStr, "h")
			}
			if !strings.Contains(uptimeStr, "m") {
				t.Errorf("%q does not contain %q", uptimeStr, "m")
			}
		})
	}
}
