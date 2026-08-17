package hostsfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func TestNew(t *testing.T) {
	// Test with empty config
	cfg := &config.Config{}
	h := New(cfg)
	if h != nil {
		t.Errorf("h = %v, want nil", h)
	}

	// Test with non-existent file
	cfg.HostsFile = "/non/existent/file"
	h = New(cfg)
	if h != nil {
		t.Errorf("h = %v, want nil", h)
	}

	// Test with valid file
	tmpFile := createTempHostsFile(t, "127.0.0.1 localhost")
	defer os.Remove(tmpFile)

	cfg.HostsFile = tmpFile
	h = New(cfg)
	if h == nil {
		t.Fatalf("h is nil")
	}
	if !reflect.DeepEqual(tmpFile, h.path) {
		t.Errorf("h.path = %v, want %v", h.path, tmpFile)
	}
	if !reflect.DeepEqual(uint32(600), h.ttl) {
		t.Errorf("h.ttl = %v, want %v", h.ttl, uint32(600))
	}
	if !reflect.DeepEqual("hostsfile", h.Name()) {
		t.Errorf("h.Name() = %v, want %v", h.Name(), "hostsfile")
	}
}

func TestServeDNS_Basic(t *testing.T) {
	content := `
127.0.0.1 localhost
::1 localhost
192.168.1.1 router.local router
10.0.0.1 server.example.com server
# Comment line
192.168.1.100 *.wildcard.local
`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name     string
		qname    string
		qtype    uint16
		expected int
		found    bool
	}{
		{"A record for localhost", "localhost.", dns.TypeA, 1, true},
		{"AAAA record for localhost", "localhost.", dns.TypeAAAA, 1, true},
		{"A record for router alias", "router.", dns.TypeA, 1, true},
		{"A record for server", "server.example.com.", dns.TypeA, 1, true},
		{"Non-existent host", "notfound.local.", dns.TypeA, 0, false},
		{"PTR for 127.0.0.1", "1.0.0.127.in-addr.arpa.", dns.TypePTR, 1, true},
		{"Wildcard match", "test.wildcard.local.", dns.TypeA, 1, true},
		{"MX query for existing host", "localhost.", dns.TypeMX, 0, true}, // NODATA
		{"TXT query for non-existent", "notfound.", dns.TypeTXT, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tt.qname, tt.qtype)

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{h})
			ch.Reset(w, req)

			h.ServeDNS(context.Background(), ch)

			if tt.found {
				if !(w.Written()) {
					t.Fatalf("w.Written() is false")
				}
				resp := w.Msg()
				if !reflect.DeepEqual(tt.expected, len(resp.Answer)) {
					t.Errorf("len(resp.Answer) = %v, want %v", len(resp.Answer), tt.expected)
				}
				if tt.expected > 0 {
					if !(resp.Authoritative) {
						t.Errorf("resp.Authoritative is false")
					}
					if !(resp.RecursionAvailable) {
						t.Errorf("resp.RecursionAvailable is false")
					}
				}
			} else if w.Written() {
				// Should pass through unanswered.
				t.Errorf("w.Written() is true")
			}
		})
	}
}

// TestServeDNS_PreservesHeaderBits guards the manual response
// construction that bypasses miekg/dns SetReply. CheckingDisabled
// and RecursionDesired are wire-visible header bits, and CD in
// particular is used as part of the cache key elsewhere in sdns —
// a clean-bit regression would silently poison cache lookups.
func TestServeDNS_PreservesHeaderBits(t *testing.T) {
	content := `127.0.0.1 localhost`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{path: tmpFile, ttl: 300}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name string
		cd   bool
		rd   bool
	}{
		{"CD off / RD off", false, false},
		{"CD off / RD on", false, true},
		{"CD on  / RD on", true, true},
		{"CD on  / RD off", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("localhost.", dns.TypeA)
			req.CheckingDisabled = tc.cd
			req.RecursionDesired = tc.rd

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{h})
			ch.Reset(w, req)
			h.ServeDNS(context.Background(), ch)

			if !(w.Written()) {
				t.Fatalf("w.Written() is false")
			}
			resp := w.Msg()
			if resp == nil {
				t.Fatalf("resp is nil")
			}

			if !reflect.DeepEqual(tc.cd, resp.CheckingDisabled) {
				t.Errorf("%s: resp.CheckingDisabled = %v, want %v", "CheckingDisabled bit must round-trip", resp.CheckingDisabled, tc.cd)
			}
			if !reflect.DeepEqual(tc.rd, resp.RecursionDesired) {
				t.Errorf("%s: resp.RecursionDesired = %v, want %v", "RecursionDesired bit must round-trip", resp.RecursionDesired, tc.rd)
			}
			if !(resp.Response) {
				t.Errorf("%s: resp.Response is false", "Response bit must be set")
			}
			if !reflect.DeepEqual(req.Id, resp.Id) {
				t.Errorf("resp.Id = %v, want %v", resp.Id, req.Id)
			}
		})
	}
}

func TestServeDNS_EdgeCases(t *testing.T) {
	content := `127.0.0.1 localhost`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test with empty question
	req := new(dns.Msg)
	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{h})
	ch.Reset(w, req)

	h.ServeDNS(context.Background(), ch)
	if w.Written() {
		t.Errorf("w.Written() is true")
	}
}

func TestLookupFunctions(t *testing.T) {
	content := `
127.0.0.1 localhost local
::1 localhost
192.168.1.1 host1.local
192.168.1.2 host2.local alias2
10.0.0.1 *.wildcard.com
2001:db8::1 ipv6.host.com
`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	db := h.getDB()

	// Test lookupA
	t.Run("lookupA", func(t *testing.T) {
		// Direct lookup
		rrs, found := h.lookupA(db, "localhost")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
		if !reflect.DeepEqual("127.0.0.1", rrs[0].(*dns.A).A.String()) {
			t.Errorf("rrs[0].(*dns.A).A.String() = %v, want %v", rrs[0].(*dns.A).A.String(), "127.0.0.1")
		}

		// Wildcard lookup
		rrs, found = h.lookupA(db, "test.wildcard.com")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
		if !reflect.DeepEqual("10.0.0.1", rrs[0].(*dns.A).A.String()) {
			t.Errorf("rrs[0].(*dns.A).A.String() = %v, want %v", rrs[0].(*dns.A).A.String(), "10.0.0.1")
		}

		// Not found
		rrs, found = h.lookupA(db, "notfound.local")
		if found {
			t.Errorf("found is true")
		}
		if rrs != nil {
			t.Errorf("rrs = %v, want nil", rrs)
		}
	})

	// Test lookupAAAA
	t.Run("lookupAAAA", func(t *testing.T) {
		rrs, found := h.lookupAAAA(db, "localhost")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
		if !reflect.DeepEqual("::1", rrs[0].(*dns.AAAA).AAAA.String()) {
			t.Errorf("rrs[0].(*dns.AAAA).AAAA.String() = %v, want %v", rrs[0].(*dns.AAAA).AAAA.String(), "::1")
		}

		rrs, found = h.lookupAAAA(db, "ipv6.host.com")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
	})

	// Test lookupPTR
	t.Run("lookupPTR", func(t *testing.T) {
		rrs, found := h.lookupPTR(db, "1.0.0.127.in-addr.arpa.")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
		if !reflect.DeepEqual("localhost.", rrs[0].(*dns.PTR).Ptr) {
			t.Errorf("rrs[0].(*dns.PTR).Ptr = %v, want %v", rrs[0].(*dns.PTR).Ptr, "localhost.")
		}

		// Invalid PTR
		rrs, found = h.lookupPTR(db, "invalid.ptr")
		if found {
			t.Errorf("found is true")
		}
		if rrs != nil {
			t.Errorf("rrs = %v, want nil", rrs)
		}
	})

	// Test lookupCNAME
	t.Run("lookupCNAME", func(t *testing.T) {
		rrs, found := h.lookupCNAME(db, "local")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
		if !reflect.DeepEqual("localhost.", rrs[0].(*dns.CNAME).Target) {
			t.Errorf("rrs[0].(*dns.CNAME).Target = %v, want %v", rrs[0].(*dns.CNAME).Target, "localhost.")
		}

		rrs, found = h.lookupCNAME(db, "alias2")
		if !(found) {
			t.Errorf("found is false")
		}
		if len(rrs) != 1 {
			t.Errorf("len(rrs) = %d, want %d", len(rrs), 1)
		}
		if !reflect.DeepEqual("host2.local.", rrs[0].(*dns.CNAME).Target) {
			t.Errorf("rrs[0].(*dns.CNAME).Target = %v, want %v", rrs[0].(*dns.CNAME).Target, "host2.local.")
		}
	})

	// Test hostExists
	t.Run("hostExists", func(t *testing.T) {
		if !(h.hostExists(db, "localhost")) {
			t.Errorf("h.hostExists(db, 'localhost') is false")
		}
		if !(h.hostExists(db, "local")) {
			t.Errorf("h.hostExists(db, 'local') is false")
		} // alias
		if !(h.hostExists(db, "test.wildcard.com")) {
			t.Errorf("h.hostExists(db, 'test.wildcard.com') is false")
		} // wildcard
		if h.hostExists(db, "notfound.com") {
			t.Errorf("h.hostExists(db, 'notfound.com') is true")
		}
	})
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		line            string
		expectedIP      string
		expectedHosts   []string
		expectedComment string
		shouldParse     bool
	}{
		{
			"127.0.0.1 localhost",
			"127.0.0.1",
			[]string{"localhost"},
			"",
			true,
		},
		{
			"192.168.1.1    host1   host2  # This is a comment",
			"192.168.1.1",
			[]string{"host1", "host2"},
			"This is a comment",
			true,
		},
		{
			"::1 ipv6host",
			"::1",
			[]string{"ipv6host"},
			"",
			true,
		},
		{
			"# Comment only line",
			"",
			nil,
			"",
			false,
		},
		{
			"invalid.ip.address host",
			"",
			nil,
			"",
			false,
		},
		{
			"127.0.0.1", // No hostname
			"",
			nil,
			"",
			false,
		},
		{
			"", // Empty line
			"",
			nil,
			"",
			false,
		},
		{
			"fe80::1%eth0 ipv6-with-zone",
			"fe80::1",
			[]string{"ipv6-with-zone"},
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			ip, hosts, comment := parseLine(tt.line)

			if tt.shouldParse {
				if ip == nil {
					t.Fatalf("ip is nil")
				}
				if !reflect.DeepEqual(tt.expectedIP, ip.String()) {
					t.Errorf("ip.String() = %v, want %v", ip.String(), tt.expectedIP)
				}
				if !reflect.DeepEqual(tt.expectedHosts, hosts) {
					t.Errorf("hosts = %v, want %v", hosts, tt.expectedHosts)
				}
				if !reflect.DeepEqual(tt.expectedComment, comment) {
					t.Errorf("comment = %v, want %v", comment, tt.expectedComment)
				}
			} else {
				if ip != nil {
					t.Errorf("ip = %v, want nil", ip)
				}
				if hosts != nil {
					t.Errorf("hosts = %v, want nil", hosts)
				}
			}
		})
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		match   bool
	}{
		{"*.example.com", "test.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "sub.test.example.com", true},
		{"*.example.com", "example.org", false},
		{"*.example.com", "com", false},
		{"test.com", "test.com", false}, // Not a wildcard
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s matches %s", tt.pattern, tt.name), func(t *testing.T) {
			if !reflect.DeepEqual(tt.match, matchWildcard(tt.pattern, tt.name)) {
				t.Errorf("matchWildcard(tt.pattern, tt.name) = %v, want %v", matchWildcard(tt.pattern, tt.name), tt.match)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	content := `
127.0.0.1 localhost
192.168.1.1 host1 alias1 alias2
10.0.0.1 *.wildcard.local
::1 localhost
invalid line
300.300.300.300 invalid-ip
`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}

	err := h.load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	db := h.getDB()
	if !reflect.DeepEqual(int64(4), atomic.LoadInt64(&db.stats.entries)) {
		t.Errorf("atomic.LoadInt64(&db.stats.entries) = %v, want %v", atomic.LoadInt64(&db.stats.entries), int64(4))
	} // localhost, host1, alias1, alias2
	if !reflect.DeepEqual(int64(1), atomic.LoadInt64(&db.stats.wildcards)) {
		t.Errorf("atomic.LoadInt64(&db.stats.wildcards) = %v, want %v", atomic.LoadInt64(&db.stats.wildcards), int64(1))
	}

	// Check reverse mappings
	if !slices.Contains(db.reverse["127.0.0.1"], "localhost") {
		t.Errorf("reverse[127.0.0.1] %v does not contain localhost", db.reverse["127.0.0.1"])
	}
	if !slices.Contains(db.reverse["192.168.1.1"], "host1") {
		t.Errorf("reverse[192.168.1.1] %v does not contain host1", db.reverse["192.168.1.1"])
	}

	// Check aliases
	entry := db.hosts["host1"]
	if !slices.Contains(entry.Aliases, "alias1") {
		t.Errorf("aliases %v do not contain alias1", entry.Aliases)
	}
	if !slices.Contains(entry.Aliases, "alias2") {
		t.Errorf("aliases %v do not contain alias2", entry.Aliases)
	}
}

func TestFileWatcher(t *testing.T) {
	// Skip on CI/short tests as file watching can be flaky
	if testing.Short() {
		t.Skip("Skipping file watcher test in short mode")
	}

	content := `127.0.0.1 localhost`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	cfg := &config.Config{HostsFile: tmpFile}
	h := New(cfg)
	if h == nil {
		t.Fatalf("h is nil")
	}
	if h.watcher == nil {
		t.Fatalf("h.watcher is nil")
	}

	// Initial state
	db := h.getDB()
	if !reflect.DeepEqual(int64(1), atomic.LoadInt64(&db.stats.entries)) {
		t.Errorf("atomic.LoadInt64(&db.stats.entries) = %v, want %v", atomic.LoadInt64(&db.stats.entries), int64(1))
	}

	// Update file
	newContent := `
127.0.0.1 localhost
192.168.1.1 newhost
`
	err := os.WriteFile(tmpFile, []byte(newContent), 0644) //nolint:gosec // G306 - test file
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for reload with timeout
	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for file reload")
		case <-ticker.C:
			db = h.getDB()
			if atomic.LoadInt64(&db.stats.entries) == 2 {
				// Success!
				return
			}
		}
	}
}

func TestStats(t *testing.T) {
	content := `
127.0.0.1 localhost
192.168.1.1 host1
10.0.0.1 *.wildcard.com
`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate some lookups
	db := h.getDB()
	atomic.AddUint64(&db.stats.lookups, 100)
	atomic.AddUint64(&db.stats.hits, 75)

	stats := h.Stats()
	if !reflect.DeepEqual(int64(2), stats["entries"]) {
		t.Errorf("stats['entries'] = %v, want %v", stats["entries"], int64(2))
	}
	if !reflect.DeepEqual(int64(1), stats["wildcards"]) {
		t.Errorf("stats['wildcards'] = %v, want %v", stats["wildcards"], int64(1))
	}
	if !reflect.DeepEqual(uint64(100), stats["lookups"]) {
		t.Errorf("stats['lookups'] = %v, want %v", stats["lookups"], uint64(100))
	}
	if !reflect.DeepEqual(uint64(75), stats["hits"]) {
		t.Errorf("stats['hits'] = %v, want %v", stats["hits"], uint64(75))
	}
	if s, _ := stats["reload_time"].(string); s == "" {
		t.Errorf("stats['reload_time'] is empty")
	}
}

func TestConcurrentAccess(t *testing.T) {
	content := `
127.0.0.1 localhost
192.168.1.1 host1
`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Concurrent lookups
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			req := new(dns.Msg)
			if i%2 == 0 {
				req.SetQuestion("localhost.", dns.TypeA)
			} else {
				req.SetQuestion("host1.", dns.TypeA)
			}

			w := mock.NewWriter("tcp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{h})
			ch.Reset(w, req)

			h.ServeDNS(context.Background(), ch)
			if !(w.Written()) {
				t.Errorf("w.Written() is false")
			}
		}(i)
	}

	// Concurrent reload
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			err := h.load()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Verify stats - get final DB after all reloads
	db := h.getDB()
	// Since we do concurrent reloads, the DB might have been replaced
	// Just verify we have the expected number of entries
	if !reflect.DeepEqual(int64(2), atomic.LoadInt64(&db.stats.entries)) {
		t.Errorf("atomic.LoadInt64(&db.stats.entries) = %v, want %v", atomic.LoadInt64(&db.stats.entries), int64(2))
	}
}

func TestMultipleIPs(t *testing.T) {
	content := `
127.0.0.1 multi.local
127.0.0.2 multi.local
::1 multi.local
::2 multi.local
`
	tmpFile := createTempHostsFile(t, content)
	defer os.Remove(tmpFile)

	h := &Hostsfile{
		path: tmpFile,
		ttl:  300,
	}
	if err := h.load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test A records
	req := new(dns.Msg)
	req.SetQuestion("multi.local.", dns.TypeA)

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{h})
	ch.Reset(w, req)

	h.ServeDNS(context.Background(), ch)
	if !(w.Written()) {
		t.Fatalf("w.Written() is false")
	}

	resp := w.Msg()
	if len(resp.Answer) != 2 {
		t.Errorf("len(resp.Answer) = %d, want %d", len(resp.Answer), 2)
	}

	// Test AAAA records
	req.SetQuestion("multi.local.", dns.TypeAAAA)
	w = mock.NewWriter("tcp", "127.0.0.1:0")
	ch.Reset(w, req)

	h.ServeDNS(context.Background(), ch)
	if !(w.Written()) {
		t.Fatalf("w.Written() is false")
	}

	resp = w.Msg()
	if len(resp.Answer) != 2 {
		t.Errorf("len(resp.Answer) = %d, want %d", len(resp.Answer), 2)
	}
}

// Helper function to create temporary hosts file.
func createTempHostsFile(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "hosts")

	// Normalize line endings for Windows
	if runtime.GOOS == "windows" {
		content = strings.ReplaceAll(content, "\n", "\r\n")
	}

	err := os.WriteFile(tmpFile, []byte(content), 0644) //nolint:gosec // G306 - test file
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return tmpFile
}
