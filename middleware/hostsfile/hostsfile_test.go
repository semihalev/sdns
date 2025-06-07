package hostsfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	// Test with empty config
	cfg := &config.Config{}
	h := New(cfg)
	assert.Nil(t, h)

	// Test with non-existent file
	cfg.HostsFile = "/non/existent/file"
	h = New(cfg)
	assert.Nil(t, h)

	// Test with valid file
	tmpFile := createTempHostsFile(t, "127.0.0.1 localhost")
	defer os.Remove(tmpFile)

	cfg.HostsFile = tmpFile
	h = New(cfg)
	require.NotNil(t, h)
	assert.Equal(t, tmpFile, h.path)
	assert.Equal(t, uint32(600), h.ttl)
	assert.Equal(t, "hostsfile", h.Name())
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
	require.NoError(t, h.load())

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
				require.True(t, w.Written())
				resp := w.Msg()
				assert.Equal(t, tt.expected, len(resp.Answer))
				if tt.expected > 0 {
					assert.True(t, resp.Authoritative)
					assert.True(t, resp.RecursionAvailable)
				}
			} else {
				// Should pass through
				assert.False(t, w.Written())
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
	require.NoError(t, h.load())

	// Test with empty question
	req := new(dns.Msg)
	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{h})
	ch.Reset(w, req)

	h.ServeDNS(context.Background(), ch)
	assert.False(t, w.Written())
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
	require.NoError(t, h.load())
	db := h.getDB()

	// Test lookupA
	t.Run("lookupA", func(t *testing.T) {
		// Direct lookup
		rrs, found := h.lookupA(db, "localhost")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
		assert.Equal(t, "127.0.0.1", rrs[0].(*dns.A).A.String())

		// Wildcard lookup
		rrs, found = h.lookupA(db, "test.wildcard.com")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
		assert.Equal(t, "10.0.0.1", rrs[0].(*dns.A).A.String())

		// Not found
		rrs, found = h.lookupA(db, "notfound.local")
		assert.False(t, found)
		assert.Nil(t, rrs)
	})

	// Test lookupAAAA
	t.Run("lookupAAAA", func(t *testing.T) {
		rrs, found := h.lookupAAAA(db, "localhost")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
		assert.Equal(t, "::1", rrs[0].(*dns.AAAA).AAAA.String())

		rrs, found = h.lookupAAAA(db, "ipv6.host.com")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
	})

	// Test lookupPTR
	t.Run("lookupPTR", func(t *testing.T) {
		rrs, found := h.lookupPTR(db, "1.0.0.127.in-addr.arpa.")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
		assert.Equal(t, "localhost.", rrs[0].(*dns.PTR).Ptr)

		// Invalid PTR
		rrs, found = h.lookupPTR(db, "invalid.ptr")
		assert.False(t, found)
		assert.Nil(t, rrs)
	})

	// Test lookupCNAME
	t.Run("lookupCNAME", func(t *testing.T) {
		rrs, found := h.lookupCNAME(db, "local")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
		assert.Equal(t, "localhost.", rrs[0].(*dns.CNAME).Target)

		rrs, found = h.lookupCNAME(db, "alias2")
		assert.True(t, found)
		assert.Len(t, rrs, 1)
		assert.Equal(t, "host2.local.", rrs[0].(*dns.CNAME).Target)
	})

	// Test hostExists
	t.Run("hostExists", func(t *testing.T) {
		assert.True(t, h.hostExists(db, "localhost"))
		assert.True(t, h.hostExists(db, "local"))             // alias
		assert.True(t, h.hostExists(db, "test.wildcard.com")) // wildcard
		assert.False(t, h.hostExists(db, "notfound.com"))
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
				require.NotNil(t, ip)
				assert.Equal(t, tt.expectedIP, ip.String())
				assert.Equal(t, tt.expectedHosts, hosts)
				assert.Equal(t, tt.expectedComment, comment)
			} else {
				assert.Nil(t, ip)
				assert.Nil(t, hosts)
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
			assert.Equal(t, tt.match, matchWildcard(tt.pattern, tt.name))
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
	require.NoError(t, err)

	db := h.getDB()
	assert.Equal(t, int64(4), atomic.LoadInt64(&db.stats.entries)) // localhost, host1, alias1, alias2
	assert.Equal(t, int64(1), atomic.LoadInt64(&db.stats.wildcards))

	// Check reverse mappings
	assert.Contains(t, db.reverse["127.0.0.1"], "localhost")
	assert.Contains(t, db.reverse["192.168.1.1"], "host1")

	// Check aliases
	entry := db.hosts["host1"]
	assert.Contains(t, entry.Aliases, "alias1")
	assert.Contains(t, entry.Aliases, "alias2")
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
	require.NotNil(t, h)
	require.NotNil(t, h.watcher)

	// Initial state
	db := h.getDB()
	assert.Equal(t, int64(1), atomic.LoadInt64(&db.stats.entries))

	// Update file
	newContent := `
127.0.0.1 localhost
192.168.1.1 newhost
`
	err := os.WriteFile(tmpFile, []byte(newContent), 0644)
	require.NoError(t, err)

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
	require.NoError(t, h.load())

	// Simulate some lookups
	db := h.getDB()
	atomic.AddUint64(&db.stats.lookups, 100)
	atomic.AddUint64(&db.stats.hits, 75)

	stats := h.Stats()
	assert.Equal(t, int64(2), stats["entries"])
	assert.Equal(t, int64(1), stats["wildcards"])
	assert.Equal(t, uint64(100), stats["lookups"])
	assert.Equal(t, uint64(75), stats["hits"])
	assert.NotEmpty(t, stats["reload_time"])
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
	require.NoError(t, h.load())

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
			assert.True(t, w.Written())
		}(i)
	}

	// Concurrent reload
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			err := h.load()
			assert.NoError(t, err)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Verify stats - get final DB after all reloads
	db := h.getDB()
	// Since we do concurrent reloads, the DB might have been replaced
	// Just verify we have the expected number of entries
	assert.Equal(t, int64(2), atomic.LoadInt64(&db.stats.entries))
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
	require.NoError(t, h.load())

	// Test A records
	req := new(dns.Msg)
	req.SetQuestion("multi.local.", dns.TypeA)

	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{h})
	ch.Reset(w, req)

	h.ServeDNS(context.Background(), ch)
	require.True(t, w.Written())

	resp := w.Msg()
	assert.Len(t, resp.Answer, 2)

	// Test AAAA records
	req.SetQuestion("multi.local.", dns.TypeAAAA)
	w = mock.NewWriter("tcp", "127.0.0.1:0")
	ch.Reset(w, req)

	h.ServeDNS(context.Background(), ch)
	require.True(t, w.Written())

	resp = w.Msg()
	assert.Len(t, resp.Answer, 2)
}

// Helper function to create temporary hosts file
func createTempHostsFile(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "hosts")

	// Normalize line endings for Windows
	if runtime.GOOS == "windows" {
		content = strings.ReplaceAll(content, "\n", "\r\n")
	}

	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	return tmpFile
}
