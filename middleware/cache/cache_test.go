// Package cache provides a high-performance DNS caching middleware for SDNS
package cache

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)
	return r
}

func makeTestConfig() *config.Config {
	cfg := &config.Config{
		Expire:    300,
		CacheSize: 10240,
		Prefetch:  0, // Disable prefetch for tests
		RateLimit: 10,
		Maxdepth:  30,
	}
	cfg.RootServers = []string{"192.5.5.241:53", "192.203.230.10:53"}
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	256 3 8 AwEAAc4qsciJ5MdMUIu4n/pSTsSiU9OCyAanPTe5TcMX4v1hxhpFwiTGQUv3BXT6IAO4litrZKTUaj4vitqHW1+RQsHn3k/gSvt7FwyQwpy0mEnShBgr6RQiGtlBODNY67sTl+W8M/b6SLTAaaDri3BO5u6wrDs149rMELJAdoVBjmXW+zRH3kZzh3lwyTZsYtk7L+3DYbTiiHq+sRB4F9XoBPAz5Psv4q4EiPq07nW3acbW84zTz3CyQUmQkJT9VB1oUKHz6sNoyccqzcMX4q1GHAYpQ7FAXlKMxidoN1Ay5DWANgTmgJXzKhcI2nIZoq1x3yq4814O1LQd9QP68gI37+0=",
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	cfg.Timeout.Duration = 10 * time.Second
	cfg.Directory = filepath.Join(os.TempDir(), "sdns_test_"+time.Now().Format("20060102150405"))

	if !middleware.Ready() {
		middleware.Register("cache", func(cfg *config.Config) middleware.Handler { return New(cfg) })
		middleware.Setup(cfg)
	}

	return cfg
}

func TestNew(t *testing.T) {
	cfg := makeTestConfig()
	c := New(cfg)
	defer c.Stop()

	require.NotNil(t, c)
	assert.Equal(t, "cache", c.Name())
	assert.NotNil(t, c.positive)
	assert.NotNil(t, c.negative)
	assert.Equal(t, cfg.CacheSize, c.config.Size)

	// Clean up
	os.RemoveAll(cfg.Directory)
}

func TestCachePurge(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	// Create a mock handler that returns a response for CHAOS queries
	mockHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		w, req := ch.Writer, ch.Request
		if len(req.Question) == 0 {
			ch.Cancel()
			return
		}

		q := req.Question[0]
		if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL {
			// This is a purge query
			msg := new(dns.Msg)
			msg.SetReply(req)
			msg.Extra = append(msg.Extra, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0},
				Txt: []string{"Purged"},
			})
			_ = w.WriteMsg(msg)
			ch.Cancel()
		}
	})

	// Test purge with valid base64 encoded name
	bqname := base64.StdEncoding.EncodeToString([]byte("A:test.com."))
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(bqname), dns.TypeNULL)
	req.Question[0].Qclass = dns.ClassCHAOS

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c, mockHandler})
	ch.Reset(mw, req)

	c.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())
	assert.Len(t, mw.Msg().Extra, 1)
}

func TestPositiveCache(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	q := req.Question[0]
	key := cache.Key(q)

	// Check cache is empty initially
	entry := c.checkCache(key)
	assert.Nil(t, entry)

	// Create and cache a positive response
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("test.com. 300 IN A 1.2.3.4"))

	c.Set(key, msg)

	// Verify it's in cache
	entry = c.checkCache(key)
	require.NotNil(t, entry)

	// Serve from cache
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())

	resp := mw.Msg()
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, "test.com.", resp.Answer[0].Header().Name)
}

func TestNegativeCache(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("notfound.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	q := req.Question[0]
	key := cache.Key(q)

	// Create and cache a negative response (NXDOMAIN)
	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeNameError)
	msg.Ns = append(msg.Ns, makeRR("com. 900 IN SOA ns1.com. admin.com. 1 7200 3600 1209600 900"))

	c.Set(key, msg)

	// Verify it's in cache (NXDOMAIN goes to positive cache)
	entry := c.checkCache(key)
	require.NotNil(t, entry)

	// NXDOMAIN responses are stored in positive cache with ttl from SOA
	posEntry, found := c.positive.Get(key)
	assert.True(t, found)
	assert.NotNil(t, posEntry)
}

func TestCacheTTL(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Expire = 5       // 5 second minimum TTL
	cfg.CacheSize = 1024 // Meet minimum requirements
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("ttltest.com.", dns.TypeA)

	q := req.Question[0]
	key := cache.Key(q)

	// Create response with 5 second TTL (minimum)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("ttltest.com. 5 IN A 1.2.3.4"))

	c.Set(key, msg)

	// Should be in cache immediately
	entry := c.checkCache(key)
	require.NotNil(t, entry)

	// Wait for expiration (5 seconds plus buffer)
	time.Sleep(5100 * time.Millisecond)

	// Should be expired
	entry = c.checkCache(key)
	assert.Nil(t, entry)
}

func TestCacheDNSSEC(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("secure.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit set

	q := req.Question[0]
	key := cache.Key(q, true) // CD flag

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("secure.com. 300 IN A 1.2.3.4"))
	msg.Answer = append(msg.Answer, makeRR("secure.com. 300 IN RRSIG A 8 2 300 20301231235959 20201231235959 12345 secure.com. fakesig=="))

	c.Set(key, msg)

	// Query without CD bit should not find it
	keyNoCD := cache.Key(q, false)
	entry := c.checkCache(keyNoCD)
	assert.Nil(t, entry)

	// Query with CD bit should find it
	entry = c.checkCache(key)
	assert.NotNil(t, entry)
}

func TestCachePrefetch(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Prefetch = 80 // Prefetch when 80% of TTL passed
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop() // Clean up prefetch workers

	// Just verify prefetch is configured
	if cfg.Prefetch > 0 {
		assert.NotNil(t, c.prefetchQueue)
	}

	// Test basic caching without waiting for prefetch
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("test.com. 300 IN A 1.2.3.4"))

	key := cache.Key(req.Question[0])
	c.Set(key, msg)

	// Verify it's cached
	entry := c.checkCache(key)
	assert.NotNil(t, entry)
}

func TestCacheConcurrency(t *testing.T) {
	cfg := makeTestConfig()
	cfg.CacheSize = 1024 // Meet minimum requirements
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	// Test concurrent Set/Get operations
	const numGoroutines = 10
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				req := new(dns.Msg)
				req.SetQuestion(fmt.Sprintf("test%d.com.", id), dns.TypeA)

				msg := new(dns.Msg)
				msg.SetReply(req)
				msg.Answer = append(msg.Answer, makeRR(fmt.Sprintf("test%d.com. 300 IN A 1.2.3.%d", id, id)))

				key := cache.Key(req.Question[0])

				// Set and get
				c.Set(key, msg)
				c.checkCache(key)
			}
		}(i)
	}

	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}

	// Verify cache has some entries
	stats := c.Stats()
	assert.Contains(t, stats, "positive_size")
}

func TestCacheMetrics(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	// Add some positive entries
	for i := 0; i < 10; i++ {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("test%d.com.", i), dns.TypeA)

		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Answer = append(msg.Answer, makeRR(fmt.Sprintf("test%d.com. 300 IN A 1.2.3.%d", i, i)))

		key := cache.Key(req.Question[0])
		c.Set(key, msg)
	}

	// Add some negative entries
	for i := 0; i < 5; i++ {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("nx%d.com.", i), dns.TypeA)

		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeNameError)

		key := cache.Key(req.Question[0])
		c.Set(key, msg)
	}

	stats := c.Stats()

	assert.Contains(t, stats, "positive_size")
	assert.Contains(t, stats, "negative_size")
	assert.Contains(t, stats, "hits")
	assert.Contains(t, stats, "misses")
}

func TestCacheInvalidation(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	// Add entry
	req := new(dns.Msg)
	req.SetQuestion("invalidate.com.", dns.TypeA)

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("invalidate.com. 300 IN A 1.2.3.4"))

	key := cache.Key(req.Question[0])
	c.Set(key, msg)

	// Verify it's cached
	entry := c.checkCache(key)
	require.NotNil(t, entry)

	// Clear cache by creating new instances
	c.positive = NewPositiveCache(c.config.Size/2, c.config.MinTTL, c.config.MaxTTL, c.metrics)
	c.negative = NewNegativeCache(c.config.Size/2, c.config.MinTTL, c.config.NegativeTTL, c.metrics)

	// Should be gone
	entry = c.checkCache(key)
	assert.Nil(t, entry)
}

func TestCacheEDNS(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	// Test with EDNS0
	req := new(dns.Msg)
	req.SetQuestion("edns.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	opt := req.IsEdns0()
	require.NotNil(t, opt)

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("edns.com. 300 IN A 1.2.3.4"))

	key := cache.Key(req.Question[0])
	c.Set(key, msg)

	// Query with different EDNS buffer size
	req2 := new(dns.Msg)
	req2.SetQuestion("edns.com.", dns.TypeA)
	req2.SetEdns0(512, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(mw, req2)

	c.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())

	// Response should be valid
	resp := mw.Msg()
	require.NotNil(t, resp)
	assert.Len(t, resp.Answer, 1)
	assert.Equal(t, "edns.com.", resp.Answer[0].Header().Name)
}

// Helper function to clean up test directories
func cleanupTestDirs(t *testing.T) {
	pattern := filepath.Join(os.TempDir(), "sdns_test_*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Logf("Failed to glob test directories: %v", err)
		return
	}

	for _, dir := range matches {
		os.RemoveAll(dir)
	}
}
