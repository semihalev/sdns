// Package cache provides a high-performance DNS caching middleware for SDNS
package cache

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
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

	if c == nil {
		t.Fatalf("c is nil")
	}
	if !reflect.DeepEqual("cache", c.Name()) {
		t.Errorf("c.Name() = %v, want %v", c.Name(), "cache")
	}
	if c.positive == nil {
		t.Fatalf("c.positive is nil")
	}
	if c.negative == nil {
		t.Fatalf("c.negative is nil")
	}
	if !reflect.DeepEqual(cfg.CacheSize, c.config.Size) {
		t.Errorf("c.config.Size = %v, want %v", c.config.Size, cfg.CacheSize)
	}

	// Clean up
	os.RemoveAll(cfg.Directory) //nolint:gosec // G104 - test cleanup
}

func TestCachePurge(t *testing.T) {
	cfg := makeTestConfig()
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop()

	// Create a mock handler that returns a response for CHAOS queries
	mockHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		w, req := ch.Writer, ch.Request.Msg()
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
	// The cache is invoked directly, so it must not also sit in the chain:
	// its own ch.Next would then enter it a second time for the same
	// request, and the second entry would wait as a follower on the
	// deduplication generation its own caller still holds. That deadlock
	// resolved only when the wait timed out, fifteen seconds later.
	ch := middleware.NewChain([]middleware.Handler{mockHandler})
	ch.Reset(mw, req)

	c.ServeDNS(context.Background(), ch)
	if !(mw.Written()) {
		t.Errorf("mw.Written() is false")
	}
	if len(mw.Msg().Extra) != 1 {
		t.Errorf("len(mw.Msg().Extra) = %d, want %d", len(mw.Msg().Extra), 1)
	}
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
	if entry != nil {
		t.Errorf("entry = %v, want nil", entry)
	}

	// Create and cache a positive response
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = append(msg.Answer, makeRR("test.com. 300 IN A 1.2.3.4"))

	c.Set(key, msg)

	// Verify it's in cache
	entry = c.checkCache(key)
	if entry == nil {
		t.Fatalf("entry is nil")
	}

	// Serve from cache
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	if !(mw.Written()) {
		t.Errorf("mw.Written() is false")
	}

	resp := mw.Msg()
	if len(resp.Answer) != 1 {
		t.Fatalf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
	}
	if !reflect.DeepEqual("test.com.", resp.Answer[0].Header().Name) {
		t.Errorf("resp.Answer[0].Header().Name = %v, want %v", resp.Answer[0].Header().Name, "test.com.")
	}
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
	if entry == nil {
		t.Fatalf("entry is nil")
	}

	// NXDOMAIN responses are stored in positive cache with ttl from SOA
	posEntry, found := c.positive.Get(key)
	if !(found) {
		t.Errorf("found is false")
	}
	if posEntry == nil {
		t.Fatalf("posEntry is nil")
	}
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
	if entry == nil {
		t.Fatalf("entry is nil")
	}

	// Age the entry past its TTL rather than waiting it out: expiry is
	// derived from stored+ttl, so moving stored back is exactly equivalent
	// to five seconds passing — and the minimum TTL the configuration
	// accepts is five seconds, so waiting is the only alternative.
	entry.stored = entry.stored.Add(-6 * time.Second)

	// Should be expired
	entry = c.checkCache(key)
	if entry != nil {
		t.Errorf("entry = %v, want nil", entry)
	}
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
	msg.Answer = append(msg.Answer, makeRR("secure.com. 300 IN RRSIG A 8 2 300 20301231235959 20201231235959 12345 secure.com. ZmFrZXNpZw=="))

	c.Set(key, msg)

	// Query without CD bit should not find it
	keyNoCD := cache.Key(q, false)
	entry := c.checkCache(keyNoCD)
	if entry != nil {
		t.Errorf("entry = %v, want nil", entry)
	}

	// Query with CD bit should find it
	entry = c.checkCache(key)
	if entry == nil {
		t.Fatalf("entry is nil")
	}
}

func TestCachePrefetch(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Prefetch = 80 // Prefetch when 80% of TTL passed
	defer os.RemoveAll(cfg.Directory)

	c := New(cfg)
	defer c.Stop() // Clean up prefetch workers

	// Just verify prefetch is configured
	if cfg.Prefetch > 0 {
		if c.prefetchQueue == nil {
			t.Fatalf("c.prefetchQueue is nil")
		}
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
	if entry == nil {
		t.Fatalf("entry is nil")
	}
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
	if _, ok := stats["positive_size"]; !ok {
		t.Errorf("stats %v missing %q", stats, "positive_size")
	}
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

	for _, key := range []string{"positive_size", "negative_size", "hits", "misses"} {
		if _, ok := stats[key]; !ok {
			t.Errorf("stats %v missing %q", stats, key)
		}
	}
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
	if entry == nil {
		t.Fatalf("entry is nil")
	}

	// Clear cache by creating new instances. checkCache reads through
	// c.store, so the swap has to update both the direct fields and
	// the store facade — they share pointers and must stay in sync.
	c.positive = NewPositiveCache(c.config.Size/2, c.config.MinTTL, c.config.MaxTTL, c.metrics)
	c.negative = NewNegativeCache(c.config.Size/2, c.config.MinTTL, c.config.NegativeTTL, c.metrics)
	c.store = NewStore(c.positive, c.negative, c.config)

	// Should be gone
	entry = c.checkCache(key)
	if entry != nil {
		t.Errorf("entry = %v, want nil", entry)
	}
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
	if opt == nil {
		t.Fatalf("opt is nil")
	}

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
	ch := middleware.NewChain([]middleware.Handler{})
	ch.Reset(mw, req2)

	c.ServeDNS(context.Background(), ch)
	if !(mw.Written()) {
		t.Errorf("mw.Written() is false")
	}

	// Response should be valid
	resp := mw.Msg()
	if resp == nil {
		t.Fatalf("resp is nil")
	}
	if len(resp.Answer) != 1 {
		t.Errorf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
	}
	if !reflect.DeepEqual("edns.com.", resp.Answer[0].Header().Name) {
		t.Errorf("resp.Answer[0].Header().Name = %v, want %v", resp.Answer[0].Header().Name, "edns.com.")
	}
}

// TestForwardZoneBypassesCoveringDenial pins the gate in front of covering
// state. An NXDOMAIN cut is learned by resolving publicly and denies a whole
// subtree; a forward zone says that subtree is answered elsewhere. Without the
// gate the public denial answers first and the zone is unreachable for as long
// as the cut lives — which is the split-horizon case the feature exists for.
func TestForwardZoneBypassesCoveringDenial(t *testing.T) {
	// The forward zone sits inside the denied subtree, so one cut covers both
	// the control name and the forwarded one.
	c := New(&config.Config{
		CacheSize: 1024,
		ForwardZones: []config.ForwardZoneConfig{
			{Name: "lab.corp.example.", Servers: []string{"10.0.0.53:53"}},
		},
	})
	defer c.Stop()

	fixture := newNXDomainCutFixture(t, "corp.example.", "example.", dns.ClassINET)
	if !c.store.RecordNXDomainCut(fixture.msg, "corp.example.", "example.", time.Time{}) {
		t.Fatal("covering cut was not recorded")
	}

	// The cut is live: a name under it but outside the forward zone is still
	// denied. Without this the assertion below would pass on an empty cache.
	outside := newQuestionMsg("other.corp.example.", dns.TypeA, dns.ClassINET)
	if cut := c.lookupNXDomainCut(context.Background(), outside, netip.Prefix{}); cut == nil {
		t.Fatal("the covering cut does not deny a name it should")
	}

	inside := newQuestionMsg("host.lab.corp.example.", dns.TypeA, dns.ClassINET)
	if cut := c.lookupNXDomainCut(context.Background(), inside, netip.Prefix{}); cut != nil {
		t.Fatal("a public NXDOMAIN cut answered for a forwarded zone")
	}
}

// TestForwardZoneFailureKinds pins which cached failures a forwarded question
// may still be answered from. The two kinds mean opposite things here: a
// zone-kind failure records an authority zone that was unreachable while
// resolving publicly, which says nothing about the zone's own upstream; a
// question-kind failure for a forwarded name is what the forwarder recorded
// when that upstream failed, and dropping it would retry a dead upstream on
// every client query.
func TestForwardZoneFailureKinds(t *testing.T) {
	newCache := func() *Cache {
		return New(&config.Config{
			CacheSize: 1024,
			ForwardZones: []config.ForwardZoneConfig{
				{Name: "corp.example.", Servers: []string{"10.0.0.53:53"}},
			},
		})
	}

	t.Run("question-kind backoff survives", func(t *testing.T) {
		c := newCache()
		defer c.Stop()
		req := newQuestionMsg("host.corp.example.", dns.TypeA, dns.ClassINET)
		c.store.RecordFailure(req, netip.Prefix{}, FailureProvenance("response"), nil)

		hit, ok := c.lookupFailure(req, netip.Prefix{})
		if !ok || hit.Kind != FailureKindQuestion {
			t.Fatalf("forwarded question lost its own backoff: ok=%v kind=%v", ok, hit.Kind)
		}
	})

	t.Run("zone-kind denial is bypassed", func(t *testing.T) {
		c := newCache()
		defer c.Stop()
		outside := newQuestionMsg("other.example.", dns.TypeA, dns.ClassINET)
		c.store.RecordZoneFailure(outside.Question[0], "example.")

		// The zone failure is live for names it should still cover; without
		// this the assertion below would pass on an empty failure cache.
		if hit, ok := c.lookupFailure(outside, netip.Prefix{}); !ok || hit.Kind != FailureKindZone {
			t.Fatalf("zone failure does not cover a public name: ok=%v kind=%v", ok, hit.Kind)
		}
		inside := newQuestionMsg("host.corp.example.", dns.TypeA, dns.ClassINET)
		if _, ok := c.lookupFailure(inside, netip.Prefix{}); ok {
			t.Fatal("a public zone failure answered for a forwarded zone")
		}
	})
}
