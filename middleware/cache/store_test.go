package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	cfg := CacheConfig{
		Size:        1024,
		PositiveTTL: time.Minute,
		NegativeTTL: time.Minute,
		MinTTL:      time.Second,
		MaxTTL:      time.Minute,
	}
	metrics := &CacheMetrics{}
	pos := NewPositiveCache(cfg.Size/2, cfg.MinTTL, cfg.MaxTTL, metrics)
	neg := NewNegativeCache(cfg.Size/2, cfg.MinTTL, cfg.NegativeTTL, metrics)
	return NewStore(pos, neg, cfg)
}

func newTestSuccessResp(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 1},
	}}
	return resp
}

// TestStoreGetLookupRoundTrip covers Store.Lookup and Store.Get via
// SetFromResponse — the three public facade methods every caller
// outside the middleware goes through.
func TestStoreGetLookupRoundTrip(t *testing.T) {
	s := newTestStore(t)

	resp := newTestSuccessResp("example.com.")
	s.SetFromResponse(resp, false)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	entry, ok := s.Lookup(req)
	if !ok || entry == nil {
		t.Fatal("Lookup missed after SetFromResponse")
	}

	got, ok := s.Get(req)
	if !ok || got == nil {
		t.Fatal("Get missed after SetFromResponse")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(got.Answer))
	}
	if got.Answer[0].Header().Name != "example.com." {
		t.Fatalf("answer owner = %q, want example.com.", got.Answer[0].Header().Name)
	}
}

// TestStoreLookupEmptyQuestion exercises the len(req.Question) == 0
// guard on Lookup; avoids a nil-deref in callers that hand the
// store a malformed request.
func TestStoreLookupEmptyQuestion(t *testing.T) {
	s := newTestStore(t)
	if _, ok := s.Lookup(new(dns.Msg)); ok {
		t.Fatal("Lookup on empty-question request must miss")
	}
}

// TestStoreGetMiss exercises the miss path; Get on an empty store
// must return false without panicking.
func TestStoreGetMiss(t *testing.T) {
	s := newTestStore(t)
	req := new(dns.Msg)
	req.SetQuestion("nothing.com.", dns.TypeA)
	if _, ok := s.Get(req); ok {
		t.Fatal("Get on empty store must miss")
	}
}

// TestStorePurge pins that Purge removes both CD variants of an
// entry. SetFromResponse for CD=false and CD=true, then Purge once,
// then Lookup for both — both must miss.
func TestStorePurge(t *testing.T) {
	s := newTestStore(t)

	respCDFalse := newTestSuccessResp("purge.com.")
	s.SetFromResponse(respCDFalse, false)

	respCDTrue := newTestSuccessResp("purge.com.")
	respCDTrue.CheckingDisabled = true
	s.SetFromResponse(respCDTrue, true)

	// Confirm both sides populated.
	reqCDFalse := new(dns.Msg)
	reqCDFalse.SetQuestion("purge.com.", dns.TypeA)
	reqCDTrue := new(dns.Msg)
	reqCDTrue.SetQuestion("purge.com.", dns.TypeA)
	reqCDTrue.CheckingDisabled = true
	if _, ok := s.Lookup(reqCDFalse); !ok {
		t.Fatal("CD=false entry should be cached")
	}
	if _, ok := s.Lookup(reqCDTrue); !ok {
		t.Fatal("CD=true entry should be cached")
	}

	s.Purge(dns.Question{Name: "purge.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	if _, ok := s.Lookup(reqCDFalse); ok {
		t.Fatal("CD=false entry should be purged")
	}
	if _, ok := s.Lookup(reqCDTrue); ok {
		t.Fatal("CD=true entry should be purged")
	}
}

// TestCachePurgePublicAPI exercises the *Cache.Purge adapter that
// satisfies middleware.Purger — called by api/api.go via
// Pipeline.Purgers() iteration.
func TestCachePurgePublicAPI(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 60})
	defer c.Stop()

	resp := newTestSuccessResp("purge.com.")
	c.store.SetFromResponse(resp, false)

	req := new(dns.Msg)
	req.SetQuestion("purge.com.", dns.TypeA)
	if _, ok := c.store.Lookup(req); !ok {
		t.Fatal("entry should be cached before Purge")
	}

	c.Purge(dns.Question{Name: "purge.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	if _, ok := c.store.Lookup(req); ok {
		t.Fatal("entry should be purged")
	}
}
