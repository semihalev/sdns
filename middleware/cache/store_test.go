package cache

import (
	"net/netip"
	"os"
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

// TestLookupByKeyVerifiedRejectsCollision plants two distinct questions
// under the SAME key — deterministically simulating an xxhash64 collision —
// and confirms full-key verification serves only the matching question.
// Without it, an attacker who searches a colliding qname could poison the
// cache (the cache previously returned an entry on a bare hash match).
func TestLookupByKeyVerifiedRejectsCollision(t *testing.T) {
	s := newTestStore(t)

	const collidingKey = uint64(0xC0FFEE)
	respA := newTestSuccessResp("a.example.")
	s.positive.Set(collidingKey, NewCacheEntryWithKey(respA, time.Minute, 0, collidingKey))

	qA := dns.Question{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	qB := dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	if _, ok := s.LookupByKeyVerified(collidingKey, CacheKey{Question: qB}); ok {
		t.Fatal("collision: mismatched question must be a miss")
	}
	if _, ok := s.LookupByKeyVerified(collidingKey, CacheKey{Question: qA}); !ok {
		t.Fatal("matching question must hit")
	}
	// Name comparison is case-insensitive (RFC 4343), matching the key hash.
	qAUpper := dns.Question{Name: "A.EXAMPLE.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if _, ok := s.LookupByKeyVerified(collidingKey, CacheKey{Question: qAUpper}); !ok {
		t.Fatal("name match must be case-insensitive")
	}
	// Type and class must match exactly.
	for _, q := range []dns.Question{
		{Name: "a.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS},
	} {
		if _, ok := s.LookupByKeyVerified(collidingKey, CacheKey{Question: q}); ok {
			t.Fatalf("mismatched %v must be a miss", q)
		}
	}
}

// TestCacheHitRejectsCollisionAcrossScopeAndCD plants an entry under a key
// its own preimage does not hash to — a deterministic stand-in for the
// xxhash64 collision an attacker can search for offline on a chosen qname —
// and pins that the hit chokepoint declines it instead of serving one ECS
// audience's (or CD partition's) answer to a client that belongs to
// neither. Verifying the question alone would let both through.
func TestCacheHitRejectsCollisionAcrossScopeAndCD(t *testing.T) {
	t.Run("scoped entry under the shared key", func(t *testing.T) {
		cfg := makeTestConfig()
		defer os.RemoveAll(cfg.Directory)
		c := New(cfg)
		defer c.Stop()

		req := new(dns.Msg)
		req.SetQuestion("collide.example.", dns.TypeA)
		scope := netip.MustParsePrefix("203.0.113.0/24")

		// The entry belongs to 203.0.113.0/24; the key is the one a
		// plain, ECS-less client computes.
		sharedKey := CacheKey{Question: req.Question[0], CD: false}.Hash()
		c.store.SetFromResponseScoped(sharedKey, reply(req, "10.9.9.9", 24), scope, time.Time{}, 0)

		if _, ok := c.store.LookupByKeyVerified(sharedKey, CacheKey{Question: req.Question[0]}); ok {
			t.Fatal("shared-key lookup accepted an entry scoped to another audience")
		}

		h := &echoHandler{aRecord: "10.0.0.1"}
		resp := sendAndExpect(t, c, h, req, "198.51.100.7")
		if got := answerA(resp); got != "10.0.0.1" {
			t.Fatalf("answer = %q, want the upstream answer 10.0.0.1", got)
		}
		if h.Calls() != 1 {
			t.Fatalf("upstream calls = %d, want 1 (the collision must read as a miss)", h.Calls())
		}

		// The decline is a miss, not a broken cache: the answer the miss
		// stored serves the next identical query.
		resp = sendAndExpect(t, c, h, req, "198.51.100.7")
		if got := answerA(resp); got != "10.0.0.1" || h.Calls() != 1 {
			t.Fatalf("second query: answer %q after %d upstream calls, want 10.0.0.1 after 1", got, h.Calls())
		}
	})

	t.Run("CD=1 entry under the CD=0 key", func(t *testing.T) {
		cfg := makeTestConfig()
		defer os.RemoveAll(cfg.Directory)
		c := New(cfg)
		defer c.Stop()

		req := new(dns.Msg)
		req.SetQuestion("cdcollide.example.", dns.TypeA)

		// A checking-disabled answer — unvalidated by definition — planted
		// under the key a validating (CD=0) client computes.
		cdResp := reply(req, "10.9.9.9", 0)
		cdResp.CheckingDisabled = true
		sharedKey := CacheKey{Question: req.Question[0], CD: false}.Hash()
		c.store.SetFromResponseWithKey(sharedKey, cdResp, time.Time{}, 0)

		if _, ok := c.store.LookupByKeyVerified(sharedKey, CacheKey{Question: req.Question[0]}); ok {
			t.Fatal("CD=0 lookup accepted an entry admitted under CD=1")
		}

		h := &echoHandler{aRecord: "10.0.0.1"}
		resp := sendAndExpect(t, c, h, req, "198.51.100.7")
		if got := answerA(resp); got != "10.0.0.1" {
			t.Fatalf("answer = %q, want the upstream answer 10.0.0.1", got)
		}
		if h.Calls() != 1 {
			t.Fatalf("upstream calls = %d, want 1 (the collision must read as a miss)", h.Calls())
		}
	})

	t.Run("wire verification stays allocation-free", func(t *testing.T) {
		// The wire path verifies the same dimensions on the strict path,
		// where a single allocation is a contract break (docs/zero-path.md):
		// the qname is compared against the stored presentation name in
		// place, never rebuilt.
		entry := NewCacheEntry(newTestSuccessResp("wirecheck.example."), time.Minute, 0)
		wireReq, _ := wireTestRequest(t, "wirecheck.example.", dns.TypeA, false)
		if !entryMatchesWire(entry, wireReq) {
			t.Fatal("the entry under test does not verify")
		}
		if allocs := testing.AllocsPerRun(200, func() {
			if !entryMatchesWire(entry, wireReq) {
				t.Fatal("verification flapped")
			}
		}); allocs != 0 {
			t.Fatalf("wire verification allocated %.2f objects per hit", allocs)
		}
	})
}

// TestStoreGetLookupRoundTrip covers Store.Lookup and Store.Get via
// SetFromResponse — the three public facade methods every caller
// outside the middleware goes through.
func TestStoreGetLookupRoundTrip(t *testing.T) {
	s := newTestStore(t)

	resp := newTestSuccessResp("example.com.")
	s.SetFromResponse(resp, false, time.Time{})

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
	s.SetFromResponse(respCDFalse, false, time.Time{})

	respCDTrue := newTestSuccessResp("purge.com.")
	respCDTrue.CheckingDisabled = true
	s.SetFromResponse(respCDTrue, true, time.Time{})

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
	c.store.SetFromResponse(resp, false, time.Time{})

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

// TestEqualNameASCIIFold verifies the cache-key verification folds ASCII
// case only — matching internal/cache.Key — and does NOT do Unicode folding
// (which strings.EqualFold would), so it can't accept names the key hash
// treats as distinct.
func TestEqualNameASCIIFold(t *testing.T) {
	if !equalNameASCIIFold("a.Example.COM.", "A.example.com.") {
		t.Fatal("ASCII case must fold equal")
	}
	if equalNameASCIIFold("a.example.com.", "b.example.com.") {
		t.Fatal("different names must not be equal")
	}
	// U+017F (ſ, 2 bytes UTF-8) Unicode-folds to 's', but must NOT fold
	// here — different byte length, and the key hash treats it as distinct.
	if equalNameASCIIFold("ſ.example.", "s.example.") {
		t.Fatal("must not Unicode-fold (would diverge from the key hash)")
	}
}
