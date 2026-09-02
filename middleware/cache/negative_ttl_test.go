package cache

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// newCeilingStore mirrors production: the configured minimum is the same five
// seconds the derivation uses, which is what makes the two floors stack. A
// store with a smaller minimum would pass these tests against an
// implementation that only fixed the derivation.
func newCeilingStore(t *testing.T) *Store {
	t.Helper()
	cfg := CacheConfig{
		Size:        1024,
		PositiveTTL: time.Minute,
		NegativeTTL: time.Minute,
		MinTTL:      dnsutil.MinCacheTTL,
		MaxTTL:      time.Hour,
	}
	metrics := &CacheMetrics{}
	store := NewStore(
		NewPositiveCache(cfg.Size/2, cfg.MinTTL, cfg.MaxTTL, metrics),
		NewNegativeCache(cfg.Size/2, cfg.MinTTL, cfg.NegativeTTL, metrics),
		cfg,
	)
	t.Cleanup(store.Stop)
	return store
}

// denialResponse builds a cacheable denial for name with the given SOA header
// TTL and MINIMUM. NXDOMAIN when nameError, NODATA otherwise.
func denialResponse(name string, nameError bool, soaTTL, soaMin uint32) (*dns.Msg, *dns.Msg) {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	if nameError {
		resp.Rcode = dns.RcodeNameError
	}
	resp.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.org.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soaTTL,
		},
		Ns:     "ns1.example.org.",
		Mbox:   "hostmaster.example.org.",
		Minttl: soaMin,
	}}
	return req, resp
}

// TestAdmissionOnlyShortens pins the rule that keeps the two layers honest:
// the lifetime is decided once, by the derivation that can see the SOA and the
// signatures, and admission may only shorten it.
//
// A floor here looks harmless and is not. It cannot see that a signature has
// two seconds left, so it lifted correctly-bounded answers back over their own
// expiry, and the derivation's care was undone one call later.
func TestAdmissionOnlyShortens(t *testing.T) {
	tm := NewTTLManager(dnsutil.MinCacheTTL, time.Hour)

	for _, seconds := range []int{0, 1, 2, 4, 5} {
		in := time.Duration(seconds) * time.Second
		if got := tm.Bound(in); got != in {
			t.Errorf("Bound(%v) = %v, want it left alone", in, got)
		}
	}

	if got, want := tm.Bound(2*time.Hour), time.Hour; got != want {
		t.Errorf("Bound(2h) = %v, want the %v cap", got, want)
	}
	if got := tm.Bound(-time.Second); got != 0 {
		t.Errorf("Bound(-1s) = %v, want 0", got)
	}
}

// TestDenialAdmittedAtItsOwnLifetime is the end-to-end form of the contract:
// the value the zone published survives both floors and reaches the entry.
func TestDenialAdmittedAtItsOwnLifetime(t *testing.T) {
	for _, nameError := range []bool{true, false} {
		kind := "NODATA"
		if nameError {
			kind = "NXDOMAIN"
		}
		for _, seconds := range []uint32{1, 4, 5} {
			t.Run(kind, func(t *testing.T) {
				store := newCeilingStore(t)
				req, resp := denialResponse("absent.example.org.", nameError, 86400, seconds)
				store.SetFromResponse(resp, false, time.Time{})

				entry, ok := store.Lookup(req)
				if !ok {
					t.Fatalf("%s with a %ds SOA was not admitted", kind, seconds)
				}
				want := time.Duration(seconds) * time.Second
				if entry.ttl != want {
					t.Fatalf("%s stored for %v, want the zone's own %v", kind, entry.ttl, want)
				}
			})
		}
	}
}

// TestZeroLifetimeDenialIsNotAdmitted is criterion one: a denial the zone
// granted no lifetime must never enter the cache at all.
//
// The assertion is on the store's occupancy, not on a lookup miss. Lookup
// evicts an expired entry and reports a miss either way, so a test that only
// asked it a question passed just as happily against a build with the
// admission guard removed. PositiveLen sees the entry that should not be
// there.
func TestZeroLifetimeDenialIsNotAdmitted(t *testing.T) {
	// Every door an answer can arrive through, since each one calls the
	// bounds and the guard for itself.
	doors := []struct {
		name   string
		admit  func(t *testing.T, s *Store, c *Cache, key uint64, req, resp *dns.Msg)
		occupy func(s *Store, c *Cache) int
	}{
		{
			name: "SetFromResponse",
			admit: func(_ *testing.T, s *Store, _ *Cache, _ uint64, _, resp *dns.Msg) {
				s.SetFromResponse(resp, false, time.Time{})
			},
			occupy: func(s *Store, _ *Cache) int { return s.PositiveLen() },
		},
		{
			name: "scoped admission",
			admit: func(_ *testing.T, s *Store, _ *Cache, key uint64, _, resp *dns.Msg) {
				s.SetFromResponseScoped(key, resp, netip.MustParsePrefix("203.0.113.0/24"),
					time.Time{}, 0)
			},
			occupy: func(s *Store, _ *Cache) int { return s.PositiveLen() },
		},
		{
			name: "Cache.Set",
			admit: func(_ *testing.T, _ *Store, c *Cache, key uint64, _, resp *dns.Msg) {
				c.Set(key, resp)
			},
			occupy: func(_ *Store, c *Cache) int { return c.store.PositiveLen() },
		},
	}

	for _, door := range doors {
		for _, nameError := range []bool{true, false} {
			kind := "NODATA"
			if nameError {
				kind = "NXDOMAIN"
			}
			t.Run(door.name+"/"+kind, func(t *testing.T) {
				// Zero in either field is zero: RFC 2308 takes the smaller.
				for _, soa := range [][2]uint32{{0, 86400}, {86400, 0}, {0, 0}} {
					store := newCeilingStore(t)
					c := New(&config.Config{CacheSize: 1024, Expire: 600})
					defer c.Stop()

					req, resp := denialResponse("gone.example.org.", nameError, soa[0], soa[1])
					key := CacheKey{Question: req.Question[0], CD: false}.Hash()

					before := door.occupy(store, c)
					door.admit(t, store, c, key, req, resp)

					if got := door.occupy(store, c); got != before {
						t.Fatalf("%s with SOA TTL %d / MINIMUM %d was admitted: "+
							"cache holds %d entries, was %d",
							kind, soa[0], soa[1], got, before)
					}
					if _, ok := store.Lookup(req); ok {
						t.Fatalf("%s with SOA TTL %d / MINIMUM %d was served from cache",
							kind, soa[0], soa[1])
					}
				}
			})
		}
	}
}

// TestZeroLifetimeDenialDoesNotReplace covers the refresh door. A prefetch
// whose result comes back as a denial with no lifetime must leave the entry it
// was refreshing alone rather than replacing it with something unservable.
func TestZeroLifetimeDenialDoesNotReplace(t *testing.T) {
	store := newCeilingStore(t)

	req, live := denialResponse("fading.example.org.", true, 86400, 60)
	store.SetFromResponse(live, false, time.Time{})

	key := CacheKey{Question: req.Question[0], CD: false}.Hash()
	existing, ok := store.Lookup(req)
	if !ok {
		t.Fatal("the seed denial was not admitted")
	}

	_, exhausted := denialResponse("fading.example.org.", true, 0, 0)
	if store.ReplaceIfCurrent(key, existing, exhausted, time.Time{}, 0) {
		t.Fatal("a zero-lifetime denial replaced a live entry")
	}

	after, ok := store.Lookup(req)
	if !ok {
		t.Fatal("the live entry was dropped by a refusal that should have left it alone")
	}
	if after != existing {
		t.Fatal("the live entry was replaced rather than kept")
	}
}

// TestPositiveAdmissionKeepsTheFloor is criterion three at the store level.
// Denials share the positive sub-cache with ordinary answers, so a change made
// on the sub-cache rather than on the response type would show up right here.
func TestPositiveAdmissionKeepsTheFloor(t *testing.T) {
	store := newCeilingStore(t)

	req := new(dns.Msg)
	req.SetQuestion("present.example.org.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   "present.example.org.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    1,
		},
		A: []byte{192, 0, 2, 1},
	}}

	store.SetFromResponse(resp, false, time.Time{})

	entry, ok := store.Lookup(req)
	if !ok {
		t.Fatal("a one-second positive answer was not admitted")
	}
	if entry.ttl != dnsutil.MinCacheTTL {
		t.Fatalf("positive answer stored for %v, want the %v floor", entry.ttl, dnsutil.MinCacheTTL)
	}
}

// TestAliasChainDenialAtStoreLevel is the alias-chain shape driven through
// admission rather than through the derivation alone: the entry must carry the
// terminal SOA's lifetime, and a zone that granted none must not be stored.
func TestAliasChainDenialAtStoreLevel(t *testing.T) {
	build := func(soaMin uint32) (*dns.Msg, *dns.Msg) {
		req, resp := denialResponse("alias.example.org.", false, 86400, soaMin)
		resp.Answer = []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "alias.example.org.",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: "target.example.org.",
		}}
		return req, resp
	}

	for _, seconds := range []uint32{1, 4, 5} {
		store := newCeilingStore(t)
		req, resp := build(seconds)
		store.SetFromResponse(resp, false, time.Time{})

		entry, ok := store.Lookup(req)
		if !ok {
			t.Fatalf("SOA MINIMUM %ds: the alias denial was not admitted", seconds)
		}
		want := time.Duration(seconds) * time.Second
		if entry.ttl != want {
			t.Fatalf("SOA MINIMUM %ds: stored for %v, want %v (the alias TTL is 300s)",
				seconds, entry.ttl, want)
		}
	}

	store := newCeilingStore(t)
	_, resp := build(0)
	store.SetFromResponse(resp, false, time.Time{})
	if got := store.PositiveLen(); got != 0 {
		t.Fatalf("an alias denial with a zero SOA MINIMUM was admitted, cache holds %d", got)
	}
}

// TestUncacheableResponseIsNotAdmitted closes the loop on the classification
// change: a NOERROR carrying no answer, no delegation and no SOA is named
// TypeNotCacheable, and the store has no case for it. Asserted rather than
// assumed, because the derivation still returns a lifetime for that type and
// only the store's silence keeps it out.
func TestUncacheableResponseIsNotAdmitted(t *testing.T) {
	store := newCeilingStore(t)

	req := new(dns.Msg)
	req.SetQuestion("hollow.example.org.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)

	if mt, _ := dnsutil.ClassifyResponse(resp, time.Now().UTC()); mt != dnsutil.TypeNotCacheable {
		t.Fatalf("classified %v, want TypeNotCacheable", mt)
	}

	store.SetFromResponse(resp, false, time.Time{})
	if got := store.PositiveLen(); got != 0 {
		t.Fatalf("an uncacheable response was admitted, cache holds %d", got)
	}
	if _, ok := store.Lookup(req); ok {
		t.Fatal("an uncacheable response was served from cache")
	}
}

// signedAnswer builds a positive answer whose RRSIG carries the given bounds.
func signedAnswer(name string, recordTTL, sigTTL, origTTL uint32, expiresIn time.Duration) (*dns.Msg, *dns.Msg) {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: recordTTL},
			A:   []byte{192, 0, 2, 1},
		},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: sigTTL},
			TypeCovered: dns.TypeA,
			OrigTtl:     origTTL,
			Expiration:  uint32(time.Now().Add(expiresIn).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
		},
	}
	return req, resp
}

// TestSignedAnswerKeepsItsCeilingThroughAdmission is the end-to-end half of RFC
// 4035 §5.3.3, and the half a helper test cannot reach. The derivation had the
// bound right and admission raised it again: a signature with two seconds left
// was stored for five, and the entry outlived the signature it rested on.
//
// Driven through every door, because each one bounds the lifetime for itself.
func TestSignedAnswerKeepsItsCeilingThroughAdmission(t *testing.T) {
	// name, record TTL, signature TTL, original TTL, expiry, and the ceiling
	// all four of those imply.
	cases := []struct {
		what      string
		recordTTL uint32
		sigTTL    uint32
		origTTL   uint32
		expiresIn time.Duration
		ceiling   time.Duration
	}{
		{"expiry is nearest", 3600, 3600, 3600, 2 * time.Second, 2 * time.Second},
		{"original TTL is nearest", 3600, 3600, 1, time.Hour, time.Second},
		{"signature TTL is nearest", 3600, 2, 3600, time.Hour, 2 * time.Second},
		{"received RRset TTL is nearest", 1, 3600, 3600, time.Hour, time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			// Store, the ordinary door.
			store := newCeilingStore(t)
			req, resp := signedAnswer("signed.example.org.", tc.recordTTL, tc.sigTTL, tc.origTTL, tc.expiresIn)
			store.SetFromResponse(resp, false, time.Time{})
			entry, ok := store.Lookup(req)
			if !ok {
				t.Fatal("the signed answer was not admitted")
			}
			if entry.ttl > tc.ceiling {
				t.Errorf("SetFromResponse stored %v, want at most %v", entry.ttl, tc.ceiling)
			}

			// Scoped, the ECS door.
			store = newCeilingStore(t)
			req, resp = signedAnswer("signed.example.org.", tc.recordTTL, tc.sigTTL, tc.origTTL, tc.expiresIn)
			key := CacheKey{Question: req.Question[0], CD: false}.Hash()
			store.SetFromResponseScoped(key, resp, netip.MustParsePrefix("203.0.113.0/24"), time.Time{}, 0)
			if entry, ok = store.Lookup(req); ok && entry.ttl > tc.ceiling {
				t.Errorf("scoped admission stored %v, want at most %v", entry.ttl, tc.ceiling)
			}

			// The compatibility door.
			c := New(&config.Config{CacheSize: 1024, Expire: 600})
			defer c.Stop()
			req, resp = signedAnswer("signed.example.org.", tc.recordTTL, tc.sigTTL, tc.origTTL, tc.expiresIn)
			key = CacheKey{Question: req.Question[0], CD: false}.Hash()
			c.Set(key, resp)
			if entry, ok = c.store.Lookup(req); ok && entry.ttl > tc.ceiling {
				t.Errorf("Cache.Set stored %v, want at most %v", entry.ttl, tc.ceiling)
			}

			// The refresh door.
			store = newCeilingStore(t)
			req, seed := signedAnswer("signed.example.org.", 3600, 3600, 3600, time.Hour)
			store.SetFromResponse(seed, false, time.Time{})
			existing, found := store.Lookup(req)
			if !found {
				t.Fatal("the seed answer was not admitted")
			}
			key = CacheKey{Question: req.Question[0], CD: false}.Hash()
			_, refreshed := signedAnswer("signed.example.org.", tc.recordTTL, tc.sigTTL, tc.origTTL, tc.expiresIn)
			if !store.ReplaceIfCurrent(key, existing, refreshed, time.Time{}, 0) {
				t.Fatal("the refresh was refused")
			}
			if entry, ok = store.Lookup(req); ok && entry.ttl > tc.ceiling {
				t.Errorf("ReplaceIfCurrent stored %v, want at most %v", entry.ttl, tc.ceiling)
			}
		})
	}
}

// TestServedTTLIsNeverZero pins the wire-format half. An entry with a fraction
// of a second left is alive, and telling the client zero would mean "do not
// reuse this" from a cache that is reusing it; RFC 2308 §5 forbids it for a
// denial outright.
func TestServedTTLIsNeverZero(t *testing.T) {
	for _, remaining := range []time.Duration{time.Nanosecond, 991 * time.Millisecond, time.Second - 1} {
		if got := servedSeconds(remaining); got != 1 {
			t.Errorf("servedSeconds(%v) = %d, want 1", remaining, got)
		}
	}
	if got := servedSeconds(0); got != 0 {
		t.Errorf("servedSeconds(0) = %d, want 0", got)
	}
	if got := servedSeconds(-time.Second); got != 0 {
		t.Errorf("servedSeconds(-1s) = %d, want 0", got)
	}
	if got := servedSeconds(90 * time.Second); got != 90 {
		t.Errorf("servedSeconds(90s) = %d, want 90", got)
	}

	// End to end: a live entry down to its last fraction still serves a
	// usable TTL rather than telling the client not to cache it.
	store := newCeilingStore(t)
	req, resp := denialResponse("fading.example.org.", true, 86400, 60)
	store.SetFromResponse(resp, false, time.Time{})
	entry, ok := store.Lookup(req)
	if !ok {
		t.Fatal("the denial was not admitted")
	}
	entry.stored = entry.stored.Add(-entry.ttl + 991*time.Millisecond)

	out := entry.ToMsg(req)
	if out == nil {
		t.Fatal("a live entry served nothing")
	}
	if len(out.Ns) == 0 || out.Ns[0].Header().Ttl == 0 {
		t.Fatal("a denial with 991ms left was served with a TTL of zero")
	}
}

// TestSignedReferralNeverOutlivesItsSignature covers the delegation path, which
// used to return the cache minimum without ever looking at its records. A
// referral is still short-lived whatever its NS records advertise; it just may
// not outlive a signature it carries.
func TestSignedReferralNeverOutlivesItsSignature(t *testing.T) {
	referral := func(sigExpiresIn time.Duration) *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("child.example.org.", dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
				Ns:  "ns.example.org.",
			},
		}
		if sigExpiresIn > 0 {
			resp.Ns = append(resp.Ns, &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 172800},
				TypeCovered: dns.TypeNS,
				OrigTtl:     172800,
				Expiration:  uint32(time.Now().Add(sigExpiresIn).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
			})
		}
		return resp
	}

	signed := referral(2 * time.Second)
	mt, _ := dnsutil.ClassifyResponse(signed, time.Now().UTC())
	if mt != dnsutil.TypeReferral {
		t.Fatalf("classified %v, want TypeReferral", mt)
	}
	if got := dnsutil.CalculateCacheTTL(signed, mt); got > 2*time.Second {
		t.Errorf("signed referral: got %v, want at most the signature's 2s", got)
	}

	// An unsigned referral keeps the short lifetime it has always had, rather
	// than picking up the two days its NS records advertise.
	plain := referral(0)
	mt, _ = dnsutil.ClassifyResponse(plain, time.Now().UTC())
	if got, want := dnsutil.CalculateCacheTTL(plain, mt), dnsutil.MinCacheTTL; got != want {
		t.Errorf("unsigned referral: got %v, want %v unchanged", got, want)
	}
}
