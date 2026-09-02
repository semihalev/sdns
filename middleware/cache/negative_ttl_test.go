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

// TestTTLManagerDoesNotFloorDenials covers the second of the two stacked
// floors on its own. The derivation can be correct and the denial still get
// raised right back here, so this has to be asserted separately rather than
// only through the store.
func TestTTLManagerDoesNotFloorDenials(t *testing.T) {
	tm := NewTTLManager(dnsutil.MinCacheTTL, time.Hour)

	for _, mt := range []dnsutil.ResponseType{dnsutil.TypeNXDomain, dnsutil.TypeNoRecords} {
		for _, seconds := range []int{0, 1, 4, 5} {
			in := time.Duration(seconds) * time.Second
			if got := tm.CalculateFor(mt, in); got != in {
				t.Errorf("CalculateFor(%v, %v) = %v, want it left alone", mt, in, got)
			}
		}
		if got, want := tm.CalculateFor(mt, 2*time.Hour), time.Hour; got != want {
			t.Errorf("CalculateFor(%v, 2h) = %v, want the %v cap still applied", mt, got, want)
		}
	}

	// Everything that is not a denial keeps both bounds. TypeReferral matters
	// here because referrals live in the same sub-cache as denials.
	for _, mt := range []dnsutil.ResponseType{
		dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeServerFailure,
	} {
		if got, want := tm.CalculateFor(mt, time.Second), dnsutil.MinCacheTTL; got != want {
			t.Errorf("CalculateFor(%v, 1s) = %v, want the %v floor kept", mt, got, want)
		}
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
