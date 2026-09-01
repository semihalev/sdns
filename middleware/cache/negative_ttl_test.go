package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
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
// granted no lifetime must not come back out of the cache. Admitting it with a
// zero TTL would leave an entry every read has to discard.
func TestZeroLifetimeDenialIsNotAdmitted(t *testing.T) {
	for _, nameError := range []bool{true, false} {
		kind := "NODATA"
		if nameError {
			kind = "NXDOMAIN"
		}
		t.Run(kind, func(t *testing.T) {
			store := newCeilingStore(t)

			// Zero in either field is zero: RFC 2308 takes the smaller.
			for _, soa := range [][2]uint32{{0, 86400}, {86400, 0}, {0, 0}} {
				req, resp := denialResponse("gone.example.org.", nameError, soa[0], soa[1])
				store.SetFromResponse(resp, false, time.Time{})

				if _, ok := store.Lookup(req); ok {
					t.Fatalf("%s with SOA TTL %d / MINIMUM %d was served from cache",
						kind, soa[0], soa[1])
				}
			}
		})
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
