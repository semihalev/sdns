package resolver

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
)

// TestGlueCacheHonorsTTL pins the horizon on nameserver addresses. The glue
// caches used to hold bare address slices until eviction pressure, so a
// renumbered nameserver's old address kept being handed out for as long as
// nothing happened to push it out. Entries now carry the smallest TTL of the
// records they came from, clamped to a floor and a cap, and a read past the
// horizon deletes exactly the entry it saw.
func TestGlueCacheHonorsTTL(t *testing.T) {
	r := &Resolver{glueV4: cache.New(16), glueV6: cache.New(16)}
	addr := netip.MustParseAddr("192.0.2.10")

	t.Run("fresh entries hit and report their remaining horizon", func(t *testing.T) {
		r.addIPv4Cache(map[string]nsAddrs{"ns.example.": {addrs: []netip.Addr{addr}, ttl: 300}})
		got, remaining, ok := r.getIPv4Cache("ns.example.")
		if !ok || len(got) != 1 || got[0] != addr {
			t.Fatalf("fresh entry = %v %v, want the stored address", got, ok)
		}
		if remaining == 0 || remaining > 300 {
			t.Fatalf("remaining = %ds, want within the stored 300s", remaining)
		}
	})

	t.Run("the floor and the cap clamp what zones publish", func(t *testing.T) {
		r.addIPv4Cache(map[string]nsAddrs{"zero.example.": {addrs: []netip.Addr{addr}, ttl: 0}})
		if _, remaining, ok := r.getIPv4Cache("zero.example."); !ok || remaining > uint32(glueTTLFloor/time.Second) {
			t.Fatalf("zero TTL entry remaining = %d ok=%v, want floored", remaining, ok)
		}
		r.addIPv4Cache(map[string]nsAddrs{"week.example.": {addrs: []netip.Addr{addr}, ttl: 7 * 24 * 3600}})
		if _, remaining, _ := r.getIPv4Cache("week.example."); remaining > uint32(glueTTLCap/time.Second) {
			t.Fatalf("week-long TTL remaining = %ds, want capped at %v", remaining, glueTTLCap)
		}
	})

	t.Run("an expired entry misses and deletes itself", func(t *testing.T) {
		key := cache.Key(dns.Question{Name: "old.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
		r.glueV6.Add(key, &glueEntry{addrs: []netip.Addr{addr}, expiresAt: time.Now().Add(-time.Second).UnixNano()})
		if _, _, ok := r.getIPv6Cache("old.example."); ok {
			t.Fatal("expired glue served")
		}
		if _, ok := r.glueV6.Get(key); ok {
			t.Fatal("expired glue left in the cache after the miss")
		}
	})
}

// TestGlueCacheHitDoesNotRenewHorizon reproduces the renewal leak: an entry
// five seconds from expiry is read through the full lookupV4Nss flow, which
// used to feed the remaining TTL straight back through the 30-second floor,
// so every read of a nearly-expired address bought it another 30 seconds,
// indefinitely. A hit is not new information; the stored horizon must survive
// the read untouched.
func TestGlueCacheHitDoesNotRenewHorizon(t *testing.T) {
	r := newWiredTestResolver(makeTestConfig())

	const host = "ns.renew.example."
	key := cache.Key(dns.Question{Name: host, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	expiresAt := time.Now().Add(5 * time.Second).UnixNano()
	r.glueV4.Add(key, &glueEntry{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, expiresAt: expiresAt})

	authservers := &authority.Servers{Zone: "renew.example."}
	hosts := hostSet{host: struct{}{}}
	q := dns.Question{Name: "www.renew.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	if err := r.lookupV4Nss(context.Background(), q, authservers, 1, nil, hostSet{}, hosts, true, time.Time{}); err != nil {
		t.Fatalf("lookupV4Nss: %v", err)
	}

	authservers.RLock()
	servers := len(authservers.List)
	authservers.RUnlock()
	if servers != 1 {
		t.Fatalf("cached glue did not reach the server list: %d entries", servers)
	}

	v, ok := r.glueV4.Get(key)
	if !ok {
		t.Fatal("glue entry vanished on a hit")
	}
	if got := v.(*glueEntry).expiresAt; got != expiresAt {
		t.Fatalf("hit renewed the horizon: expiry moved %+ds",
			(got-expiresAt)/int64(time.Second))
	}
}
