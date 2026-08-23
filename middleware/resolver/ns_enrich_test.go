package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	internalcache "github.com/semihalev/sdns/internal/cache"
)

// TestLookupV4NssDefersRosterBehindGlue pins the endpoint floor: the walk
// defers the roster only once it holds two dialable endpoints, counted on
// the deduped server list — not on host names, because two names glued to
// one address are still one point of failure. Past the floor the roster is
// lane work: completed deterministically, never gambled on, never stood
// behind.
func TestLookupV4NssDefersRosterBehindGlue(t *testing.T) {
	r := newAttackHarnessResolver(&authority.Servers{Zone: "example."})
	r.startEnrichPools()
	queryer := new(selectiveNSAddressQueryer)
	installAttackQueryer(r, queryer)

	q := dns.Question{Name: "child.example.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	servers := &authority.Servers{
		Zone: q.Name,
		List: []*authority.Server{authority.NewServer("192.0.2.9:53", authority.IPv4)},
	}
	foundv4 := hostSet{"glued.child.example.": {}, "glued2.child.example.": {}}
	hosts := hostSet{
		"glued.child.example.":    {},
		"glued2.child.example.":   {},
		"healthy.child.example.":  {},
		"deferred.child.example.": {},
	}

	err := r.lookupV4Nss(context.Background(), q, servers, internalcache.Key(q), nil,
		foundv4, hosts, false, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("lookupV4Nss: %v", err)
	}

	// Two glued NAMES behind one endpoint are one point of failure, so the
	// floor demands exactly one more synchronous resolution — and not one
	// more than that.
	if calls := queryer.calls.Load(); calls != 1 {
		t.Fatalf("synchronous lookups = %d, want exactly one to reach the endpoint floor", calls)
	}

	// The lane completes the roster shortly after, from our own resolution.
	// The queryer hands every host the same address, so the server list
	// dedupes — the proof of completion is the glue cache, which keeps a
	// per-host entry either way.
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, healthyOK := r.getIPv4Cache("healthy.child.example.")
		_, _, deferredOK := r.getIPv4Cache("deferred.child.example.")
		if healthyOK && deferredOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deferred roster never completed: calls=%d healthy=%v deferred=%v",
				queryer.calls.Load(), healthyOK, deferredOK)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEnrichShedsWithoutPools pins the shed contract for bare resolvers and
// full lanes alike: offering a job never blocks and never panics — the
// addresses are simply not learned this time.
func TestEnrichShedsWithoutPools(t *testing.T) {
	r := newAttackHarnessResolver(&authority.Servers{Zone: "example."})
	queryer := new(selectiveNSAddressQueryer)
	installAttackQueryer(r, queryer)

	q := dns.Question{Name: "child.example.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	servers := &authority.Servers{
		Zone: q.Name,
		List: []*authority.Server{
			authority.NewServer("192.0.2.9:53", authority.IPv4),
			authority.NewServer("192.0.2.10:53", authority.IPv4),
		},
	}
	err := r.lookupV4Nss(context.Background(), q, servers, internalcache.Key(q), nil,
		hostSet{"glued.child.example.": {}, "glued2.child.example.": {}},
		hostSet{"glued.child.example.": {}, "glued2.child.example.": {}, "healthy.child.example.": {}},
		false, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("lookupV4Nss: %v", err)
	}

	if enqueueEnrich(nil, nsEnrichJob{}) {
		t.Fatal("a nil lane accepted a job")
	}
	time.Sleep(50 * time.Millisecond)
	if calls := queryer.calls.Load(); calls != 0 {
		t.Fatalf("nil lanes still resolved %d hosts", calls)
	}
}
