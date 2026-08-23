package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	internalcache "github.com/semihalev/sdns/internal/cache"
)

// TestLookupV4NssDefersRosterBehindGlue pins the referral contract: glue is
// the parent telling us where the child lives, and one address in hand is
// enough to walk on. The remaining hosts are roster work — completed
// deterministically by the bounded lane, never gambled on and never stood
// behind. The walk used to resolve every glue-less host inline, one full
// recursion each, before taking a single step into the delegation.
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
	foundv4 := hostSet{"glued.child.example.": {}}
	hosts := hostSet{
		"glued.child.example.":   {},
		"healthy.child.example.": {},
	}

	err := r.lookupV4Nss(context.Background(), q, servers, internalcache.Key(q), nil,
		foundv4, hosts, false, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("lookupV4Nss: %v", err)
	}

	// The walk did not wait for anything: no synchronous NS-address lookup
	// happened before lookupV4Nss returned.
	if calls := queryer.calls.Load(); calls != 0 {
		t.Fatalf("walk stood behind %d synchronous lookups despite glue in hand", calls)
	}

	// The lane completes the roster shortly after, from our own resolution.
	deadline := time.Now().Add(3 * time.Second)
	for {
		servers.RLock()
		grew := len(servers.List) == 2
		servers.RUnlock()
		if grew {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deferred roster never completed: calls=%d servers=%d",
				queryer.calls.Load(), len(servers.List))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, ok := r.getIPv4Cache("healthy.child.example."); !ok {
		t.Fatal("deferred resolution did not land in the glue cache")
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
		List: []*authority.Server{authority.NewServer("192.0.2.9:53", authority.IPv4)},
	}
	err := r.lookupV4Nss(context.Background(), q, servers, internalcache.Key(q), nil,
		hostSet{"glued.child.example.": {}},
		hostSet{"glued.child.example.": {}, "healthy.child.example.": {}},
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
