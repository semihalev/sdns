package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
)

// Test_searchCache_CD1DelegationMustNotPoisonCD0 reproduces the AD-loss
// cache-poisoning bug.
//
// Internal resolutions (NS-address lookups via the Queryer, DS lookups via
// subQuery) inherit cd=true when resolving an insecure delegation
// (cd := req.CheckingDisabled || len(parentDS)==0). Under CD=1,
// validateDelegation returns a raw, UNVALIDATED findDS result — which is an
// empty DSSet on a transient/flaky lookup — and processDelegation caches it
// under the cd=true key. If the nameserver/DS being resolved lives in a
// genuinely SIGNED zone (e.g. com.), that secure zone ends up cached as
// cd=true with an empty DSSet.
//
// searchCache then lets a CD=0 query consume that CD=1 empty-DSSet entry
// (resolver.go: "if !cd { ... if len(ns.DSSet)==0 { return } }"), so the
// secure zone is served to validating clients with no DS chain — every
// answer under it loses the AD bit until the entry expires.
//
// This test asserts the correct invariant: a CD=0 query must never be
// served an unvalidated CD=1 delegation. It FAILS on the buggy code (the
// CD=1 com. entry is returned) and passes once the cross-CD share is fixed.
func Test_searchCache_CD1DelegationMustNotPoisonCD0(t *testing.T) {
	r := &Resolver{delegations: authority.NewCache()}
	r.rootServers = &authority.Servers{
		Zone: ".",
		List: []*authority.Server{authority.NewServer("198.51.100.1:53", authority.IPv4)},
	}

	// Simulate the poisoned state: com. (a signed TLD) cached under the
	// cd=true key with an EMPTY DSSet, as an unvalidated CD=1 internal
	// resolution would leave it after a transient no-DS lookup.
	comNS := dns.Question{Name: "com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	poison := &authority.Servers{
		Zone: "com.",
		List: []*authority.Server{authority.NewServer("192.0.2.66:53", authority.IPv4)},
	}
	r.delegations.Set(cache.Key(comNS, true), nil /* empty DSSet */, poison, time.Minute)

	// A CD=0 client query under com. With no validated CD=0 delegation
	// cached, it must fall through to the root and re-establish a
	// validated chain — NOT borrow the unvalidated CD=1 com. delegation.
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := r.searchCache(q, false, q.Name)
	servers, parentDS := m.servers, m.parentDS

	if servers != nil && len(servers.List) > 0 && servers.List[0].Addr == "192.0.2.66:53" {
		t.Fatalf("BUG REPRODUCED: a CD=0 query was served the unvalidated CD=1 com. "+
			"delegation (insecure downgrade) — servers=%s parentDS=%v; "+
			"expected the root servers and a freshly validated chain",
			servers.List[0].Addr, parentDS)
	}
}
