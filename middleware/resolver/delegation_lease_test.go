package resolver

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/lease"
)

// TestProvisionalStoreDoesNotClobberDelegationLease guards the lease against
// the deferred enrichment lane. resolveV4Host stores a one-minute provisional
// delegation before its address lookup so the lookup itself can find the
// servers. Inline that entry is overwritten by the real lease as soon as the
// walk stores it, but a queued enrichment job runs after that store, and its
// provisional write used to replace an hours-long lease with the one-minute
// cap, cutting the served TTL of every answer under the delegation to it.
func TestProvisionalStoreDoesNotClobberDelegationLease(t *testing.T) {
	cfg := makeTestConfig()
	cfg.DNSSEC = "off"
	r := newWiredTestResolver(cfg)

	const host = "ns1.lease.example."
	const key = uint64(0xBEEF)

	authservers := &authority.Servers{Zone: "lease.example."}
	authservers.List = append(authservers.List,
		authority.NewServerFromAddrPort(netip.MustParseAddrPort("192.0.2.1:53")))

	until := time.Now().Add(time.Hour)
	r.delegations.SetUntil(key, nil, authservers, lease.Until(until))

	r.addIPv4Cache(map[string]nsAddrs{host: {addrs: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, ttl: 300}})

	q := dns.Question{Name: "www.lease.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if _, err := r.resolveV4Host(context.Background(), q, authservers, key, nil, host, false, lease.Lease{}); err != nil {
		t.Fatalf("resolveV4Host: %v", err)
	}

	d, err := r.delegations.Get(key)
	if err != nil {
		t.Fatalf("delegation vanished: %v", err)
	}
	if got := d.Lease.Mono().Until; got.Before(until.Add(-time.Second)) {
		t.Fatalf("lease clobbered: expires in %v, want the stored hour",
			time.Until(got).Round(time.Second))
	}
}
