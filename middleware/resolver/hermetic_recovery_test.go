package resolver

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/stretchr/testify/assert"
)

// TestHermeticResolveRefreshesStaleAuthority drives the recovery a resolver
// has to manage when the addresses it cached for a zone stop working: after
// enough failures it looks the nameservers up again and retries with what
// it finds.
//
// The zone's nameserver is named in a different zone on purpose. One named
// inside its own zone could only be found through the very servers that
// have stopped answering, so there would be nothing to recover with — and
// the refresh, having nowhere to go, would never be exercised.
func TestHermeticResolveRefreshesStaleAuthority(t *testing.T) {
	net := newHermeticNet(t)

	helper := net.Delegate("helper.test.")
	shop := net.DelegateVia("shop.test.", "ns1.helper.test.")
	shop.Serve(mustRR(t, "www.shop.test. 300 IN A 192.0.2.60"))

	// The nameserver's address is published by the other zone, and points
	// at the socket that serves shop.test.
	helper.Serve(mustRR(t, "ns1.helper.test. 300 IN A "+shop.glue.String()))

	// The recovery is reached by failing against the stale address first,
	// so the per-server budget is what this test spends its time on.
	cfg := net.Config()
	cfg.Timeout.Duration = 200 * time.Millisecond
	r := net.handlerWithConfig(cfg).resolver

	resp, err := hermeticResolve(t, r, "www.shop.test.", dns.TypeA)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	question := dns.Question{
		Name: "www.shop.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
	}
	match := r.searchCache(question, false, "www.shop.test.")
	if match.servers == nil || len(match.servers.List) == 0 {
		t.Fatal("the delegation used to answer was not cached")
	}

	// Point the cached delegation at an address nothing answers on, and put
	// it one failure short of the threshold where the resolver gives up on
	// what it has and asks where the nameservers are now.
	match.servers.List = []*authority.Server{
		authority.NewServer("192.0.2.250:53", authority.IPv4),
	}
	match.servers.Checked = false
	atomic.StoreUint32(&match.servers.ErrorCount, 4)

	lookupsBefore := helper.asked("ns1.helper.test.", dns.TypeA)

	resp, err = hermeticResolve(t, r, "www.shop.test.", dns.TypeA)

	assert.NoError(t, err, "the resolver did not recover from a stale authority")
	if assert.NotNil(t, resp) {
		addresses := []string{}
		for _, answer := range resp.Answer {
			if a, ok := answer.(*dns.A); ok {
				addresses = append(addresses, a.A.String())
			}
		}
		assert.Equal(t, []string{"192.0.2.60"}, addresses)
	}

	// The refresh is the point, and this is what it looks like from
	// outside: the resolver went and asked where the nameserver lives
	// rather than continuing to fail against the address it had.
	assert.Greater(t, helper.asked("ns1.helper.test.", dns.TypeA), lookupsBefore,
		"the nameserver's address was never looked up again, so nothing was refreshed")
}
