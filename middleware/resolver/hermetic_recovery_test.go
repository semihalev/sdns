package resolver

import (
	"net"
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
	world := newHermeticNet(t)

	helper := world.Delegate("helper.test.")
	shop := world.DelegateVia("shop.test.", "ns1.helper.test.")
	shop.Serve(mustRR(t, "www.shop.test. 300 IN A 192.0.2.60"))

	// The nameserver's address is published by the other zone, and points
	// at the socket that serves shop.test.
	helper.Serve(mustRR(t, "ns1.helper.test. 300 IN A "+shop.glue.String()))

	// The recovery is reached by failing against the stale address first,
	// so the per-server budget is what this test spends its time on.
	cfg := world.Config()
	cfg.Timeout.Duration = 200 * time.Millisecond
	r := world.handlerWithConfig(cfg).resolver

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

	// Point the cached delegation at something that fails, and put it one
	// failure short of the threshold where the resolver gives up on what it
	// has and asks where the nameservers are now.
	//
	// The failure comes from a loopback server that answers with something
	// which is not a DNS message. A TEST-NET address would do as far as the
	// resolver is concerned, but the packets would really leave the host —
	// where a VPN or a helpful local network may route or answer them — and
	// each attempt would cost a timeout.
	stale := malformedResponder(t)
	match.servers.List = []*authority.Server{
		authority.NewServer(stale, authority.IPv4),
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

	// The refresh is the point, and it shows in two places: the resolver
	// went and asked where the nameserver lives, and the address it found
	// is now among the ones it will use. The stale entry stays — the
	// refresh adds what works rather than pruning what does not — so this
	// asks whether the working address is present, not whether the dead one
	// is gone.
	assert.Greater(t, helper.asked("ns1.helper.test.", dns.TypeA), lookupsBefore,
		"the nameserver's address was never looked up again, so nothing was refreshed")

	working := net.JoinHostPort(shop.glue.String(), "53")
	after := r.searchCache(question, false, "www.shop.test.")
	if assert.NotNil(t, after.servers) {
		addrs := make([]string, 0, len(after.servers.List))
		for _, server := range after.servers.List {
			addrs = append(addrs, server.Addr)
		}
		assert.Contains(t, addrs, working,
			"the refreshed delegation does not carry the address that answers")
	}
}

// malformedResponder answers every query with something that is not a DNS
// message. A resolver pointed at it fails at once and for one reason, which
// is what a test wants from a broken endpoint — no timeout to sit through
// and no packet leaving the host.
func malformedResponder(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			_, _ = pc.WriteTo([]byte("not a DNS message")[:min(n, 17)], from)
		}
	}()

	return pc.LocalAddr().String()
}
