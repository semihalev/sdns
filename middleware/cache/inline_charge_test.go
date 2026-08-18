package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/time/rate"
)

// A wire-ladder decline must not spend the per-entry rate-limit token:
// the query falls to the Msg body — or, on an inline pass, to the replay
// on a worker — and that path checks the same limiter. A token paid by a
// serve that then declined billed one client question twice, and at
// burst 1 the second check cancelled a hit the client had already paid
// for. The charge therefore runs after every deterministic decline gate.
func TestWireDeclineDoesNotChargeEntryLimiter(t *testing.T) {
	c := New(&config.Config{Expire: 600, CacheSize: 1024, RateLimit: 1})

	resp := new(dns.Msg)
	resp.SetQuestion("charge.zone.test.", dns.TypeA)
	resp.Response = true
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "charge.zone.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 8},
	}}
	entry := NewCacheEntryWithKey(resp, time.Minute, 1, 42)
	if entry.GetRateLimiter() == nil {
		t.Fatal("test needs a rate-limited entry")
	}

	req, _ := wireTestRequest(t, "charge.zone.test.", dns.TypeA, false)
	ch := middleware.NewChain(nil)
	// A mock writer has no wire capability, so the ladder must decline
	// this serve to the Msg path — before the limiter spends anything.
	ch.ResetWire(mock.NewWriter("udp", "203.0.113.50:4242"), req)

	var spent *rate.Limiter
	if c.serveHitFromWire(context.Background(), ch, entry, &spent) {
		t.Fatal("expected the incapable writer to decline to the Msg path")
	}
	if spent != nil {
		t.Fatal("declined wire serve recorded a spent limiter")
	}
	if !entry.GetRateLimiter().Allow() {
		t.Fatal("declined wire serve consumed the entry's only token")
	}
}

// leaseTransport is a mock transport with the wire body lease, so the
// ladder reaches the branches behind the writer-capability gates.
type leaseTransport struct {
	*mock.Writer
	buf [4096]byte
}

func (l *leaseTransport) LeaseWire(capacity int) []byte {
	if capacity > len(l.buf) {
		return nil
	}
	return l.buf[:0]
}

// The chase branch declines routinely — an uncached hop is the everyday
// case — and none of its declines may spend the per-entry token: the
// query falls to the Msg path (or the replay after an inline handoff),
// which checks the same limiter, and a pre-spent token there drops a
// paid-for hit at burst 1.
func TestChaseDeclineDoesNotChargeEntryLimiter(t *testing.T) {
	c := New(&config.Config{Expire: 600, CacheSize: 1024, RateLimit: 1})

	// A bare alias: the CNAME without its terminal. Chase-unsafe by
	// shape, and the target is not cached, so collectWireChase declines.
	resp := new(dns.Msg)
	resp.SetQuestion("alias.zone.test.", dns.TypeA)
	resp.Response = true
	resp.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.zone.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.zone.test.",
	}}
	entry := NewCacheEntryWithKey(resp, time.Minute, 1, 43)
	if entry.wireServe&wireEligible == 0 {
		t.Fatal("fixture must be wire-eligible")
	}
	if entry.wireServe&wireChaseSafe != 0 {
		t.Fatal("fixture must be chase-unsafe")
	}
	if entry.GetRateLimiter() == nil {
		t.Fatal("test needs a rate-limited entry")
	}

	req, _ := wireTestRequest(t, "alias.zone.test.", dns.TypeA, false)
	ch := middleware.NewChain(nil)
	tr := &leaseTransport{Writer: mock.NewWriter("udp", "203.0.113.51:4242")}
	ch.ResetWire(tr, req)
	ch.AllowDirectPack()

	var spent *rate.Limiter
	if c.serveHitFromWire(context.Background(), ch, entry, &spent) {
		t.Fatal("expected the uncachable chase to decline to the Msg path")
	}
	if spent != nil {
		t.Fatal("declined chase recorded a spent limiter")
	}
	if !entry.GetRateLimiter().Allow() {
		t.Fatal("declined chase consumed the entry's only token")
	}
}
