//go:build !race

package rpz

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestCleanServesAllocateNoMoreWithResponseRules pins §5.11 against the
// two allocation regressions the review found: with response rules
// configured, the all-candidates-none wire hit and the clean admission
// must cost exactly what a qname-only configuration costs. The wrap is
// pooled and the explicit none is the generation's shared sentinel.
//
// The pin is race-excluded like every other allocation pin: the race
// detector's sync.Pool drops one Put in four at random, so both paths
// pay a pool refill a varying number of times per run and two
// independent counts land on different integers by chance.
func TestCleanServesAllocateNoMoreWithResponseRules(t *testing.T) {
	const qnameOnlyZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 7 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME .
`
	measure := func(h *sidecarHarness) (hit, admit float64) {
		h.truth["clean.test."] = "198.51.100.1"
		h.serve(t, "clean.test.", "192.0.2.1:40000", true) // prime

		q := new(dns.Msg)
		q.SetQuestion("clean.test.", dns.TypeA)
		q.RecursionDesired = true
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("refused")
		}
		w := mock.NewWriter("udp", "192.0.2.1:40000")
		ch := middleware.NewChain([]middleware.Handler{h.r, h.c, h.authority()})
		hit = testing.AllocsPerRun(200, func() {
			ch.ResetWire(w, req)
			ch.AllowDirectPack()
			ch.Next(context.Background())
		})

		resp := new(dns.Msg)
		resp.SetQuestion("admit.test.", dns.TypeA)
		resp.Response = true
		resp.Answer = []dns.RR{testA("admit.test.", "198.51.100.1")}
		admit = testing.AllocsPerRun(200, func() {
			h.cacheStore().SetFromResponseWithCut(resp, false, middleware.Lease{})
		})
		return hit, admit
	}

	base := newSidecarHarness(t, "enforce", config.RPZZone{Name: "names", File: writeZone(t, qnameOnlyZone)})
	baseHit, baseAdmit := measure(base)
	resp := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	respHit, respAdmit := measure(resp)

	if respHit > baseHit {
		t.Fatalf("clean wire hit allocates %.1f with response rules vs %.1f without", respHit, baseHit)
	}
	if respAdmit > baseAdmit {
		t.Fatalf("clean admission allocates %.1f with response rules vs %.1f without", respAdmit, baseAdmit)
	}
}
