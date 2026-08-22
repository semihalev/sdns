package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// TestMinimizeUpstreamQueryCount measures what minimization costs upstream,
// which is the only place this code shows: the serving path never reaches it,
// and a cold start walks the same names whatever the budget's unit is. The
// case that separates them is a second deep name under a delegation the first
// one cached — there the budget is either spent on probes or already gone.
//
// The counted zone holds every interior label as an empty non-terminal, so
// each probe is answered rather than denied. That is the most expensive shape
// there is: with no cut below the apex the extra probes buy no privacy, they
// only look for one. A name whose labels do span a real cut pays the same
// queries to find it.
func TestMinimizeUpstreamQueryCount(t *testing.T) {
	const (
		first  = "a.b.c.d.e.deep.test."
		second = "v.w.x.y.z.deep.test."
	)

	// asked reports which of the names a resolution put to the zone. Counts
	// are per name and larger than one — a zone advertises both an A and a
	// AAAA address and the resolver tries both — so presence is what this
	// pins, not the tally.
	setup := func(t *testing.T, maxCount, oneLabel int) (*hermeticZone, *DNSHandler) {
		t.Helper()

		net := newHermeticNet(t)
		zone := net.Delegate("deep.test.")
		for _, name := range []string{first, second} {
			zone.Serve(mustRR(t, name+" 300 IN A 192.0.2.11"))
			zone.ServeEmptyNonTerminals(name)
		}

		cfg := net.Config()
		cfg.QnameMaxMinimizeCount = maxCount
		cfg.QnameMinimizeOneLabel = oneLabel
		return zone, net.handlerWithConfig(cfg)
	}

	resolve := func(t *testing.T, h *DNSHandler, name string) {
		t.Helper()
		resp, err := hermeticResolve(t, h.resolver, name, dns.TypeA)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if resp == nil || len(resp.Answer) == 0 {
			t.Fatalf("resolve %s: no answer (%v)", name, resp)
		}
	}

	check := func(t *testing.T, zone *hermeticZone, asked, unasked []string) {
		t.Helper()
		for _, name := range asked {
			if zone.asked(name, dns.TypeA) == 0 {
				t.Errorf("%s was never asked for", name)
			}
		}
		for _, name := range unasked {
			if n := zone.asked(name, dns.TypeA); n != 0 {
				t.Errorf("%s was asked for %d times, want none", name, n)
			}
		}
	}

	t.Run("budget spent on probes, not on cached depth", func(t *testing.T) {
		zone, handler := setup(t, 3, 3)

		// Cold. Two of the three probes go to the root — test. and
		// deep.test. — so one is left for the zone before the full name.
		resolve(t, handler, first)
		check(t, zone,
			[]string{"e.deep.test.", first},
			[]string{"d.e.deep.test.", "c.d.e.deep.test."})

		// Warm: the delegation is cached, so the whole budget is available
		// here. Capping on delegation depth instead spent it before the
		// first query and handed the zone the full name straight away.
		resolve(t, handler, second)
		check(t, zone,
			[]string{"z.deep.test.", "y.z.deep.test.", "x.y.z.deep.test.", second},
			[]string{"w.x.y.z.deep.test."})
	})

	t.Run("a wider budget reaches further before giving up", func(t *testing.T) {
		zone, handler := setup(t, 10, 4)

		resolve(t, handler, first)
		resolve(t, handler, second)

		// The label the tight budget never got to.
		check(t, zone, []string{"w.x.y.z.deep.test."}, nil)
	})
}
