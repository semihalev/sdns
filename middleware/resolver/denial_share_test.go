package resolver

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/resolver/localroot"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// counterSum reads a counter family out of the default registry, summed
// over its labels.
func counterSum(name string) float64 {
	metric.FlushAll()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0
	}
	var sum float64
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			sum += m.GetCounter().GetValue()
		}
	}
	return sum
}

// denialHarness is a signed child zone under either the root on the wire
// or the hyperlocal root, behind the real cache and resolver.
type denialHarness struct {
	zone     *hermeticZone
	handlers []middleware.Handler
}

func newDenialHarness(t *testing.T, localRoot, nsec3, rfc8198 bool) *denialHarness {
	t.Helper()
	net := newHermeticNet(t)
	var zone *hermeticZone
	if nsec3 {
		zone = net.DelegateNSEC3("signed.")
	} else {
		zone = net.Delegate("signed.")
	}
	zone.Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))

	cfg := net.Config()
	cfg.CacheSize = 1024
	cfg.RFC8198 = &rfc8198
	handler := net.handlerWithConfig(cfg)
	if localRoot {
		z, err := roottest.BuildZone(localroot.ComputeDigest, []string{
			fmt.Sprintf(". 86400 IN SOA a.root-servers.test. nstld.test. %d 1800 900 604800 86400", roottest.Serial),
			". 518400 IN NS a.root-servers.test.",
			". 86400 IN NSEC signed. NS SOA RRSIG NSEC DNSKEY ZONEMD",
			"signed. 172800 IN NS ns.signed.",
			zone.ds[0].String(),
			"signed. 86400 IN NSEC . NS DS RRSIG NSEC",
			"a.root-servers.test. 172800 IN A 198.51.100.53",
			"ns.signed. 172800 IN A " + zone.glue.String(),
		}, roottest.Serial)
		if err != nil {
			t.Fatal(err)
		}
		mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
		if err := mgr.Load(z.RRs); err != nil {
			t.Fatal(err)
		}
		handler.resolver.localRoot.Store(mgr)
	}
	// The wiring middleware.Setup does in the server: NSEC3 synthesis hashes
	// under the resolver's crypto gate, and without one every lookup misses.
	cache := answercache.New(cfg)
	cache.SetDNSSECCryptoLimiter(handler.DNSSECCryptoLimiter())
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	return &denialHarness{zone: zone, handlers: handlers}
}

// ask resolves name/A with DO set and returns the reply and the request
// tree's lease.
func (h *denialHarness) ask(t *testing.T, name string) (*dns.Msg, middleware.Lease) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(1232, true)
	meta := new(middleware.ResponseMeta)
	ctx := middleware.WithResponseMeta(context.Background(), meta)
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain(h.handlers)
	ch.Reset(w, req)
	ch.Next(ctx)
	if !w.Written() {
		t.Fatalf("%s: no reply", name)
	}
	return w.Msg(), meta.Cut()
}

// sharedHits is every hit the RFC 8020 and RFC 8198 caches have served.
func sharedHits() float64 {
	return counterSum("nxdomain_cut_hits_total") + counterSum("aggressive_negative_hits_total")
}

// A validated NXDOMAIN is shared as an RFC 8020 cut and as an RFC 8198 proof
// whatever root the resolution started from. The hyperlocal root bounds
// every lease by its copy's signature expiration, a wall-clock deadline; the
// same signed child must be treated alike under it and under the root on
// the wire, and what the shared state answers must end no later than the
// denial it was learned from.
func TestValidatedDenialIsSharedUnderEitherRoot(t *testing.T) {
	for _, root := range []struct {
		name  string
		local bool
	}{{"root on the wire", false}, {"hyperlocal root", true}} {
		t.Run(root.name+"/rfc8020 cut", func(t *testing.T) {
			h := newDenialHarness(t, root.local, false, false)
			first, cut := h.ask(t, "absent.signed.")
			if first.Rcode != dns.RcodeNameError || !first.AuthenticatedData {
				t.Fatalf("first answer %s AD=%v, want a validated NXDOMAIN",
					dns.RcodeToString[first.Rcode], first.AuthenticatedData)
			}
			if wall := !cut.Wall().Until.IsZero(); wall != root.local {
				t.Fatalf("lease wall-clock bound %v, want %v", wall, root.local)
			}

			// The control: the same question is the ordinary negative
			// cache's, which a cut answering its own name would hide.
			asked, hits := h.zone.asked("absent.signed.", dns.TypeA), sharedHits()
			if again, _ := h.ask(t, "absent.signed."); again.Rcode != dns.RcodeNameError ||
				h.zone.asked("absent.signed.", dns.TypeA) != asked || sharedHits() != hits {
				t.Fatal("the repeated question was not answered from the negative cache")
			}

			hits = counterSum("nxdomain_cut_hits_total")
			below, derived := h.ask(t, "child.absent.signed.")
			if below.Rcode != dns.RcodeNameError {
				t.Fatalf("name below the cut: %s", dns.RcodeToString[below.Rcode])
			}
			if n := h.zone.asked("child.absent.signed.", dns.TypeA); n != 0 {
				t.Errorf("the name below the cut reached the authority %d times", n)
			}
			if d := counterSum("nxdomain_cut_hits_total") - hits; d != 1 {
				t.Errorf("nxdomain cut hits %+v, want one", d)
			}

			// Both bounds reach the answer: the proof's signature expiration
			// on the wall clock under either root, and under the hyperlocal
			// root nothing later than the lease the denial was learned under.
			if derived.Mono().Until.IsZero() || derived.Wall().Until.IsZero() {
				t.Fatalf("the cut's answer is bound to %+v, want a deadline on each clock", derived)
			}
			if root.local && derived.Wall().Until.After(cut.Wall().Until) {
				t.Fatalf("the cut's answer ends at %v on the wall clock, after the denial's %v",
					derived.Wall().Until, cut.Wall().Until)
			}
		})

		for _, proof := range []struct {
			name  string
			nsec3 bool
		}{{"nsec", false}, {"nsec3", true}} {
			t.Run(root.name+"/rfc8198 "+proof.name, func(t *testing.T) {
				h := newDenialHarness(t, root.local, proof.nsec3, true)
				first, cut := h.ask(t, "absent.signed.")
				if first.Rcode != dns.RcodeNameError || !first.AuthenticatedData {
					t.Fatalf("first answer %s AD=%v, want a validated NXDOMAIN",
						dns.RcodeToString[first.Rcode], first.AuthenticatedData)
				}
				if wall := !cut.Wall().Until.IsZero(); wall != root.local {
					t.Fatalf("lease wall-clock bound %v, want %v", wall, root.local)
				}

				hits := counterSum("aggressive_negative_hits_total")
				other, derived := h.ask(t, "other.signed.")
				if other.Rcode != dns.RcodeNameError {
					t.Fatalf("another covered name: %s", dns.RcodeToString[other.Rcode])
				}
				if n := h.zone.asked("other.signed.", dns.TypeA); n != 0 {
					t.Errorf("another name the proof covers reached the authority %d times", n)
				}
				if d := counterSum("aggressive_negative_hits_total") - hits; d != 1 {
					t.Errorf("aggressive negative hits %+v, want one", d)
				}

				// Both bounds reach the synthesized answer, as for a cut.
				if derived.Mono().Until.IsZero() || derived.Wall().Until.IsZero() {
					t.Fatalf("the synthesized answer is bound to %+v, want a deadline on each clock", derived)
				}
				if root.local && derived.Wall().Until.After(cut.Wall().Until) {
					t.Fatalf("the synthesized answer ends at %v on the wall clock, after the denial's %v",
						derived.Wall().Until, cut.Wall().Until)
				}
			})
		}
	}
}
