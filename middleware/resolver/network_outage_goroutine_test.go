package resolver

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
	internalcache "github.com/semihalev/sdns/internal/cache"
)

// blackholeAuthority is an authoritative fixture whose "network" can be cut
// mid-flight. When dropping is set it still receives the packet but never
// answers, which is what a blackholed route looks like to the resolver: no
// REFUSED, no ICMP unreachable, no connection error — every in-flight
// exchange has to wait out its full timeout instead of failing fast.
//
// That distinction is the whole point of the fixture. Fast failures are
// cheap; silent drops are what convert a network incident into a goroutine
// backlog, because the resolver's concurrency is bounded per-exchange but
// its *lifetime* is bounded only by timeouts.
type blackholeAuthority struct {
	dropping atomic.Bool
	received atomic.Int64
	answered atomic.Int64

	server   *dns.Server
	packet   net.PacketConn
	shutdown sync.Once
}

func startBlackholeAuthority(t testing.TB, answer func(dns.Question) *dns.Msg) *blackholeAuthority {
	t.Helper()

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole fixture: %v", err)
	}

	f := &blackholeAuthority{packet: packet}
	f.server = &dns.Server{
		Net:        "udp",
		PacketConn: packet,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			if len(req.Question) == 0 {
				return
			}
			f.received.Add(1)

			// The outage: packet accepted, no reply ever sent.
			if f.dropping.Load() {
				return
			}

			src := answer(req.Question[0])
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Compress = true
			if src != nil {
				reply.Authoritative = src.Authoritative
				reply.Rcode = src.Rcode
				reply.Answer = src.Answer
				reply.Ns = src.Ns
				reply.Extra = src.Extra
			}
			if w.WriteMsg(reply) == nil {
				f.answered.Add(1)
			}
		}),
	}

	go func() { _ = f.server.ActivateAndServe() }()
	t.Cleanup(func() {
		f.shutdown.Do(func() {
			_ = f.server.Shutdown()
			_ = f.packet.Close()
		})
	})

	return f
}

func (f *blackholeAuthority) addr() string { return f.packet.LocalAddr().String() }

// newOutageResolver mirrors newAttackHarnessResolver but enables IPv6Access,
// which is what arms the detached lookupV6Nss job on every glue-less-V6
// referral. Production runs with IPv6 on, so a goroutine-accounting test that
// left it off would measure a strictly easier system than the one on the wire.
func newOutageResolver(root *authority.Servers, maxConcurrent int) *Resolver {
	cfg := &config.Config{
		DNSSEC:               "off",
		Maxdepth:             30,
		MaxConcurrentQueries: maxConcurrent,
		IPv6Access:           true,
		Timeout:              config.Duration{Duration: 500 * time.Millisecond},
	}
	r := &Resolver{
		cfg:             cfg,
		delegations:     authority.NewCache(),
		rootServers:     root,
		glueV4:          internalcache.New(defaultCacheSize),
		glueV6:          internalcache.New(defaultCacheSize),
		dnssec:          false,
		qnameMinCount:   0,
		netTimeout:      500 * time.Millisecond,
		sfGroup:         NewSingleflightWrapper(),
		circuitBreaker:  newCircuitBreaker(),
		maxConcurrent:   make(chan struct{}, maxConcurrent),
		resolutionSlots: make(chan struct{}, maxConcurrent),
		zoneInflight:    newZoneInflightLimiter(max(maxConcurrent/16, 16)),
	}
	// The enrichment lanes are a fixed number of workers, so they belong to
	// the pre-load baseline this test subtracts — what it measures is
	// whether anything still scales with the outage.
	r.startEnrichPools()
	return r
}

// outageSample is one observation of the system under load. Raw
// NumGoroutine() is not directly comparable across arms of this test: the load
// generator itself holds one goroutine per in-flight request, so a slower
// system looks "leakier" purely because more of its own callers are parked.
//
// backlog subtracts both the pre-test baseline and the harness's own caller
// goroutines. What remains is resolver-internal machinery — the number that
// blew from 139 to ~400k in production.
type outageSample struct {
	goroutines int
	inflight   int64
	backlog    int
}

// sampleGoroutines watches goroutine count against in-flight requests and
// reports the sample with the largest internal backlog.
func sampleGoroutines(stop <-chan struct{}, inflight *atomic.Int64, baseline int, done chan<- outageSample) {
	var worst outageSample
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			done <- worst
			return
		case <-ticker.C:
			n := runtime.NumGoroutine()
			f := inflight.Load()
			if b := n - baseline - int(f); b > worst.backlog {
				worst = outageSample{goroutines: n, inflight: f, backlog: b}
			}
		}
	}
}

// dumpTopStacks groups live goroutines by their originating frame. Under an
// outage the interesting question is not "how many" but "spawned from where",
// since a bounded pool and an unbounded detached job look identical in a count.
func dumpTopStacks(t *testing.T, label string, limit int) {
	t.Helper()

	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]

	counts := map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		lines := strings.Split(strings.TrimSpace(g), "\n")
		if len(lines) < 2 {
			continue
		}
		// Group by where the goroutine is parked (its top frame plus the
		// wait reason) — under an outage the question is what work is
		// being held open, not which site spawned it.
		state := ""
		if open := strings.Index(lines[0], "["); open >= 0 {
			state = lines[0][open:]
		}
		site := strings.TrimSpace(lines[1])
		if cut := strings.Index(site, "(0x"); cut > 0 {
			site = site[:cut]
		}
		counts[site+" "+state]++
	}

	type row struct {
		site string
		n    int
	}
	rows := make([]row, 0, len(counts))
	for s, n := range counts {
		rows = append(rows, row{s, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	for _, r := range rows {
		t.Logf("  [%s] %5d  %s", label, r.n, r.site)
	}
}

// glueIPFor derives a stable, zone-unique glue address. Uniqueness is the
// point: in the production incident every victim zone advertised its own
// nameserver addresses, so the per-server circuit breaker never accumulated
// five failures against any single address and could not shed the load. A
// shared glue IP here would let the breaker trip after five zones and quietly
// convert the outage arm into a fast-fail benchmark.
func glueIPFor(zone string) net.IP {
	h := fnv.New32a()
	_, _ = h.Write([]byte(zone))
	v := h.Sum32()
	return net.IPv4(10, byte(v>>16), byte(v>>8), byte(v)) //nolint:gosec // G115 - deliberate byte truncation of a hash
}

// TestNetworkOutageGoroutineBacklog reproduces the production incident shape:
// a PARTIAL network failure — root and TLD authorities keep answering, the
// leaf authorities go dark — while client queries keep arriving at a steady
// rate. Inbound QPS never changes; only the network does. (A total blackhole
// is the easy case: every path fails fast at the root and the circuit breaker
// sheds the load. Production died on the partial case.)
//
// Each request walks a fresh delegation (distinct zone per query, distinct
// glue address per zone) so the delegation cache, singleflight, and the
// per-server circuit breaker cannot collapse the load — which is what makes
// every arrival pay the full referral + NS-address + detached-V6 cost.
//
// The test asserts two properties that together bound a network incident:
//
//   - Backlog: resolver-internal goroutines (total minus baseline minus the
//     harness's own in-flight callers) must stay within a multiplier of the
//     healthy arm under identical offered load. Unbounded growth here is the
//     139 → 400k production signature.
//   - Drain: once load stops and the network returns, goroutines must fall
//     back near the pre-outage baseline within the detached-job budget.
//     A floor that stays elevated means work outlived its request tree.
func TestNetworkOutageGoroutineBacklog(t *testing.T) {
	const (
		maxConcurrent = 64
		// ~200 qps — the production node's real inbound rate. The point of
		// the fixture is a network incident under NORMAL load; an offered
		// rate that saturates the healthy arm invalidates the comparison.
		arrivalRate  = 5 * time.Millisecond
		outageWindow = 6 * time.Second
	)

	// Root refers every zone to an in-bailiwick nameserver with V4 glue only.
	// The missing AAAA glue is deliberate: it is exactly the condition that
	// arms the detached 30s lookupV6Nss goroutine on the referral path.
	//
	// Zones named dead*.test model a breaker-resistant dark destination:
	// every referral advertises a FRESH nameserver name and glue address
	// (172.16.x.y), so the per-server circuit breaker never accumulates
	// five failures against any single address — the resolver's slot pools
	// are the only thing standing between one dark provider and everyone
	// else.
	var darkGlue atomic.Uint32
	root := startBlackholeAuthority(t, func(q dns.Question) *dns.Msg {
		zone := zoneOf(q.Name)
		if zone == "" {
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
		}
		ns := "ns." + zone
		glue := glueIPFor(zone)
		if strings.HasPrefix(zone, "dead") {
			n := darkGlue.Add(1)
			ns = fmt.Sprintf("ns%d.%s", n, zone)
			glue = net.IPv4(172, 16, byte(n>>8), byte(n)) //nolint:gosec // G115 - deliberate byte truncation
		}
		return &dns.Msg{
			Ns: []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  ns,
			}},
			Extra: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: ns, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   glue,
			}},
		}
	})

	child := startBlackholeAuthority(t, func(q dns.Question) *dns.Msg {
		msg := &dns.Msg{Answer: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 200),
		}}}
		msg.Authoritative = true
		return msg
	})

	// darkChild swallows every packet from the start — it exists only to be
	// the dead destination behind 172.16.x.y glue.
	darkChild := startBlackholeAuthority(t, func(dns.Question) *dns.Msg { return nil })
	darkChild.dropping.Store(true)

	// Every 10.x.y.z glue address dials the shared child fixture and every
	// 172.16.x.y address dials the dark one; the root keeps its real
	// address. The resolver still sees thousands of distinct server
	// identities — RTT stats, circuit breaker and connection pooling all
	// operate per unique address, as they did in production.
	rootAddr := root.addr()
	mapper := func(addr string) string {
		if addr == rootAddr {
			return addr
		}
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				switch ip.To4()[0] {
				case 10:
					return child.addr()
				case 172:
					return darkChild.addr()
				}
			}
		}
		return addr
	}

	rootServers := &authority.Servers{
		Zone:            ".",
		List:            []*authority.Server{authority.NewServer(root.addr(), authority.IPv4)},
		CheckingDisable: true,
	}

	testStartGoroutines := runtime.NumGoroutine()

	// runArm builds a FRESH resolver (its own circuit breaker, delegation
	// cache, singleflight group), proves the wiring resolves while healthy,
	// then drives a fixed-rate query stream — optionally with the leaf
	// authorities dark. Fresh state per arm matters: breaker trips earned
	// under one arm's load must not leak into the next arm's measurements.
	// Naming is namespaced per arm so the shared fixtures stay stateless.
	runArm := func(prefix string, dark bool) (worst outageSample, issued, resolved int64, baseline int) {
		// Wait out the previous arm's detached jobs so this arm's warm-up
		// and baseline aren't measured against leftover load.
		settleDeadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(settleDeadline) &&
			runtime.NumGoroutine() > testStartGoroutines+20 {
			time.Sleep(250 * time.Millisecond)
		}

		r := newOutageResolver(rootServers, maxConcurrent)
		r.resolveTarget.Store(&mapper)

		resolve := func(name string, budget time.Duration) error {
			req := new(dns.Msg)
			req.SetQuestion(name, dns.TypeA)
			req.CheckingDisabled = true
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			ctx = context.WithValue(ctx, contextKeyRequestID, req.Id)
			_, err := r.Resolve(ctx, req, rootServers, false, 30, 0, true, nil)
			return err
		}

		// Prove the arm's resolver actually resolves before drawing any
		// conclusion from goroutine counts under failure.
		before := child.answered.Load()
		if err := resolve("www."+prefix+"warm.test.", 5*time.Second); err != nil ||
			child.answered.Load() == before {
			t.Fatalf("%s arm: fixture never resolved while healthy (err=%v, child_answered_delta=%d, "+
				"root_rx=%d child_rx=%d, goroutines=%d); numbers would be meaningless",
				prefix, err, child.answered.Load()-before,
				root.received.Load(), child.received.Load(), runtime.NumGoroutine())
		}

		// Let the warm-up's own detached V6 job settle so it is not
		// counted as backlog.
		time.Sleep(500 * time.Millisecond)
		runtime.GC()
		baseline = runtime.NumGoroutine()

		if dark {
			child.dropping.Store(true)
			defer child.dropping.Store(false)
		}

		var inflight, issuedN, resolvedN atomic.Int64
		stop := make(chan struct{})
		worstCh := make(chan outageSample, 1)
		go sampleGoroutines(stop, &inflight, baseline, worstCh)

		if dark {
			// Attribute the outage-arm backlog to its spawn sites while the
			// incident is at full pressure.
			midDump := time.AfterFunc(outageWindow*3/4, func() {
				dumpTopStacks(t, prefix+"-mid-outage", 10)
			})
			defer midDump.Stop()
		}

		var wg sync.WaitGroup
		deadline := time.Now().Add(outageWindow)
		for i := 0; time.Now().Before(deadline); i++ {
			wg.Add(1)
			issuedN.Add(1)
			inflight.Add(1)
			go func(n int) {
				defer wg.Done()
				defer inflight.Add(-1)
				if resolve(fmt.Sprintf("www.%s%d.test.", prefix, n), 10*time.Second) == nil {
					resolvedN.Add(1)
				}
			}(i)
			time.Sleep(arrivalRate)
		}
		wg.Wait()
		close(stop)
		return <-worstCh, issuedN.Load(), resolvedN.Load(), baseline
	}

	// Control arm — healthy network. This is what separates "the load
	// generator is holding goroutines" from "the outage is making SDNS
	// hold goroutines".
	healthy, healthyIssued, healthyOK, _ := runArm("ok", false)
	t.Logf("healthy: offered=%d resolved=%d peak_backlog=%d (goroutines=%d inflight=%d)",
		healthyIssued, healthyOK, healthy.backlog, healthy.goroutines, healthy.inflight)
	if healthyOK*10 < healthyIssued*8 {
		t.Fatalf("healthy arm resolved only %d/%d — the offered load saturates the resolver "+
			"even without an outage, so the arms are not comparable; lower the arrival rate",
			healthyOK, healthyIssued)
	}

	// Partial outage arm — leaf authorities dark, root keeps answering
	// referrals, queries keep arriving at the same rate.
	rootBefore, childBefore := root.received.Load(), child.received.Load()
	outage, outageIssued, outageOK, baseline := runArm("z", true)

	t.Logf("outage:  offered=%d resolved=%d peak_backlog=%d (goroutines=%d inflight=%d)",
		outageIssued, outageOK, outage.backlog, outage.goroutines, outage.inflight)
	t.Logf("wire during outage: root_rx=%d child_rx=%d (offered=%d) — "+
		"referrals answered, leaf queries swallowed",
		root.received.Load()-rootBefore, child.received.Load()-childBefore, outageIssued)

	// Destination-fairness arm — the "one provider's network is down"
	// scenario. Two dead zones (each hiding behind ever-fresh NS addresses,
	// so the circuit breaker cannot collapse them) receive half the load;
	// unique healthy zones receive the other half. The claim: the dead
	// destination pays for itself via its per-zone quota, and resolution
	// for everyone else keeps flowing.
	{
		settleDeadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(settleDeadline) &&
			runtime.NumGoroutine() > testStartGoroutines+20 {
			time.Sleep(250 * time.Millisecond)
		}

		r := newOutageResolver(rootServers, maxConcurrent)
		r.resolveTarget.Store(&mapper)

		resolve := func(name string) error {
			req := new(dns.Msg)
			req.SetQuestion(name, dns.TypeA)
			req.CheckingDisabled = true
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, contextKeyRequestID, req.Id)
			_, err := r.Resolve(ctx, req, rootServers, false, 30, 0, true, nil)
			return err
		}

		var wg sync.WaitGroup
		var healthyIss, healthyRes, darkIss atomic.Int64
		deadline := time.Now().Add(outageWindow)
		for i := 0; time.Now().Before(deadline); i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				if n%2 == 0 {
					healthyIss.Add(1)
					if resolve(fmt.Sprintf("www.good%d.test.", n)) == nil {
						healthyRes.Add(1)
					}
					return
				}
				darkIss.Add(1)
				// Half the load hammers two dead zones — many hosts, few
				// zones, exactly the popular-destination outage shape.
				_ = resolve(fmt.Sprintf("www%d.dead%d.test.", n, n%4/2))
			}(i)
			time.Sleep(arrivalRate)
		}
		wg.Wait()

		ratio := float64(healthyRes.Load()) / float64(max(healthyIss.Load(), 1))
		t.Logf("fairness: healthy=%d/%d (%.1f%%) dark_offered=%d",
			healthyRes.Load(), healthyIss.Load(), 100*ratio, darkIss.Load())

		// The healthy half must be essentially untouched by the dead
		// destination — this is the property that makes shedding
		// destination-scoped rather than resolver-wide.
		if ratio < 0.9 {
			t.Errorf("healthy resolution collapsed during a single-destination outage: "+
				"%d/%d (%.1f%%), want >= 90%%; the dead destination is starving healthy zones",
				healthyRes.Load(), healthyIss.Load(), 100*ratio)
		}
	}

	// Recovery — network restored, load stopped. Detached jobs get their
	// full 30s budget to retire; sample until they do or the budget expires.
	drained := runtime.NumGoroutine()
	if drained > baseline*2 {
		dumpTopStacks(t, "post-outage", 8)
	}
	drainDeadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(drainDeadline) {
		runtime.GC()
		drained = runtime.NumGoroutine()
		if drained <= baseline*2 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Logf("baseline=%d after_drain=%d max_concurrent=%d", baseline, drained, maxConcurrent)

	// Backlog bound. The claim under test: a partial outage must not grow the
	// resolver-internal backlog beyond a small multiple of the healthy arm
	// under identical offered load. Comparing arms makes the bound
	// independent of the harness's own caller goroutines.
	//
	// The enrichment lanes add a constant envelope on top: during an outage
	// every worker grinds a resolution against dead upstreams, and each such
	// resolution transiently holds a lookup, its racing exchange pair and
	// their reads. That envelope scales with the fixed worker count — never
	// with the offered load, which is the property this test defends.
	const perWorkerEnvelope = 6
	enrichEnvelope := 2 * nsEnrichWorkers * perWorkerEnvelope
	if limit := healthy.backlog*3 + maxConcurrent + enrichEnvelope; outage.backlog > limit {
		t.Errorf("outage grows internal goroutine backlog: healthy=%d, outage=%d, want <= %d "+
			"(goroutines=%d, inflight=%d); work accumulates faster than timeouts retire it",
			healthy.backlog, outage.backlog, limit, outage.goroutines, outage.inflight)
	}

	// Drain bound. Anything still running after the detached budget outlived
	// its request tree and will ratchet the floor incident over incident.
	if limit := baseline * 2; drained > limit {
		t.Errorf("goroutines did not drain after recovery: %d, want <= %d (baseline=%d); "+
			"detached work outlived its request tree",
			drained, limit, baseline)
	}
}

// zoneOf returns the parent zone of a www.<zone>.test. style name, i.e. the
// delegation point the root fixture refers to.
func zoneOf(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) < 3 {
		return ""
	}
	return dns.Fqdn(labels[len(labels)-2] + "." + labels[len(labels)-1])
}
