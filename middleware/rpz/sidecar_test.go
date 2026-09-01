package rpz

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/mock"
	rpzengine "github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/cache"
)

// The phase 4 exit criteria (design §6) as tests: truth in the cache,
// the P0 scenarios verbatim, per-client outcomes over one entry, reload
// re-evaluation, both counting paths.

const respTestZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
24.0.113.0.203.rpz-ip.rpz.test.  IN CNAME .
32.9.100.51.198.rpz-ip.rpz.test. IN CNAME rpz-passthru.
`

const qnameTestZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 2 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME .
`

// spyPolicy wraps the RPZ provider so a test can see which path served:
// Count* fires only on committed byte serves.
type spyPolicy struct {
	r *RPZ

	mu          sync.Mutex
	countHits   int
	countChases int
}

func (p *spyPolicy) SidecarEvaluator() middleware.SidecarEvaluator { return p.r.SidecarEvaluator() }
func (p *spyPolicy) WireHitGate() middleware.WireHitGate           { return p }

func (p *spyPolicy) JudgeWireHit(sc *middleware.Sidecar) middleware.WireHitVerdict {
	return p.r.JudgeWireHit(sc)
}

func (p *spyPolicy) JudgeWireChase(chain middleware.SidecarChain) middleware.WireHitVerdict {
	return p.r.JudgeWireChase(chain)
}

func (p *spyPolicy) CountWireHit(sc *middleware.Sidecar) {
	p.mu.Lock()
	p.countHits++
	p.mu.Unlock()
	p.r.CountWireHit(sc)
}

func (p *spyPolicy) CountWireChase(chain middleware.SidecarChain) {
	p.mu.Lock()
	p.countChases++
	p.mu.Unlock()
	p.r.CountWireChase(chain)
}

// chainQueryer routes the cache's decoded CNAME chase back through the
// same handlers, the shape Setup wires in production.
type chainQueryer struct {
	handlers []middleware.Handler
}

func (q *chainQueryer) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain(q.handlers)
	ch.Reset(w, req)
	ch.Next(context.Background())
	if !w.Written() {
		return nil, middleware.ErrNoResponse
	}
	return w.Msg(), nil
}

// sidecarHarness is one full rpz→cache→authority pipeline with the seam
// wired the way Setup wires it.
type sidecarHarness struct {
	r     *RPZ
	c     *cache.Cache
	spy   *spyPolicy
	truth map[string]string // qname -> A address the authority serves
}

func newSidecarHarness(t *testing.T, mode string, zones ...config.RPZZone) *sidecarHarness {
	t.Helper()
	h := &sidecarHarness{
		r:     newRPZ(t, mode, zones...),
		c:     cache.New(&config.Config{CacheSize: 1024, Expire: 600}),
		truth: map[string]string{},
	}
	t.Cleanup(h.c.Stop)
	h.spy = &spyPolicy{r: h.r}
	h.c.SetSidecarPolicy(h.spy)
	h.c.SetQueryer(&chainQueryer{handlers: []middleware.Handler{h.c, h.authority()}})
	return h
}

func (h *sidecarHarness) authority() middleware.Handler {
	return middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		req := ch.Request.Msg()
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		if addr, ok := h.truth[req.Question[0].Name]; ok {
			resp.Answer = []dns.RR{testA(req.Question[0].Name, addr)}
		} else {
			resp.Rcode = dns.RcodeNameError
		}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
}

func testA(name, addr string) *dns.A {
	rr, err := dns.NewRR(name + " 300 IN A " + addr)
	if err != nil {
		panic(err)
	}
	return rr.(*dns.A)
}

// serve drives one query; bytePath allows the direct-pack byte serve.
func (h *sidecarHarness) serve(t *testing.T, qname, clientAddr string, bytePath bool) *mock.Writer {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("refused")
	}
	w := mock.NewWriter("udp", clientAddr)
	ch := middleware.NewChain([]middleware.Handler{h.r, h.c, h.authority()})
	ch.ResetWire(w, req)
	if bytePath {
		ch.AllowDirectPack()
	}
	ch.Next(context.Background())
	return w
}

// wireServed reads the cache's byte-fast-path counter for one outcome
// ("served" for exact hits, "chase_served" for compositions) through the
// prometheus registry — the only honest way to tell a byte serve from a
// decoded one: on a direct-pack chain even decoded WriteMsg reaches the
// transport as raw bytes, so the transport cannot testify.
func wireServed(t *testing.T, outcome string) float64 {
	t.Helper()
	metric.FlushAll()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "dns_cache_wire_fastpath_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "outcome" && l.GetValue() == outcome {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// cacheStore reaches the concrete store behind the wiring interface.
func (h *sidecarHarness) cacheStore() *cache.Store {
	return h.c.Store().(*cache.Store)
}

// storedEntry reads the cache's stored entry for qname.
func (h *sidecarHarness) storedEntry(t *testing.T, qname string) *cache.CacheEntry {
	t.Helper()
	key := cache.CacheKey{
		Question: dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}.Hash()
	entry, ok := h.cacheStore().LookupByKey(key)
	if !ok {
		t.Fatalf("%s: no cached entry", qname)
	}
	return entry
}

// storedTruth reads the cache's stored answer for qname.
func (h *sidecarHarness) storedTruth(t *testing.T, qname string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	req.RecursionDesired = true
	m, found := h.cacheStore().Get(req)
	if !found {
		t.Fatalf("%s: no cached answer", qname)
	}
	return m
}

// TestTruthInCacheRewriteToClient pins §5.6 item 1: the client is
// rewritten, the cache stores the resolver's truth untouched — on the
// miss and on every hit after it.
func TestTruthInCacheRewriteToClient(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	h.truth["bad.test."] = "203.0.113.10"

	for _, pass := range []string{"miss", "hit"} {
		w := h.serve(t, "bad.test.", "192.0.2.1:40000", true)
		if !w.Written() || w.Rcode() != dns.RcodeNameError {
			t.Fatalf("%s: client not rewritten: rcode=%d", pass, w.Rcode())
		}
	}

	stored := h.storedTruth(t, "bad.test.")
	if len(stored.Answer) != 1 || stored.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatalf("the cache does not hold the truth: %v", stored.Answer)
	}
}

// TestNoneCandidatesServeBytes pins the fast-path half: a hit whose
// sidecar matched nothing serves on the byte path.
func TestNoneCandidatesServeBytes(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	h.truth["clean.test."] = "198.51.100.1"

	h.serve(t, "clean.test.", "192.0.2.1:40000", true)
	before := wireServed(t, "served")
	w := h.serve(t, "clean.test.", "192.0.2.1:40000", true)
	if !w.Written() || len(w.Msg().Answer) != 1 {
		t.Fatal("clean hit did not answer the truth")
	}
	if wireServed(t, "served")-before != 1 {
		t.Fatal("clean hit did not serve on the byte fast path")
	}
}

// TestP0HeldQNAMEOverridesANoneSidecar is the review's P0 scenario
// verbatim: zone 1 carries response-IP rules that do NOT match the
// answer, zone 2's QNAME rule does — the query answers NXDOMAIN on the
// miss AND on the hit, never the stored truth.
func TestP0HeldQNAMEOverridesANoneSidecar(t *testing.T) {
	h := newSidecarHarness(t, "enforce",
		config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)},
		config.RPZZone{Name: "names", File: writeZone(t, qnameTestZone)},
	)
	h.truth["victim.example.com."] = "198.51.100.7" // matches no response rule

	for _, pass := range []string{"miss", "hit"} {
		w := h.serve(t, "victim.example.com.", "192.0.2.1:40000", true)
		if !w.Written() || w.Rcode() != dns.RcodeNameError {
			t.Fatalf("%s: held QNAME candidate lost to a none sidecar: rcode=%d", pass, w.Rcode())
		}
	}
	stored := h.storedTruth(t, "victim.example.com.")
	if len(stored.Answer) != 1 {
		t.Fatal("the truth was not cached under the rewrite")
	}
}

// TestPerClientOutcomesOverOneEntry pins the C3 scenario: a CLIENT-IP
// PASSTHRU client reads the truth from the same entry a plain client is
// rewritten from.
func TestPerClientOutcomesOverOneEntry(t *testing.T) {
	const mixedZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 3 3600 900 604800 300
32.9.2.0.192.rpz-client-ip.rpz.test. IN CNAME rpz-passthru.
24.0.113.0.203.rpz-ip.rpz.test.      IN CNAME .
`
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "mixed", File: writeZone(t, mixedZone)})
	h.truth["bad.test."] = "203.0.113.10"

	// The plain client primes the entry and is rewritten.
	if w := h.serve(t, "bad.test.", "192.0.2.55:40000", true); w.Rcode() != dns.RcodeNameError {
		t.Fatalf("plain client not rewritten: %d", w.Rcode())
	}
	// The exempted client reads the truth from the same entry.
	w := h.serve(t, "bad.test.", "192.0.2.9:40000", true)
	if w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 1 {
		t.Fatalf("PASSTHRU client did not get the truth: rcode=%d", w.Rcode())
	}
	// And the plain client keeps being rewritten afterwards.
	if w := h.serve(t, "bad.test.", "192.0.2.55:40000", true); w.Rcode() != dns.RcodeNameError {
		t.Fatalf("plain client served the truth after the exempted read: %d", w.Rcode())
	}
}

// TestReloadReevaluatesStaleSidecars pins §5.6 item 5 end to end: an
// entry stamped "none" under generation N must not keep serving bytes
// after a reload whose rules newly match it — the first serve under N+1
// re-evaluates and answers from the fresh result.
func TestReloadReevaluatesStaleSidecars(t *testing.T) {
	// The initial rules miss 198.51.100.20; the reload adds a rule that
	// hits it.
	path := writeZone(t, respTestZone)
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: path})
	h.truth["moving.test."] = "198.51.100.20"

	h.serve(t, "moving.test.", "192.0.2.1:40000", true)
	if w := h.serve(t, "moving.test.", "192.0.2.1:40000", true); w.Rcode() != dns.RcodeSuccess {
		t.Fatalf("pre-reload hit: %d", w.Rcode())
	}

	writeZoneTo(t, path, respTestZone+"32.20.100.51.198.rpz-ip.rpz.test. IN CNAME .\n")
	h.r.reload(0)

	if w := h.serve(t, "moving.test.", "192.0.2.1:40000", true); w.Rcode() != dns.RcodeNameError {
		t.Fatalf("a stale none sidecar kept serving the truth after the reload: %d", w.Rcode())
	}
}

// TestAdmissionDoorsLeaveEvaluatedSidecars pins the §6 bullet with the
// real evaluator: an entry admitted through the store's direct door
// carries a generation-stamped match list.
func TestAdmissionDoorsLeaveEvaluatedSidecars(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})

	resp := new(dns.Msg)
	resp.SetQuestion("direct.test.", dns.TypeA)
	resp.Response = true
	resp.Answer = []dns.RR{testA("direct.test.", "203.0.113.10")}
	h.c.Store().(middleware.CutStore).SetFromResponseWithCut(resp, false, time.Time{}, 0)

	sc := h.storedEntry(t, "direct.test.").Sidecar()
	if sc == nil {
		t.Fatal("the direct admission door left an unevaluated entry")
	}
	rm, ok := sc.Value.(*rpzengine.ResponseMatches)
	if !ok || rm.Gen != h.r.store.Load().Gen || len(rm.List) != 1 {
		t.Fatalf("sidecar: %+v", sc.Value)
	}
}

// TestCountingParityAcrossPaths pins the §6 counting bullet: the same
// query over the same entry counts the same zone, trigger, action and
// outcome whether the byte path or the decoded path served it — and the
// byte leg is proven to actually BE the byte path: a matched PASSTHRU
// hit serves raw bytes, counted through the gate's memoized decision at
// the commit, with no decode anywhere (§5.6's field-reads-and-counters
// serve flow).
func TestCountingParityAcrossPaths(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	h.truth["pass.test."] = "198.51.100.9" // the /32 PASSTHRU rule

	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "passthru", "enforced")
	h.serve(t, "pass.test.", "192.0.2.1:40000", true) // miss: the wrap counts

	base := testutil.ToFloat64(counter)
	servedBase := wireServed(t, "served")
	w := h.serve(t, "pass.test.", "192.0.2.1:40000", true)
	byteDelta := testutil.ToFloat64(counter) - base
	if wireServed(t, "served")-servedBase != 1 {
		t.Fatal("the matched PASSTHRU hit decoded; §5.11 wants it on the wire path")
	}
	if !w.Written() || w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 1 {
		t.Fatal("byte-path hit did not serve the truth")
	}

	base = testutil.ToFloat64(counter)
	servedBase = wireServed(t, "served")
	w = h.serve(t, "pass.test.", "192.0.2.1:40000", false) // decoded hit
	decodedDelta := testutil.ToFloat64(counter) - base
	if wireServed(t, "served")-servedBase != 0 {
		t.Fatal("the decoded leg served bytes; the parity comparison measured nothing")
	}
	_ = w

	if byteDelta != 1 || decodedDelta != 1 {
		t.Fatalf("counting parity broken: byte=%v decoded=%v", byteDelta, decodedDelta)
	}
}

// TestChaseCountsAZoneOnceWithTheRankBest pins §5.6 item 4 end to end: a
// chase whose composed answer matches one zone through two competing
// rules counts that zone exactly once, with the rule-4 best — the gate
// sends any matching chase to the decoded path, whose composed answer
// the wrap evaluates whole, so the dedupe holds by construction.
func TestChaseCountsAZoneOnceWithTheRankBest(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})

	alias := new(dns.Msg)
	alias.SetQuestion("alias.chase.test.", dns.TypeA)
	alias.Response = true
	cn, err := dns.NewRR("alias.chase.test. 300 IN CNAME t.chase.test.")
	if err != nil {
		t.Fatal(err)
	}
	alias.Answer = []dns.RR{cn}
	h.cacheStore().SetFromResponseWithCut(alias, false, time.Time{}, 0)

	target := new(dns.Msg)
	target.SetQuestion("t.chase.test.", dns.TypeA)
	target.Response = true
	// Two addresses under one zone's competing rules: the /24 says
	// NXDOMAIN, the /32 says PASSTHRU — rule 4 picks the /32.
	target.Answer = []dns.RR{testA("t.chase.test.", "203.0.113.5"), testA("t.chase.test.", "198.51.100.9")}
	h.cacheStore().SetFromResponseWithCut(target, false, time.Time{}, 0)

	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "passthru", "enforced")
	other := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "nxdomain", "enforced")
	baseP, baseN := testutil.ToFloat64(counter), testutil.ToFloat64(other)

	w := h.serve(t, "alias.chase.test.", "192.0.2.1:40000", true)
	if !w.Written() || w.Rcode() != dns.RcodeSuccess {
		t.Fatalf("PASSTHRU chase did not serve the truth: rcode=%d", w.Rcode())
	}
	if d := testutil.ToFloat64(counter) - baseP; d != 1 {
		t.Fatalf("rank-best (/32 passthru) counted %v times, want 1", d)
	}
	if d := testutil.ToFloat64(other) - baseN; d != 0 {
		t.Fatalf("the zone was counted twice across the chase (+%v nxdomain)", d)
	}
}

// TestShadowObservesResponseMatches pins shadow on the response side:
// nothing rewritten, the winner observed — both paths.
func TestShadowObservesResponseMatches(t *testing.T) {
	h := newSidecarHarness(t, "shadow", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	h.truth["bad.test."] = "203.0.113.10"

	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "nxdomain", "observed")
	base := testutil.ToFloat64(counter)

	if w := h.serve(t, "bad.test.", "192.0.2.1:40000", true); w.Rcode() != dns.RcodeSuccess {
		t.Fatalf("shadow rewrote: %d", w.Rcode())
	}
	servedBase := wireServed(t, "served")
	w := h.serve(t, "bad.test.", "192.0.2.1:40000", true)
	if w.Rcode() != dns.RcodeSuccess {
		t.Fatalf("shadow rewrote the hit: %d", w.Rcode())
	}
	if wireServed(t, "served")-servedBase != 1 {
		t.Fatal("shadow's matched hit decoded; observation must not cost the wire path")
	}
	if d := testutil.ToFloat64(counter) - base; d != 2 {
		t.Fatalf("shadow observed %v matches over miss+hit, want 2", d)
	}
}

// writeZoneTo rewrites a zone fixture file in place.
func writeZoneTo(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestEarlierResponseZoneDisplacesLaterQNAME is the other half of §5.4:
// zone order outranks trigger type, so a held QNAME match in zone 2
// loses to zone 1's response-IP match when the answer arrives. The two
// rules prescribe different actions, so a wrong winner cannot pass.
func TestEarlierResponseZoneDisplacesLaterQNAME(t *testing.T) {
	const nodataQnameZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 4 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME *.
`
	h := newSidecarHarness(t, "enforce",
		config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)},
		config.RPZZone{Name: "names", File: writeZone(t, nodataQnameZone)},
	)
	h.truth["victim.example.com."] = "203.0.113.10" // matches zone 1's /24 NXDOMAIN

	for _, pass := range []string{"miss", "hit"} {
		w := h.serve(t, "victim.example.com.", "192.0.2.1:40000", true)
		if !w.Written() || w.Rcode() != dns.RcodeNameError {
			t.Fatalf("%s: zone 1's response match did not displace zone 2's QNAME (rcode=%d, want NXDOMAIN)", pass, w.Rcode())
		}
	}
}

// TestConcurrentReloadAndPolicedServe is the §6 -race bullet over the
// full pipeline: readers serve a policed name while a writer reloads the
// zone between two rule generations; every answer must be one
// generation's whole outcome.
func TestConcurrentReloadAndPolicedServe(t *testing.T) {
	path := writeZone(t, respTestZone)
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: path})
	h.truth["bad.test."] = "203.0.113.10"
	h.serve(t, "bad.test.", "192.0.2.1:40000", true) // prime the entry

	// Generation A: the /24 rule says NXDOMAIN. Generation B: NODATA.
	const genB = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 9 3600 900 604800 300
24.0.113.0.203.rpz-ip.rpz.test. IN CNAME *.
`
	stop := make(chan struct{})
	torn := make(chan string, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := range 60 {
			if i%2 == 0 {
				writeZoneTo(t, path, genB)
			} else {
				writeZoneTo(t, path, respTestZone)
			}
			h.r.reload(0)
		}
	}()
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				w := h.serve(t, "bad.test.", "192.0.2.1:40000", true)
				if !w.Written() {
					torn <- "no answer"
					return
				}
				rc := w.Rcode()
				nodata := rc == dns.RcodeSuccess && len(w.Msg().Answer) == 0
				if rc != dns.RcodeNameError && !nodata {
					torn <- "neither generation's outcome: rcode=" + dns.RcodeToString[rc]
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case msg := <-torn:
		t.Fatal(msg)
	default:
	}
}

// TestFinalWinnerSilencesLaterResponseZones pins the winner-bounded cut
// across the phases' seam: a final query-time winner in zone 0 leaves
// response zones after it uncounted — in shadow, where the query
// continues, exactly as in enforce, where it never leaves rpz. Anything
// else makes the two modes' counters incomparable.
func TestFinalWinnerSilencesLaterResponseZones(t *testing.T) {
	const qnameFirstZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 6 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME .
`
	respAfter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "nxdomain", "observed")

	for _, mode := range []string{"shadow", "enforce"} {
		h := newSidecarHarness(t, mode,
			config.RPZZone{Name: "names", File: writeZone(t, qnameFirstZone)},
			config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)},
		)
		h.truth["victim.example.com."] = "203.0.113.10" // matches zone 1's response rule

		base := testutil.ToFloat64(respAfter)
		h.serve(t, "victim.example.com.", "192.0.2.1:40000", true) // miss
		h.serve(t, "victim.example.com.", "192.0.2.1:40000", true) // hit
		if d := testutil.ToFloat64(respAfter) - base; d != 0 {
			t.Fatalf("%s: a response zone past the final winner was counted %v times", mode, d)
		}
	}
}

// TestCleanServesAllocateNoMoreWithResponseRules pins §5.11 against the
// two allocation regressions the review found: with response rules
// configured, the all-candidates-none wire hit and the clean admission
// must cost exactly what a qname-only configuration costs — the wrap is
// pooled and the explicit none is the generation's shared sentinel.
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
			h.cacheStore().SetFromResponseWithCut(resp, false, time.Time{}, 0)
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

// TestExplicitNoneIsTheSharedSentinel pins the none representation
// directly: two clean admissions carry the same sidecar object — the
// generation's sentinel — not one allocation each.
func TestExplicitNoneIsTheSharedSentinel(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})

	for _, name := range []string{"one.none.test.", "two.none.test."} {
		resp := new(dns.Msg)
		resp.SetQuestion(name, dns.TypeA)
		resp.Response = true
		resp.Answer = []dns.RR{testA(name, "198.51.100.1")}
		h.cacheStore().SetFromResponseWithCut(resp, false, time.Time{}, 0)
	}
	one := h.storedEntry(t, "one.none.test.").Sidecar()
	two := h.storedEntry(t, "two.none.test.").Sidecar()
	if one == nil || one != two {
		t.Fatal("clean admissions do not share the generation's none sentinel")
	}
	if one != h.r.store.Load().none {
		t.Fatal("the stamped none is not the published generation's own")
	}
}

// TestVanishedRulesStillCountHeldObservations pins the review's P1: a
// policed wrap installed while response triggers existed carries
// disabled query-time observations; a reload that drops the last
// response trigger before the judge must not shortcut past them — they
// count under any generation, so the judge still produces the decision
// token and the commit still counts exactly once.
func TestVanishedRulesStillCountHeldObservations(t *testing.T) {
	const disabledQnameZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 8 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME *.
`
	// The zone is disabled; its QNAME match is an observation.
	h := newSidecarHarness(t, "enforce", config.RPZZone{
		Name: "obs", File: writeZone(t, disabledQnameZone), Policy: "disabled",
	})
	s := h.r.store.Load()
	if s.HasResponseIP() {
		t.Fatal("fixture must have no response rules at judge time")
	}
	held := rpzengine.ZoneMatch{
		ZoneIdx: 0, Zone: s.Zones[0],
		Rule: &rpzengine.Rule{Action: rpzengine.ActionNODATA}, Trigger: rpzengine.TriggerQNAME,
	}
	wrap := &responseWrap{r: h.r, mode: wrapPoliced, heldObserved: []rpzengine.ZoneMatch{held}}

	counter := actionTotal.WithLabelValues("obs", rpzengine.TriggerQNAME, "nodata", "observed")
	base := testutil.ToFloat64(counter)
	if v := wrap.JudgeWireHit(nil); v != middleware.WireHitServe {
		t.Fatalf("verdict = %v, want Serve", v)
	}
	wrap.CountWireHit(nil)
	if d := testutil.ToFloat64(counter) - base; d != 1 {
		t.Fatalf("the held observation was dropped with the vanished rules: counted %v times", d)
	}
	// Exactly once: a second commit without a new judge counts nothing.
	wrap.CountWireHit(nil)
	if d := testutil.ToFloat64(counter) - base; d != 1 {
		t.Fatalf("the decision was counted twice: %v", d)
	}
}

// TestAbandonedDecisionIsNotCountedLater pins the review's P2: a judge
// that memoized a decision and was abandoned before its commit must not
// leak that memo into a later judge's commit — every judge voids the
// token first, and only its own Serve re-arms it.
func TestAbandonedDecisionIsNotCountedLater(t *testing.T) {
	h := newSidecarHarness(t, "shadow", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	s := h.r.store.Load()
	sc := &middleware.Sidecar{Value: &rpzengine.ResponseMatches{
		Gen:  s.Gen,
		List: s.EvaluateResponseList([]dns.RR{testA("x.test.", "203.0.113.10")}),
	}}
	wrap := &responseWrap{r: h.r, mode: wrapPoliced}

	// Judge 1 memoizes a shadow observation and is then abandoned.
	if v := wrap.JudgeWireHit(sc); v != middleware.WireHitServe {
		t.Fatalf("first verdict = %v, want Serve", v)
	}

	// The world changes: the reload drops every response rule.
	const qnameOnly = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 9 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME .
`
	z, err := rpzengine.LoadZone("resp", strings.NewReader(qnameOnly), "reload", rpzengine.OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	h.r.publishStore(&rpzengine.Store{Zones: []*rpzengine.Zone{z}})

	// Judge 2 finds nothing to decide; the commit after it must count
	// nothing — never judge 1's stale memo.
	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "nxdomain", "observed")
	base := testutil.ToFloat64(counter)
	if v := wrap.JudgeWireHit(sc); v != middleware.WireHitServe {
		t.Fatalf("second verdict = %v, want Serve", v)
	}
	wrap.CountWireHit(sc)
	if d := testutil.ToFloat64(counter) - base; d != 0 {
		t.Fatalf("an abandoned judge's decision was counted by a later commit: %v", d)
	}
}

// serveProto is serve with the transport under test.
func (h *sidecarHarness) serveProto(t *testing.T, qname, proto string) *mock.Writer {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("refused")
	}
	w := mock.NewWriter(proto, "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{h.r, h.c, h.authority()})
	ch.ResetWire(w, req)
	ch.AllowDirectPack()
	ch.Next(context.Background())
	return w
}

// TestResponseActionsEndToEnd drives the wrap's remaining actions over
// real resolutions: DROP swallows the reply, TCP-Only truncates UDP and
// passes other transports, NODATA empties the answer, and Local Data
// answers with the rule's records on the client's qname.
func TestResponseActionsEndToEnd(t *testing.T) {
	const actionZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
24.0.113.0.203.rpz-ip.rpz.test. IN CNAME rpz-drop.
24.0.100.51.198.rpz-ip.rpz.test. IN CNAME rpz-tcp-only.
24.0.2.0.192.rpz-ip.rpz.test.   IN CNAME *.
16.0.0.0.10.rpz-ip.rpz.test.    IN A 203.0.113.53
`
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "act", File: writeZone(t, actionZone)})
	h.truth["dropme.test."] = "203.0.113.5"
	h.truth["tcpme.test."] = "198.51.100.5"
	h.truth["nodatame.test."] = "192.0.2.5"
	h.truth["localme.test."] = "10.0.1.2"

	for _, pass := range []string{"miss", "hit"} {
		if w := h.serve(t, "dropme.test.", "192.0.2.1:40000", true); w.Written() {
			t.Fatalf("%s: DROP wrote a reply", pass)
		}
		w := h.serve(t, "tcpme.test.", "192.0.2.1:40000", true)
		if !w.Written() || !w.Msg().Truncated || len(w.Msg().Answer) != 0 {
			t.Fatalf("%s: TCP-Only over UDP must truncate emptily: tc=%v answers=%d", pass, w.Msg().Truncated, len(w.Msg().Answer))
		}
		w = h.serve(t, "nodatame.test.", "192.0.2.1:40000", true)
		if w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 0 || w.Msg().AuthenticatedData {
			t.Fatalf("%s: NODATA broken: rcode=%d answers=%d", pass, w.Rcode(), len(w.Msg().Answer))
		}
		w = h.serve(t, "localme.test.", "192.0.2.1:40000", true)
		if w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 1 {
			t.Fatalf("%s: Local Data broken: rcode=%d answers=%d", pass, w.Rcode(), len(w.Msg().Answer))
		}
		a := w.Msg().Answer[0].(*dns.A)
		if a.Hdr.Name != "localme.test." || a.A.String() != "203.0.113.53" {
			t.Fatalf("%s: Local Data owner/rdata: %v", pass, a)
		}
	}

	// A non-UDP transport already satisfies TCP-Only: the truth flows.
	w := h.serveProto(t, "tcpme.test.", "tcp")
	if w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 1 || w.Msg().Truncated {
		t.Fatalf("TCP-Only over TCP must pass the truth: rcode=%d tc=%v", w.Rcode(), w.Msg().Truncated)
	}
}

// TestNeutralGateServesExemptQueriesUntouched pins the global gate's
// contract — the gate un-wrapped (exempt) queries reach: entries stay
// healthy (stale restamps) but even a matching sidecar serves the truth
// and counts nothing, because policy does not apply to those queries.
func TestNeutralGateServesExemptQueriesUntouched(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	s := h.r.store.Load()

	matching := &middleware.Sidecar{Value: &rpzengine.ResponseMatches{
		Gen:  s.Gen,
		List: s.EvaluateResponseList([]dns.RR{testA("x.test.", "203.0.113.10")}),
	}}
	if v := h.r.JudgeWireHit(matching); v != middleware.WireHitServe {
		t.Fatalf("a matching entry must still serve an exempt query: %v", v)
	}
	if v := h.r.JudgeWireHit(nil); v != middleware.WireHitRestamp {
		t.Fatalf("an unevaluated entry must restamp: %v", v)
	}
	stale := &middleware.Sidecar{Value: &rpzengine.ResponseMatches{Gen: s.Gen - 1}}
	if v := h.r.JudgeWireHit(stale); v != middleware.WireHitRestamp {
		t.Fatalf("a stale entry must restamp: %v", v)
	}

	var chain middleware.SidecarChain
	chain.Append(matching)
	if v := h.r.JudgeWireChase(chain); v != middleware.WireHitServe {
		t.Fatalf("chase with fresh segments must serve: %v", v)
	}
	var staleChain middleware.SidecarChain
	staleChain.Append(stale)
	if v := h.r.JudgeWireChase(staleChain); v != middleware.WireHitRestamp {
		t.Fatalf("chase with a stale segment must restamp: %v", v)
	}

	// Counting nothing is the whole point.
	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "nxdomain", "enforced")
	base := testutil.ToFloat64(counter)
	h.r.CountWireHit(matching)
	h.r.CountWireChase(chain)
	if d := testutil.ToFloat64(counter) - base; d != 0 {
		t.Fatalf("the neutral gate counted an exempt query: %v", d)
	}

	// Without response rules everything serves, whatever the sidecar.
	bare := newRPZ(t, "enforce", config.RPZZone{Name: "plain", File: writeZone(t, testZone)})
	if v := bare.JudgeWireHit(nil); v != middleware.WireHitServe {
		t.Fatalf("no response rules must mean Serve: %v", v)
	}
	if v := bare.WireHitGate().JudgeWireChase(middleware.SidecarChain{}); v != middleware.WireHitServe {
		t.Fatalf("no response rules must mean Serve for chases too: %v", v)
	}
}

// TestDecodedRequestsSeeTheSamePolicy drives the Msg-born request path
// (ch.Reset, not ResetWire): the decoded key build must reach the same
// verdicts the wire-born path does.
func TestDecodedRequestsSeeTheSamePolicy(t *testing.T) {
	r := testRPZ(t, "enforce")

	q := new(dns.Msg)
	q.SetQuestion("nx.example.com.", dns.TypeA)
	q.RecursionDesired = true
	passed := false
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		ch.Cancel()
	})
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.Reset(w, q)
	ch.Next(context.Background())

	if passed || !w.Written() || w.Rcode() != dns.RcodeNameError {
		t.Fatalf("decoded request escaped policy: passed=%v rcode=%d", passed, w.Rcode())
	}
}
