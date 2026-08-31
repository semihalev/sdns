package rpz

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/semihalev/sdns/config"
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
// sidecar matched nothing serves on the byte path — the commit-time
// count is the proof it stayed there.
func TestNoneCandidatesServeBytes(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	h.truth["clean.test."] = "198.51.100.1"

	h.serve(t, "clean.test.", "192.0.2.1:40000", true)
	before := h.spy.countHits
	w := h.serve(t, "clean.test.", "192.0.2.1:40000", true)
	if !w.Written() || len(w.Msg().Answer) != 1 {
		t.Fatal("clean hit did not answer the truth")
	}
	if h.spy.countHits != before+1 {
		t.Fatalf("clean hit did not serve bytes (count %d -> %d)", before, h.spy.countHits)
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
// outcome whether the byte path or the decoded path served it.
func TestCountingParityAcrossPaths(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	h.truth["pass.test."] = "198.51.100.9" // the /32 PASSTHRU rule

	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "passthru", "enforced")
	h.serve(t, "pass.test.", "192.0.2.1:40000", true) // miss: the wrap counts

	base := testutil.ToFloat64(counter)
	h.serve(t, "pass.test.", "192.0.2.1:40000", true) // byte-path hit
	byteDelta := testutil.ToFloat64(counter) - base

	base = testutil.ToFloat64(counter)
	h.serve(t, "pass.test.", "192.0.2.1:40000", false) // decoded hit
	decodedDelta := testutil.ToFloat64(counter) - base

	if byteDelta != 1 || decodedDelta != 1 {
		t.Fatalf("counting parity broken: byte=%v decoded=%v", byteDelta, decodedDelta)
	}
}

// TestChaseFoldCountsAZoneOnce pins the fold: two segments matching the
// same zone through different rules count that zone once, with the
// rank-best match.
func TestChaseFoldCountsAZoneOnce(t *testing.T) {
	h := newSidecarHarness(t, "enforce", config.RPZZone{Name: "resp", File: writeZone(t, respTestZone)})
	s := h.r.store.Load()

	seg1 := s.EvaluateResponse([]dns.RR{testA("a.test.", "203.0.113.1")})  // /24 NXDOMAIN
	seg2 := s.EvaluateResponse([]dns.RR{testA("b.test.", "198.51.100.9")}) // /32 PASSTHRU
	var chain middleware.SidecarChain
	chain.Append(&middleware.Sidecar{Value: seg1})
	chain.Append(&middleware.Sidecar{Value: seg2})

	counter := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "passthru", "enforced")
	other := actionTotal.WithLabelValues("resp", rpzengine.TriggerResponseIP, "nxdomain", "enforced")
	baseP, baseN := testutil.ToFloat64(counter), testutil.ToFloat64(other)
	h.r.CountWireChase(chain)
	if d := testutil.ToFloat64(counter) - baseP; d != 1 {
		t.Fatalf("rank-best (/32 passthru) counted %v times", d)
	}
	if d := testutil.ToFloat64(other) - baseN; d != 0 {
		t.Fatalf("the same zone was counted twice across segments (+%v nxdomain)", d)
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
	if w := h.serve(t, "bad.test.", "192.0.2.1:40000", true); w.Rcode() != dns.RcodeSuccess {
		t.Fatalf("shadow rewrote the hit: %d", w.Rcode())
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
