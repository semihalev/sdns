package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// recordingPolicy is a SidecarPolicyProvider that remembers what the seam
// showed it: every message the evaluator saw and every sidecar set the
// gate judged.
type recordingPolicy struct {
	mu        sync.Mutex
	evaluated []string
	hits      []*middleware.Sidecar
	chases    [][]*middleware.Sidecar
	allow     bool
}

func (p *recordingPolicy) SidecarEvaluator() middleware.SidecarEvaluator {
	return func(msg *dns.Msg) *middleware.Sidecar {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.evaluated = append(p.evaluated, msg.Question[0].Name)
		return &middleware.Sidecar{Value: msg.Question[0].Name}
	}
}

func (p *recordingPolicy) WireHitGate() middleware.WireHitGate { return p }

func (p *recordingPolicy) AllowWireHit(sc *middleware.Sidecar) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hits = append(p.hits, sc)
	return p.allow
}

func (p *recordingPolicy) AllowWireChase(scs []*middleware.Sidecar) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.chases = append(p.chases, append([]*middleware.Sidecar(nil), scs...))
	return p.allow
}

func seamResponse(name string, answers ...dns.RR) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetQuestion(name, dns.TypeA)
	resp.Response = true
	resp.RecursionAvailable = true
	resp.Answer = answers
	return resp
}

func seamA(name string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 1},
	}
}

// TestEveryAdmissionDoorStampsTheSidecar pins the seam's admission
// contract: no door admits an entry unevaluated while an evaluator is
// wired — the writer/resolver funnel, the prefetch CAS replacement, and
// the compatibility Set alike.
func TestEveryAdmissionDoorStampsTheSidecar(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()
	p := &recordingPolicy{allow: true}
	c.SetSidecarPolicy(p)

	// Door 1: the SetFromResponse funnel (writer and resolver paths).
	resp := seamResponse("door1.test.", seamA("door1.test."))
	c.store.SetFromResponseWithCut(resp, false, time.Time{}, 0)
	key := CacheKey{Question: resp.Question[0], CD: false}.Hash()
	entry, ok := c.store.LookupByKey(key)
	if !ok || entry.Sidecar() == nil {
		t.Fatal("the SetFromResponse funnel admitted an unevaluated entry")
	}
	if entry.Sidecar().Value != "door1.test." {
		t.Fatalf("evaluator saw the wrong message: %v", entry.Sidecar().Value)
	}

	// Door 2: the prefetch replacement.
	if !c.store.ReplaceIfCurrent(key, entry, seamResponse("door1.test.", seamA("door1.test.")), time.Time{}, 0) {
		t.Fatal("replacement declined")
	}
	replaced, ok := c.store.LookupByKey(key)
	if !ok || replaced == entry {
		t.Fatal("replacement did not install a new entry")
	}
	if replaced.Sidecar() == nil {
		t.Fatal("the replacement door admitted an unevaluated entry")
	}

	// Door 3: the compatibility Set.
	resp3 := seamResponse("door3.test.", seamA("door3.test."))
	key3 := CacheKey{Question: resp3.Question[0], CD: false}.Hash()
	c.Set(key3, resp3)
	entry3, ok := c.store.LookupByKey(key3)
	if !ok || entry3.Sidecar() == nil {
		t.Fatal("the compatibility Set admitted an unevaluated entry")
	}
}

// TestUnwiredSeamLeavesEntriesUnstamped pins the nil half of the
// contract: with no policy registered, entries carry a nil sidecar and
// nothing is consulted — today's behavior, byte for byte.
func TestUnwiredSeamLeavesEntriesUnstamped(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	resp := seamResponse("plain.test.", seamA("plain.test."))
	c.store.SetFromResponseWithCut(resp, false, time.Time{}, 0)
	entry, ok := c.store.LookupByKey(CacheKey{Question: resp.Question[0], CD: false}.Hash())
	if !ok {
		t.Fatal("entry missing")
	}
	if entry.Sidecar() != nil {
		t.Fatal("an unwired seam stamped a sidecar")
	}
}

// seamServe drives one query through cache + terminal on the Msg-born
// path. AllowDirectPack declares the mock an owned byte sink, so hits
// the gate approves genuinely serve bytes (the mock unpacks them for the
// same asserts either way).
func seamServe(t *testing.T, c *Cache, name string) *mock.Writer {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.RecursionDesired = true

	terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := seamResponse(name, seamA(name))
		resp.SetReply(ch.Request.Msg())
		resp.Answer = []dns.RR{seamA(name)}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
	w := mock.NewWriter("udp", "192.0.2.9:53000")
	ch := middleware.NewChain([]middleware.Handler{c, terminal})
	ch.Reset(w, q)
	ch.AllowDirectPack()
	ch.Next(context.Background())
	return w
}

// TestWireGateDeclineFallsToTheDecodedPath pins the serve half: a gate
// that turns a byte serve away is consulted with the entry's own sidecar,
// and the same query is answered — correctly — by the decoded path.
func TestWireGateDeclineFallsToTheDecodedPath(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()
	p := &recordingPolicy{allow: false}
	c.SetSidecarPolicy(p)

	seamServe(t, c, "gated.test.") // miss primes the entry
	before := len(p.hits)
	w := seamServe(t, c, "gated.test.") // hit
	if !w.Written() || w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 1 {
		t.Fatalf("declined byte serve did not answer from the decoded path: written=%v rcode=%d", w.Written(), w.Rcode())
	}
	if len(p.hits) == before {
		t.Fatal("the gate was never consulted on a hit")
	}
	sc := p.hits[len(p.hits)-1]
	if sc == nil || sc.Value != "gated.test." {
		t.Fatalf("the gate saw the wrong sidecar: %v", sc)
	}
}

// TestWireGateApprovalServesBytes is the other verdict: an allowing gate
// is consulted and the hit still serves.
func TestWireGateApprovalServesBytes(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()
	p := &recordingPolicy{allow: true}
	c.SetSidecarPolicy(p)

	seamServe(t, c, "open.test.")
	served := wireFastServed.Value()
	w := seamServe(t, c, "open.test.")
	if !w.Written() || len(w.Msg().Answer) != 1 {
		t.Fatal("approved hit did not answer")
	}
	if len(p.hits) == 0 {
		t.Fatal("the gate was never consulted")
	}
	if wireFastServed.Value() == served {
		t.Fatal("an approving gate kept the hit off the byte path")
	}
}

// TestDecodedServeStampsAnUnevaluatedEntry pins the unknown-never-clean
// recovery: an entry admitted before the seam was wired carries no
// sidecar, the gate turns its byte serve away, and the decoded serve that
// answers instead evaluates and stamps it — the next hit has a sidecar.
func TestDecodedServeStampsAnUnevaluatedEntry(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	seamServe(t, c, "late.test.") // admitted with no evaluator wired

	p := &recordingPolicy{allow: false}
	c.SetSidecarPolicy(p)
	w := seamServe(t, c, "late.test.")
	if !w.Written() {
		t.Fatal("hit did not answer")
	}

	key := CacheKey{Question: dns.Question{Name: "late.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, CD: false}.Hash()
	entry, ok := c.store.LookupByKey(key)
	if !ok {
		t.Fatal("entry missing")
	}
	if entry.Sidecar() == nil {
		t.Fatal("the decoded serve left the entry unevaluated; every later hit stays off the byte path forever")
	}
}

// TestChaseGateSeesEverySegmentInOrder pins the per-segment principle on
// the composed chase: the gate is shown one sidecar per segment, alias
// first — a whole-chain verdict on the alias entry alone would go stale
// when the target refreshed under it.
func TestChaseGateSeesEverySegmentInOrder(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()
	p := &recordingPolicy{allow: true}
	c.SetSidecarPolicy(p)

	alias := seamResponse("alias.seam.test.", &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.seam.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.seam.test.",
	})
	c.store.SetFromResponseWithCut(alias, false, time.Time{}, 0)
	target := seamResponse("target.seam.test.", seamA("target.seam.test."))
	c.store.SetFromResponseWithCut(target, false, time.Time{}, 0)

	req, _ := wireTestRequest(t, "alias.seam.test.", dns.TypeA, false)
	w := mock.NewWriter("udp", "192.0.2.9:53000")
	ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		ch.Cancel()
	})})
	ch.ResetWire(w, req)
	ch.AllowDirectPack()
	ch.Next(context.Background())

	if len(p.chases) == 0 {
		t.Fatal("the chase gate was never consulted")
	}
	seen := p.chases[len(p.chases)-1]
	if len(seen) != 2 || seen[0] == nil || seen[1] == nil ||
		seen[0].Value != "alias.seam.test." || seen[1].Value != "target.seam.test." {
		t.Fatalf("chase gate did not see every segment in order: %v", seen)
	}
}

// TestCompareAndStampSidecar pins the restamp primitive: a stale pointer
// loses to a concurrent stamp instead of overwriting it.
func TestCompareAndStampSidecar(t *testing.T) {
	e := &CacheEntry{}
	first := &middleware.Sidecar{Value: 1}
	if !e.CompareAndStampSidecar(nil, first) {
		t.Fatal("first stamp refused")
	}
	stale := &middleware.Sidecar{Value: 2}
	if e.CompareAndStampSidecar(nil, stale) {
		t.Fatal("a stale claim overwrote a live stamp")
	}
	if e.Sidecar() != first {
		t.Fatal("stamp lost")
	}
	next := &middleware.Sidecar{Value: 3}
	if !e.CompareAndStampSidecar(first, next) || e.Sidecar() != next {
		t.Fatal("restamp from the live value refused")
	}
}

// TestRawPathGateKeepsADeclinedHitOffBytes pins the wire-born exact-hit
// gate specifically: with the gate declining, the byte fast path must not
// serve — the Msg body answers instead — and the fast-served counter
// proves which one did.
func TestRawPathGateKeepsADeclinedHitOffBytes(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()
	p := &recordingPolicy{allow: false}
	c.SetSidecarPolicy(p)

	resp := seamResponse("raw.seam.test.", seamA("raw.seam.test."))
	c.store.SetFromResponseWithCut(resp, false, time.Time{}, 0)

	served := wireFastServed.Value()
	req, _ := wireTestRequest(t, "raw.seam.test.", dns.TypeA, false)
	w := mock.NewWriter("udp", "192.0.2.9:53000")
	ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		ch.Cancel()
	})})
	ch.ResetWire(w, req)
	ch.AllowDirectPack()
	ch.Next(context.Background())

	if !w.Written() || len(w.Msg().Answer) != 1 {
		t.Fatal("declined hit did not answer from the decoded path")
	}
	if wireFastServed.Value() != served {
		t.Fatal("a declining gate let the raw byte path serve")
	}
	if len(p.hits) == 0 {
		t.Fatal("the gate was never consulted")
	}
}
