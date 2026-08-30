package rpz

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	dto "github.com/prometheus/client_model/go"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	rpzengine "github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/middleware"
)

const testZone = `
rpz.test.	3600	IN	SOA	ns.rpz.test. admin.rpz.test. 2026083001 3600 900 604800 300
rpz.test.	3600	IN	NS	ns.rpz.test.
nx.example.com.rpz.test.       300 IN CNAME .
nodata.example.com.rpz.test.   300 IN CNAME *.
pass.example.com.rpz.test.     300 IN CNAME rpz-passthru.
drop.example.com.rpz.test.     300 IN CNAME rpz-drop.
tcp.example.com.rpz.test.      300 IN CNAME rpz-tcp-only.
walled.example.com.rpz.test.   300 IN A 192.0.2.1
walled.example.com.rpz.test.   300 IN TXT "garden"
alias.example.com.rpz.test.    300 IN CNAME garden.example.net.
wildtarget.example.com.rpz.test. 300 IN CNAME *.garden.example.net.
*.wild.example.com.rpz.test.   300 IN A 192.0.2.7
`

func writeZone(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.zone")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newRPZ(t *testing.T, mode string, zones ...config.RPZZone) *RPZ {
	t.Helper()
	cfg := new(config.Config)
	cfg.RPZ = config.RPZ{Enabled: true, Mode: mode, Zones: zones}
	return New(cfg)
}

func testRPZ(t *testing.T, mode string) *RPZ {
	t.Helper()
	return newRPZ(t, mode, config.RPZZone{Name: "test", File: writeZone(t, testZone)})
}

// serve drives one query through rpz with a recording terminal behind it.
func serve(t *testing.T, r *RPZ, qname string, qtype uint16, proto string, rd bool) (*mock.Writer, bool) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.RecursionDesired = rd
	q.SetEdns0(1232, false)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("ParseWire refused an eligible query")
	}

	passed := false
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		ch.Cancel()
	})
	w := mock.NewWriter(proto, "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	return w, passed
}

func TestEnforceActions(t *testing.T) {
	r := testRPZ(t, "enforce")

	t.Run("nxdomain", func(t *testing.T) {
		w, passed := serve(t, r, "nx.example.com.", dns.TypeA, "udp", true)
		if passed || !w.Written() || w.Rcode() != dns.RcodeNameError {
			t.Fatalf("passed=%v written=%v rcode=%d", passed, w.Written(), w.Rcode())
		}
		m := w.Msg()
		if m.AuthenticatedData {
			t.Fatal("a rewrite may never carry AD")
		}
		// The policy zone's SOA names the source in the additional section.
		var soa *dns.SOA
		for _, rr := range m.Extra {
			if s, ok := rr.(*dns.SOA); ok {
				soa = s
			}
		}
		if soa == nil || soa.Hdr.Name != "rpz.test." || soa.Serial != 2026083001 {
			t.Fatalf("policy SOA missing or wrong: %+v", soa)
		}
		if ede := dnsutil.GetEDE(m); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeFiltered {
			t.Fatalf("EDE = %+v, want Filtered", ede)
		}
	})

	t.Run("nodata", func(t *testing.T) {
		w, passed := serve(t, r, "nodata.example.com.", dns.TypeA, "udp", true)
		if passed || w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 0 {
			t.Fatalf("passed=%v rcode=%d answers=%d", passed, w.Rcode(), len(w.Msg().Answer))
		}
	})

	t.Run("passthru", func(t *testing.T) {
		w, passed := serve(t, r, "pass.example.com.", dns.TypeA, "udp", true)
		if !passed || w.Written() {
			t.Fatalf("passthru must continue the chain: passed=%v written=%v", passed, w.Written())
		}
	})

	t.Run("drop", func(t *testing.T) {
		w, passed := serve(t, r, "drop.example.com.", dns.TypeA, "udp", true)
		if passed || w.Written() {
			t.Fatalf("drop must answer nothing: passed=%v written=%v", passed, w.Written())
		}
	})

	t.Run("tcp-only on udp truncates", func(t *testing.T) {
		w, passed := serve(t, r, "tcp.example.com.", dns.TypeA, "udp", true)
		if passed || !w.Written() || !w.Msg().Truncated {
			t.Fatalf("passed=%v written=%v tc=%v", passed, w.Written(), w.Written() && w.Msg().Truncated)
		}
	})

	t.Run("tcp-only elsewhere passes", func(t *testing.T) {
		for _, proto := range []string{"tcp", "tls", "doh", "doh3", "doq"} {
			if _, passed := serve(t, r, "tcp.example.com.", dns.TypeA, proto, true); !passed {
				t.Fatalf("%s: tcp-only must pass through on a non-UDP transport", proto)
			}
		}
	})

	t.Run("local data", func(t *testing.T) {
		w, passed := serve(t, r, "walled.example.com.", dns.TypeA, "udp", true)
		if passed || len(w.Msg().Answer) != 1 {
			t.Fatalf("passed=%v answers=%v", passed, w.Msg().Answer)
		}
		a, ok := w.Msg().Answer[0].(*dns.A)
		if !ok || a.A.String() != "192.0.2.1" || a.Hdr.Name != "walled.example.com." {
			t.Fatalf("answer = %v", w.Msg().Answer[0])
		}
	})

	t.Run("local data ANY serves every rrset", func(t *testing.T) {
		w, _ := serve(t, r, "walled.example.com.", dns.TypeANY, "udp", true)
		if len(w.Msg().Answer) != 2 {
			t.Fatalf("ANY answers = %v", w.Msg().Answer)
		}
	})

	t.Run("local data absent type with CNAME serves the CNAME", func(t *testing.T) {
		w, _ := serve(t, r, "alias.example.com.", dns.TypeA, "udp", true)
		answers := w.Msg().Answer
		if len(answers) != 1 {
			t.Fatalf("answers = %v", answers)
		}
		c, ok := answers[0].(*dns.CNAME)
		if !ok || c.Target != "garden.example.net." || c.Hdr.Name != "alias.example.com." {
			t.Fatalf("cname = %v", answers[0])
		}
	})

	// The wildcard rule's answer carries the client's qname as owner,
	// never the wildcard — the §5.2 owner rule, pinned.
	t.Run("wildcard local data owner is the qname", func(t *testing.T) {
		w, _ := serve(t, r, "deep.wild.example.com.", dns.TypeA, "udp", true)
		answers := w.Msg().Answer
		if len(answers) != 1 || answers[0].Header().Name != "deep.wild.example.com." {
			t.Fatalf("answers = %v", answers)
		}
	})
}

func TestShadowObservesWithoutRewriting(t *testing.T) {
	r := testRPZ(t, "shadow")
	for _, qname := range []string{"nx.example.com.", "drop.example.com.", "walled.example.com."} {
		w, passed := serve(t, r, qname, dns.TypeA, "udp", true)
		if !passed || w.Written() {
			t.Fatalf("%s: shadow must never rewrite: passed=%v written=%v", qname, passed, w.Written())
		}
	}
}

func TestGatesPassUnpoliciedQueries(t *testing.T) {
	r := testRPZ(t, "enforce")

	// RD=0: recursive-service policy does not apply.
	if _, passed := serve(t, r, "nx.example.com.", dns.TypeA, "udp", false); !passed {
		t.Fatal("an RD=0 query must not be policy-checked")
	}
	// A name no rule covers.
	if _, passed := serve(t, r, "innocent.example.org.", dns.TypeA, "udp", true); !passed {
		t.Fatal("a non-matching query must pass")
	}
}

func TestCNAMEOverrideRewritesWholeZone(t *testing.T) {
	r := newRPZ(t, "enforce", config.RPZZone{
		Name: "garden", File: writeZone(t, testZone),
		Policy: "cname", Cname: "landing.garden.example.",
	})
	// Even an NXDOMAIN rule serves the walled-garden CNAME under the
	// override.
	w, passed := serve(t, r, "nx.example.com.", dns.TypeA, "udp", true)
	if passed || len(w.Msg().Answer) != 1 {
		t.Fatalf("passed=%v answers=%v", passed, w.Msg().Answer)
	}
	c, ok := w.Msg().Answer[0].(*dns.CNAME)
	if !ok || c.Target != "landing.garden.example." || c.Hdr.Name != "nx.example.com." {
		t.Fatalf("cname = %v", w.Msg().Answer[0])
	}
}

func TestDisabledZoneLetsALaterZoneAct(t *testing.T) {
	watching := config.RPZZone{Name: "watching", File: writeZone(t, testZone), Policy: "disabled"}
	acting := config.RPZZone{Name: "acting", File: writeZone(t, `
z2.test. IN SOA ns. admin. 7 3600 900 604800 300
nx.example.com.z2.test. IN CNAME rpz-drop.
`)}
	r := newRPZ(t, "enforce", watching, acting)

	w, passed := serve(t, r, "nx.example.com.", dns.TypeA, "udp", true)
	if passed || w.Written() {
		t.Fatalf("the later zone's drop must act: passed=%v written=%v", passed, w.Written())
	}
}

func TestReloadSwapsTheZone(t *testing.T) {
	path := writeZone(t, testZone)
	r := newRPZ(t, "enforce", config.RPZZone{Name: "test", File: path})

	if w, _ := serve(t, r, "fresh.example.com.", dns.TypeA, "udp", true); w.Written() {
		t.Fatal("fresh name matched before the reload")
	}

	// The push replaces the file; reload is driven directly — the watcher
	// wiring is exercised, but waiting on fsnotify timing is a flake, not
	// a test.
	if err := os.WriteFile(path, []byte(`
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 2026083002 3600 900 604800 300
fresh.example.com.rpz.test. IN CNAME .
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(0)

	if w, _ := serve(t, r, "fresh.example.com.", dns.TypeA, "udp", true); !w.Written() || w.Rcode() != dns.RcodeNameError {
		t.Fatal("reloaded rule did not take effect")
	}
	// And the old rule is gone with the old generation.
	if _, passed := serve(t, r, "nx.example.com.", dns.TypeA, "udp", true); !passed {
		t.Fatal("a rule removed by the reload kept acting")
	}
}

func TestReloadFailureKeepsServing(t *testing.T) {
	path := writeZone(t, testZone)
	r := newRPZ(t, "enforce", config.RPZZone{Name: "test", File: path})

	if err := os.WriteFile(path, []byte("this is not a zone file {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(0)

	// The bad push must not have taken the rules away.
	if w, _ := serve(t, r, "nx.example.com.", dns.TypeA, "udp", true); !w.Written() || w.Rcode() != dns.RcodeNameError {
		t.Fatal("a failed reload dropped the previous rules")
	}
}

// TestNonMatchingQueryAllocatesNothing is §5.11's headline commitment at
// the middleware level: the steady state — a query no rule names — pays
// the stack key build and the map probes, and allocates nothing.
//
// The pin is measured against the harness itself: the same wire query
// through the same chain shape without rpz costs one allocation of test
// scaffolding, and rpz must add exactly zero on top. An absolute zero
// would pin the harness, not the middleware.
func TestNonMatchingQueryAllocatesNothing(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("innocent.example.org.", dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { ch.Cancel() })
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ctx := context.Background()
	req := new(middleware.Request)

	measure := func(handlers []middleware.Handler) float64 {
		ch := middleware.NewChain(handlers)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("refused")
		}
		ch.ResetWire(w, req)
		ch.Next(ctx) // warm the shells
		return testing.AllocsPerRun(200, func() {
			if !req.ParseWire(raw, time.Now(), nil) {
				t.Fatal("refused")
			}
			ch.ResetWire(w, req)
			ch.Next(ctx)
		})
	}

	baseline := measure([]middleware.Handler{next})
	withRPZ := measure([]middleware.Handler{testRPZ(t, "enforce"), next})

	if withRPZ != baseline {
		t.Fatalf("a non-matching query cost %.0f allocations against a %.0f baseline; rpz must add zero",
			withRPZ, baseline)
	}
}

// chaseQueryer answers every sub-query with one A record plus an RRSIG,
// so the test can pin both halves of the chase contract: the target's
// real answer is appended, and DNSSEC records are stripped on the way.
type chaseQueryer struct{ asked *dns.Msg }

func (c *chaseQueryer) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	c.asked = req
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 55}},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeA, Algorithm: dns.RSASHA256, SignerName: ".", Signature: "AA=="},
	}
	return resp, nil
}

func TestLocalDataCNAMEChasesThroughTheQueryer(t *testing.T) {
	r := testRPZ(t, "enforce")
	q := &chaseQueryer{}
	r.SetQueryer(q)

	w, _ := serve(t, r, "alias.example.com.", dns.TypeA, "udp", true)
	answers := w.Msg().Answer
	if len(answers) != 2 {
		t.Fatalf("answers = %v, want CNAME + chased A", answers)
	}
	if c, ok := answers[0].(*dns.CNAME); !ok || c.Target != "garden.example.net." {
		t.Fatalf("first answer = %v", answers[0])
	}
	if a, ok := answers[1].(*dns.A); !ok || a.Hdr.Name != "garden.example.net." {
		t.Fatalf("second answer = %v", answers[1])
	}
	if q.asked == nil || q.asked.Question[0].Name != "garden.example.net." || q.asked.Question[0].Qtype != dns.TypeA {
		t.Fatalf("chase asked %v", q.asked)
	}
	// The RRSIG the sub-pipeline returned must not survive into the
	// assembled policy answer (design C2), and AD stays clear.
	for _, rr := range w.Msg().Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			t.Fatal("a chased RRSIG leaked into the rewrite")
		}
	}
	if w.Msg().AuthenticatedData {
		t.Fatal("a rewrite may never carry AD")
	}
}

// counterValue reads one rpz_action_total series without pulling in an
// assertion or test-util dependency: client_model is already a direct
// dependency, and a counter writes itself into its dto.
func counterValue(t *testing.T, zone, action, outcome string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := actionTotal.WithLabelValues(zone, "qname", action, outcome).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// TestReplayDoesNotDoubleCount pins the counting rule for the inline
// handoff dance: a pass-through match counted on the first pass must not
// count again when the worker replays the whole chain after a cache
// handoff — otherwise the same query counts once or twice depending on
// the cache's mood.
func TestReplayDoesNotDoubleCount(t *testing.T) {
	r := testRPZ(t, "shadow")
	q := new(dns.Msg)
	q.SetQuestion("nx.example.com.", dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { ch.Cancel() })

	pass := func(replay bool) {
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("refused")
		}
		ch := middleware.NewChain([]middleware.Handler{r, next})
		ch.ResetWire(mock.NewWriter("udp", "192.0.2.1:40000"), req)
		if replay {
			ch.SetReplay()
		}
		ch.Next(context.Background())
	}

	before := counterValue(t, "test", "nxdomain", outcomeObserved)
	pass(false) // the inline/worker first pass counts
	pass(true)  // the replay of that same query must not
	if got := counterValue(t, "test", "nxdomain", outcomeObserved) - before; got != 1 {
		t.Fatalf("one query counted %.0f times across first pass + replay, want 1", got)
	}
}

// TestChaseHandsOffTheInlinePass pins the reader-safety rule: a Local
// Data match whose CNAME needs the sub-pipeline must decline an
// inline-only pass unwritten (the cache's own discipline), act on the
// worker replay instead, and count exactly once — on the pass that acted.
func TestChaseHandsOffTheInlinePass(t *testing.T) {
	r := testRPZ(t, "enforce")
	r.SetQueryer(&chaseQueryer{})

	q := new(dns.Msg)
	q.SetQuestion("alias.example.com.", dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { ch.Cancel() })

	before := counterValue(t, "test", "local-data", outcomeEnforced)

	// Inline pass: no write, no count, handoff marked.
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("refused")
	}
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.SetInlineOnly()
	ch.Next(context.Background())
	if w.Written() {
		t.Fatal("a chase ran on the inline pass — that blocks the transport reader")
	}
	if !ch.Handoff() {
		t.Fatal("the inline pass must mark a handoff for the worker replay")
	}
	if got := counterValue(t, "test", "local-data", outcomeEnforced) - before; got != 0 {
		t.Fatalf("the declined inline pass counted %.0f times, want 0", got)
	}

	// Worker replay: the chase completes, and the count lands here, once.
	req2 := new(middleware.Request)
	if !req2.ParseWire(raw, time.Now(), nil) {
		t.Fatal("refused")
	}
	w2 := mock.NewWriter("udp", "192.0.2.1:40000")
	ch2 := middleware.NewChain([]middleware.Handler{r, next})
	ch2.ResetWire(w2, req2)
	ch2.SetReplay()
	ch2.Next(context.Background())
	if !w2.Written() || len(w2.Msg().Answer) != 2 {
		t.Fatalf("replay did not complete the chase: written=%v answers=%v", w2.Written(), w2.Msg().Answer)
	}
	if got := counterValue(t, "test", "local-data", outcomeEnforced) - before; got != 1 {
		t.Fatalf("chase counted %.0f times across handoff + replay, want 1", got)
	}

	// And a Local Data match that needs no chase stays inline: records of
	// the requested type are pure synthesis.
	w3, _ := serve(t, r, "walled.example.com.", dns.TypeA, "udp", true)
	if !w3.Written() {
		t.Fatal("chase-free local data must serve inline")
	}
}

func TestEmptyButValidReloadKeepsServing(t *testing.T) {
	path := writeZone(t, testZone)
	r := newRPZ(t, "enforce", config.RPZZone{Name: "test", File: path})

	// A push that parses but compiles nothing: SOA/NS only.
	if err := os.WriteFile(path, []byte(`
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 9 3600 900 604800 300
rpz.test. IN NS ns.rpz.test.
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(0)

	if w, _ := serve(t, r, "nx.example.com.", dns.TypeA, "udp", true); !w.Written() || w.Rcode() != dns.RcodeNameError {
		t.Fatal("an empty-but-valid push stripped the working policy")
	}
}

func TestWildcardCNAMETargetExpandsForEveryQtype(t *testing.T) {
	r := testRPZ(t, "enforce")
	// wildtarget's rule is `CNAME *.garden.example.net.`; asked for the
	// CNAME itself (the direct type-match branch), the wildcard must
	// still expand — a `*.` target may never reach a client.
	for _, qtype := range []uint16{dns.TypeCNAME, dns.TypeANY, dns.TypeA} {
		w, _ := serve(t, r, "wildtarget.example.com.", qtype, "udp", true)
		if len(w.Msg().Answer) == 0 {
			t.Fatalf("qtype %d: no answer", qtype)
		}
		c, ok := w.Msg().Answer[0].(*dns.CNAME)
		if !ok {
			t.Fatalf("qtype %d: answer = %v", qtype, w.Msg().Answer[0])
		}
		if c.Target != "wildtarget.example.com.garden.example.net." {
			t.Fatalf("qtype %d: target %q leaked unexpanded", qtype, c.Target)
		}
	}
}

// dnssecChaseQueryer answers with the whole DNSSEC family beside one real
// record, so the strip filter is judged against every type it must catch.
type dnssecChaseQueryer struct{}

func (dnssecChaseQueryer) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	name := req.Question[0].Name
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 60}
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.DNSKEY{Hdr: hdr(dns.TypeDNSKEY), Flags: 256, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "AwEAAa=="},
		&dns.DS{Hdr: hdr(dns.TypeDS), KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "ab"},
		&dns.NSEC{Hdr: hdr(dns.TypeNSEC), NextDomain: "z." + name, TypeBitMap: []uint16{dns.TypeA}},
		&dns.RRSIG{Hdr: hdr(dns.TypeRRSIG), TypeCovered: dns.TypeDNSKEY, Algorithm: 8, SignerName: ".", Signature: "AA=="},
		&dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{"clean"}},
	}
	return resp, nil
}

func TestChaseStripsTheWholeDNSSECFamily(t *testing.T) {
	r := testRPZ(t, "enforce")
	r.SetQueryer(dnssecChaseQueryer{})

	// alias has only a CNAME; a DNSKEY question takes the chase path.
	w, _ := serve(t, r, "alias.example.com.", dns.TypeDNSKEY, "udp", true)
	for _, rr := range w.Msg().Answer {
		if rpzengine.IsDNSSECType(rr.Header().Rrtype) {
			t.Fatalf("chased %v leaked into the rewrite", dns.TypeToString[rr.Header().Rrtype])
		}
	}
	// The non-DNSSEC record survived the filter.
	found := false
	for _, rr := range w.Msg().Answer {
		if rr.Header().Rrtype == dns.TypeTXT {
			found = true
		}
	}
	if !found {
		t.Fatal("the filter stripped more than the DNSSEC family")
	}
}

func TestReloadZeroesDroppedSkipReasons(t *testing.T) {
	// First load carries an unknown-action skip...
	path := writeZone(t, `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
keep.example.com.rpz.test. IN CNAME .
odd.example.com.rpz.test. IN CNAME rpz-mystery-action.
`)
	r := newRPZ(t, "enforce", config.RPZZone{Name: "gauges", File: path})

	read := func() float64 {
		m := &dto.Metric{}
		if err := zoneRulesSkipped.WithLabelValues("gauges", rpzengine.SkipUnknownAction).Write(m); err != nil {
			t.Fatal(err)
		}
		return m.GetGauge().GetValue()
	}
	if read() != 1 {
		t.Fatalf("skip gauge = %v after first load, want 1", read())
	}

	// ...and the cleaned-up push must read as zero, not linger.
	if err := os.WriteFile(path, []byte(`
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 2 3600 900 604800 300
keep.example.com.rpz.test. IN CNAME .
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(0)
	if read() != 0 {
		t.Fatalf("skip gauge = %v after a clean reload, want 0", read())
	}
}

const clientIPTestZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 5 3600 900 604800 300
24.0.2.0.192.rpz-client-ip.rpz.test.  IN CNAME rpz-drop.
32.9.2.0.192.rpz-client-ip.rpz.test.  IN CNAME rpz-passthru.
16.0.0.0.10.rpz-client-ip.rpz.test.   IN A 192.0.2.99
victim.example.com.rpz.test.          IN CNAME *.
`

// serveFrom is serve with the client address under test.
func serveFrom(t *testing.T, r *RPZ, addr, qname string, qtype uint16) (*mock.Writer, bool) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("refused")
	}
	passed := false
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		ch.Cancel()
	})
	w := mock.NewWriter("udp", addr)
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	return w, passed
}

func TestClientIPEndToEnd(t *testing.T) {
	r := newRPZ(t, "enforce", config.RPZZone{Name: "cip", File: writeZone(t, clientIPTestZone)})

	// A client in the dropped /24 gets nothing, whatever it asks.
	if w, passed := serveFrom(t, r, "192.0.2.55:40000", "totally.unrelated.example.", dns.TypeA); passed || w.Written() {
		t.Fatalf("dropped client answered: passed=%v written=%v", passed, w.Written())
	}
	// The /32 passthru inside it is exempt (longest prefix wins).
	if _, passed := serveFrom(t, r, "192.0.2.9:40000", "victim.example.com.", dns.TypeA); !passed {
		t.Fatal("the /32 passthru client was not exempted")
	}
	// A client outside every prefix falls to the QNAME rule.
	if w, passed := serveFrom(t, r, "198.51.100.1:40000", "victim.example.com.", dns.TypeA); passed || w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 0 {
		t.Fatalf("outside client: passed=%v rcode=%v", passed, w.Rcode())
	}
	// And an unpolicied client + unpolicied name passes untouched.
	if _, passed := serveFrom(t, r, "198.51.100.1:40000", "innocent.example.org.", dns.TypeA); !passed {
		t.Fatal("clean query blocked")
	}
}

// TestClientIPLocalDataOwnerIsTheQName is the phase 2 exit criterion from
// the design, verbatim: an address-encoded trigger owner must never
// appear in a response.
func TestClientIPLocalDataOwnerIsTheQName(t *testing.T) {
	r := newRPZ(t, "enforce", config.RPZZone{Name: "cip", File: writeZone(t, clientIPTestZone)})

	w, _ := serveFrom(t, r, "10.0.12.13:40000", "some.name.example.", dns.TypeA)
	answers := w.Msg().Answer
	if len(answers) != 1 {
		t.Fatalf("answers = %v", answers)
	}
	a, ok := answers[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.99" {
		t.Fatalf("answer = %v", answers[0])
	}
	if a.Hdr.Name != "some.name.example." {
		t.Fatalf("owner %q leaked from the trigger encoding", a.Hdr.Name)
	}
}

func TestClientIPCountsUnderItsOwnTriggerLabel(t *testing.T) {
	r := newRPZ(t, "shadow", config.RPZZone{Name: "ciplabel", File: writeZone(t, clientIPTestZone)})

	before := func(trigger string) float64 {
		m := &dto.Metric{}
		if err := actionTotal.WithLabelValues("ciplabel", trigger, "drop", outcomeObserved).Write(m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}
	b := before("client-ip")
	serveFrom(t, r, "192.0.2.55:40000", "x.example.", dns.TypeA)
	if got := before("client-ip") - b; got != 1 {
		t.Fatalf("client-ip trigger counted %.0f, want 1", got)
	}
}
