package rpz

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
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
