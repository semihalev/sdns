package rpz

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	rpzengine "github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/middleware"
)

// The coverage-gap round: paths the arc's tests drove only indirectly
// or not at all — the feed's real lifecycle loop, the neutral global
// gate's exempt-query contract, the response wrap's remaining actions,
// and the decoded request path.

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

// TestAXFRFeedRunLoopLifecycle runs the feed's real schedule loop: the
// first transfer lands without being hand-driven, and cancelling the
// context ends the loop.
func TestAXFRFeedRunLoopLifecycle(t *testing.T) {
	srv := startFeedServer(t, "", "")
	r, feed := feedUnderTest(t, srv, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); feed.run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !passed {
			break // the first transfer landed and the rule enforces
		}
		if time.Now().After(deadline) {
			t.Fatal("the run loop never completed its first transfer")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the context did not end the run loop")
	}
}
