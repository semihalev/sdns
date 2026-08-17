package cache

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// witnessTestProof admits one validated NSEC proof for zone, giving the
// denial index the warm shape production always has.
func witnessTestProof(t *testing.T, s *Store, zone, owner, next string) {
	t.Helper()
	fixture := newDenialProofNSECFixture(
		t,
		time.Now().UTC(),
		"q."+zone,
		dns.TypeA,
		dns.RcodeNameError,
		zone,
		[2]string{owner, next},
	)
	aggressiveNegativeMakeSignaturesPackable(fixture.msg)
	if !s.RecordDenialProof(fixture.msg, zone, middleware.ValidatedNegativeProofNSEC, time.Time{}) {
		t.Fatalf("NSEC proof for %s refused", zone)
	}
}

// TestFailureMissWitnessLifecycle pins the witness contract at the store:
// captured at record, held while the on-path denial snapshots are
// pointer-identical, broken by any admission on the path, moot off-path.
func TestFailureMissWitnessLifecycle(t *testing.T) {
	c := New(makeTestConfig())
	defer c.Stop()
	s := c.store

	witnessTestProof(t, s, "sig.test.", "glib.sig.test.", "help.sig.test.")

	witness := s.failureMissWitness("down.sig.test.", dns.ClassINET)
	if len(witness) != 1 {
		t.Fatalf("witness pairs = %d, want 1 (the sig.test. zone)", len(witness))
	}

	onPath, _ := wireTestRequest(t, "down.sig.test.", dns.TypeA, false)
	offPath, _ := wireTestRequest(t, "down.unrelated.example.", dns.TypeA, false)

	if !s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, witness) {
		t.Fatal("fresh witness did not hold for its own name")
	}
	if s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, nil) {
		t.Fatal("nil witness held with a denial zone on the path")
	}
	if !s.denialProofs.missWitnessHoldsWire(offPath.WireName(), dns.ClassINET, nil) {
		t.Fatal("nil witness did not hold off-path — no zone could deny this name")
	}

	// Any admission to an on-path zone replaces its snapshot: the old
	// witness must stop holding, a fresh one must hold again.
	witnessTestProof(t, s, "sig.test.", "mo.sig.test.", "mu.sig.test.")
	if s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, witness) {
		t.Fatal("witness held across a snapshot replacement")
	}
	fresh := s.failureMissWitness("down.sig.test.", dns.ClassINET)
	if !s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, fresh) {
		t.Fatal("fresh witness did not hold after re-capture")
	}

	// The witnessed hold is on the serving path: it must cost nothing.
	if allocs := testing.AllocsPerRun(200, func() {
		if !s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, fresh) {
			t.Fatal("hold broke during the allocation pin")
		}
	}); allocs != 0 {
		t.Fatalf("witness hold allocated %.2f objects per check", allocs)
	}

	c.Stop()
	if s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, fresh) {
		t.Fatal("witness held on a stopped cache")
	}
}

// serveFailureThrough runs one query through edns→cache exactly as the
// live chain wires them, asserts the client sees SERVFAIL, and reports
// whether the byte path composed it. With direct-pack declared, even a
// Msg-path answer leaves the transport as bytes, so the discriminator is
// the wire counter, not the write method.
func serveFailureThrough(t *testing.T, c *Cache, e *edns.EDNS, name string) (byWire bool) {
	t.Helper()
	// Wire-born, as production sends it: the wire dispatch runs only for
	// undecoded requests.
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack %s: %v", name, err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatalf("eligible query %s refused", name)
	}

	before := wireFailureServed.Value()
	writer := mock.NewWriter("udp", "198.51.100.9:40000")
	terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		t.Fatalf("query %s missed the failure cache and reached the terminal handler", name)
	})
	ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
	ch.ResetWire(writer, req)
	ch.AllowDirectPack()
	ch.Next(context.Background())
	if !writer.Written() {
		t.Fatalf("no response written for %s", name)
	}
	if writer.Rcode() != dns.RcodeServerFailure {
		t.Fatalf("cached failure for %s answered rcode %d, want SERVFAIL", name, writer.Rcode())
	}
	return wireFailureServed.Value() > before
}

// TestWireFailureServeWitnessGate pins the gate end to end: a failure under
// a warm denial index serves from bytes exactly while its witness holds,
// falls back to the Msg path the moment denial state moves, and answers
// SERVFAIL identically on both paths.
func TestWireFailureServeWitnessGate(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 0
	c := New(cfg)
	defer c.Stop()
	e := edns.New(cfg)

	// The production shape that kept this rung dormant: denial proofs
	// exist, just not for the failing name's path.
	witnessTestProof(t, c.store, "sig.test.", "glib.sig.test.", "help.sig.test.")

	// Tier 1: no denial zone on the failing name's path — no witness
	// needed, the byte path serves outright.
	offReq := new(dns.Msg)
	offReq.SetQuestion("down.other.example.", dns.TypeA)
	c.store.RecordFailure(offReq, netip.Prefix{}, FailureProvenance("test"))
	if !serveFailureThrough(t, c, e, "down.other.example.") {
		t.Fatal("off-path failure materialized despite no denial zone on its path")
	}

	// Tier 2: a denial zone on the path — the record-time witness lets
	// the byte path serve.
	onReq := new(dns.Msg)
	onReq.SetQuestion("down.sig.test.", dns.TypeA)
	c.store.RecordFailure(onReq, netip.Prefix{}, FailureProvenance("test"))
	if !serveFailureThrough(t, c, e, "down.sig.test.") {
		t.Fatal("witnessed failure materialized")
	}

	// Denial state moves: the witness breaks, and the same query must
	// fall to the Msg path — same SERVFAIL, different composer.
	witnessTestProof(t, c.store, "sig.test.", "mo.sig.test.", "mu.sig.test.")
	if serveFailureThrough(t, c, e, "down.sig.test.") {
		t.Fatal("stale-witness failure served from bytes; the Msg ladder owns this decision now")
	}
}
