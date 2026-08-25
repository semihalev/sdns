package localroot

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// TestManagerLifecycle drives refreshOnce through the states the RFC 8806
// schedule produces: first load, an unchanged serial (no transfer), a serial
// bump (transfer + swap), a failing source (previous copy stays), and the
// SOA expire horizon (Active withdraws the copy).
func TestManagerLifecycle(t *testing.T) {
	root := buildTestRoot(t)
	now := time.Now()

	transfers := 0
	serial := root.serial
	failing := false
	// The source serves the zone it advertises: probe and transfer move
	// together, as a healthy source's do.
	served := map[uint32][]dns.RR{root.serial: root.rrs}
	serve := func(s uint32) []dns.RR {
		t.Helper()
		if rrs, ok := served[s]; ok {
			return rrs
		}
		z, err := roottest.BuildZoneWithKey(
			ComputeDigest, roottest.DefaultLines(s), s, root.key, root.priv,
		)
		if err != nil {
			t.Fatalf("zone %d: %v", s, err)
		}
		served[s] = z.RRs
		return z.RRs
	}

	m := New(nil, func() []dns.RR { return root.anchors })
	m.now = func() time.Time { return now }
	m.probeFn = func(context.Context, string, time.Duration) (uint32, error) {
		if failing {
			return 0, errors.New("probe down")
		}
		return serial, nil
	}
	m.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) {
		if failing {
			return nil, errors.New("transfer down")
		}
		transfers++
		return serve(serial), nil
	}

	if m.Active() != nil {
		t.Fatal("a copy active before any transfer")
	}

	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if m.Active() == nil || transfers != 1 {
		t.Fatalf("first load did not install a copy (transfers=%d)", transfers)
	}

	// Unchanged serial inside the re-transfer horizon: probe only.
	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("steady refresh: %v", err)
	}
	if transfers != 1 {
		t.Fatalf("an unchanged serial transferred anyway (transfers=%d)", transfers)
	}

	// A serial bump transfers and swaps.
	serial++
	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("bumped refresh: %v", err)
	}
	if transfers != 2 {
		t.Fatalf("a bumped serial did not transfer (transfers=%d)", transfers)
	}

	// Every source failing keeps the previous copy serving.
	failing = true
	if err := m.refreshOnce(context.Background()); err == nil {
		t.Fatal("refresh reported success with every source down")
	}
	if m.Active() == nil {
		t.Fatal("a failed refresh withdrew a live copy")
	}

	// Past the horizon (here the signature window, the nearer bound) the
	// copy is withdrawn, not served stale.
	now = now.Add(2 * time.Hour)
	if m.Active() != nil {
		t.Fatal("a copy served past its horizon")
	}
}

// TestManagerReanchorsExpireHorizon pins the half-expire rule: a source
// whose serial never changes must still hand over a fresh transfer before
// the copy's expire horizon threatens, because the horizon anchors at the
// transfer, not at the probe.
func TestManagerReanchorsExpireHorizon(t *testing.T) {
	root := buildTestRoot(t)
	now := time.Now()

	transfers := 0
	m := New(nil, func() []dns.RR { return root.anchors })
	m.now = func() time.Time { return now }
	m.probeFn = func(context.Context, string, time.Duration) (uint32, error) {
		return root.serial, nil
	}
	m.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) {
		transfers++
		return root.rrs, nil
	}

	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("first load: %v", err)
	}

	// The horizon here is the one-hour signature window; half of it spent
	// must trigger a fresh transfer even with the serial unchanged.
	now = now.Add(31 * time.Minute)
	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("half-horizon refresh: %v", err)
	}
	if transfers != 2 {
		t.Fatalf("the half-expire horizon did not re-anchor (transfers=%d)", transfers)
	}
	if s := m.Active(); s == nil || m.now().Sub(s.Loaded()) > time.Second {
		t.Fatal("the re-anchored copy does not carry the fresh horizon")
	}
}

// TestManagerRefusesUnverifiedSwap pins the gate: a source serving a zone
// that does not verify must not displace the live copy.
func TestManagerRefusesUnverifiedSwap(t *testing.T) {
	root := buildTestRoot(t)
	tampered := append([]dns.RR(nil), root.rrs...)
	for i, rr := range tampered {
		if a, ok := rr.(*dns.A); ok {
			evil := dns.Copy(a).(*dns.A)
			evil.A[3]++
			tampered[i] = evil
			break
		}
	}

	now := time.Now()
	serve := root.rrs
	serial := root.serial

	m := New(nil, func() []dns.RR { return root.anchors })
	m.now = func() time.Time { return now }
	m.probeFn = func(context.Context, string, time.Duration) (uint32, error) { return serial, nil }
	m.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) { return serve, nil }

	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("first load: %v", err)
	}
	good := m.Active()

	serve = tampered
	serial++
	if err := m.refreshOnce(context.Background()); err == nil {
		t.Fatal("a tampered transfer reported success")
	}
	if m.Active() != good {
		t.Fatal("a tampered transfer displaced the verified copy")
	}
}

// TestRunDefersTheFirstTransfer pins that the copy yields to the resolver's
// cold start. Pulling the zone the instant the process comes up shares the
// link with the priming query, the trust-anchor refresh and the first
// client queries — measurably slowing them on a modest connection, which is
// the opposite of what the copy is for. The delay is generous compared to
// the window this test watches, so a regression to an immediate transfer
// shows up immediately rather than as a timing flake.
func TestRunDefersTheFirstTransfer(t *testing.T) {
	root := buildTestRoot(t)

	var transfers atomic.Int32
	m := New(nil, func() []dns.RR { return root.anchors })
	m.probeFn = func(context.Context, string, time.Duration) (uint32, error) {
		return root.serial, nil
	}
	m.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) {
		transfers.Add(1)
		return root.rrs, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	time.Sleep(250 * time.Millisecond)
	if got := transfers.Load(); got != 0 {
		t.Fatalf("%d transfers within 250ms of start — the first one must wait out "+
			"the resolver's cold start (%v)", got, initialTransferDelay)
	}
	if m.Active() != nil {
		t.Fatal("a copy became active before any transfer")
	}
}

// TestRefreshWithoutAnchorsDoesNotTransfer pins the guard in front of the
// wire. Trust anchors can fail closed and stay empty, and nothing transferred
// in that state could ever verify — so pulling a few megabytes from every
// source on every retry interval, indefinitely, is waste aimed at root
// infrastructure.
func TestRefreshWithoutAnchorsDoesNotTransfer(t *testing.T) {
	var transfers, probes atomic.Int64

	m := New(nil, func() []dns.RR { return nil })
	m.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) {
		transfers.Add(1)
		return nil, errors.New("transfer must not be reached")
	}
	m.probeFn = func(context.Context, string, time.Duration) (uint32, error) {
		probes.Add(1)
		return 0, errors.New("probe must not be reached")
	}

	if err := m.refreshOnce(context.Background()); !errors.Is(err, errNoAnchors) {
		t.Fatalf("refreshOnce with no anchors = %v, want errNoAnchors", err)
	}
	if transfers.Load() != 0 || probes.Load() != 0 {
		t.Fatalf("an anchorless refresh still reached the network: %d transfers, %d probes",
			transfers.Load(), probes.Load())
	}
}

// TestNewDropsBlankSources pins that a blank configured source cannot leave
// the manager with one unusable address and the feature silently off.
func TestNewDropsBlankSources(t *testing.T) {
	anchors := func() []dns.RR { return nil }

	for name, sources := range map[string][]string{
		"a single empty entry": {""},
		"only whitespace":      {"   ", "\t"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := New(sources, anchors).sources; len(got) != len(DefaultSources) {
				t.Fatalf("sources = %v, want the built-in set", got)
			}
		})
	}

	got := New([]string{"", "example.test:53", "  "}, anchors).sources
	if len(got) != 1 || got[0] != "example.test:53" {
		t.Fatalf("sources = %v, want only the usable entry", got)
	}
}

// TestObserveReportsSerialAndAge pins what the gauges say. A fleet watching
// only the copy's age cannot tell whether its nodes settled on the same zone
// version, which is the question a rollout actually asks.
func TestObserveReportsSerialAndAge(t *testing.T) {
	root := buildTestRoot(t)
	now := time.Now()

	m := New(nil, func() []dns.RR { return root.anchors })
	m.now = func() time.Time { return now }

	if age, serial := m.observe(); age != -1 || serial != -1 {
		t.Fatalf("with no copy: age=%v serial=%v, want -1/-1", age, serial)
	}

	if err := m.Load(root.rrs); err != nil {
		t.Fatalf("load: %v", err)
	}
	now = now.Add(90 * time.Second)
	age, serial := m.observe()
	if age != 90 {
		t.Fatalf("age = %v, want 90 seconds since the transfer", age)
	}
	if serial != float64(root.serial) {
		t.Fatalf("serial = %v, want the copy's %d", serial, root.serial)
	}

	// Past the horizon the copy is withdrawn, and the gauges must say so
	// rather than freezing on the last serial they saw.
	now = now.Add(24 * time.Hour)
	if age, serial := m.observe(); age != -1 || serial != -1 {
		t.Fatalf("past the horizon: age=%v serial=%v, want -1/-1", age, serial)
	}
}

// TestActiveFollowsTheTrustAnchors pins that a copy stops being served the
// moment the anchors that verified it stop being the resolver's. Expiry alone
// is not enough: an anchor set emptied fail-closed, or one whose keys were
// replaced, withdraws the basis on which every answer built from the copy
// claims AD=1 — and days of horizon could otherwise run on evidence that no
// longer exists.
func TestActiveFollowsTheTrustAnchors(t *testing.T) {
	root := buildTestRoot(t)
	other, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("second zone: %v", err)
	}
	now := time.Now()

	anchors := root.anchors
	m := New(nil, func() []dns.RR { return anchors })
	m.now = func() time.Time { return now }
	if err := m.Load(root.rrs); err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Active() == nil {
		t.Fatal("a freshly verified copy is not being served")
	}

	// The observation is cached for anchorRecheckInterval, so move past it
	// before each change — the staleness is deliberate and bounded.
	advance := func() { now = now.Add(2 * anchorRecheckInterval) }

	anchors = nil
	advance()
	if m.Active() != nil {
		t.Fatal("the copy is still served with no trust anchors at all")
	}

	// A different anchor set is not this copy's anchor set: the key that
	// signed what we hold is no longer one the resolver trusts.
	anchors = other.Anchors
	advance()
	if m.Active() != nil {
		t.Fatal("the copy is still served under a foreign anchor set")
	}

	// Restored anchors restore the copy — the snapshot never changed, only
	// the basis for trusting it did.
	anchors = root.anchors
	advance()
	if m.Active() == nil {
		t.Fatal("the copy was not restored when its own anchors came back")
	}
}

func TestAnchorFingerprintIsOrderIndependent(t *testing.T) {
	rrs := rrsFromText(t,
		". 172800 IN DS 111 13 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE58AB7A66C82AABE7A9E10F53",
		". 172800 IN DS 222 8 2 0000000000000000000000000000000000000000000000000000000000000000",
	)
	forward, ok := anchorFingerprint(rrs)
	if !ok {
		t.Fatal("a two-record anchor set is not usable")
	}
	reversed, ok := anchorFingerprint([]dns.RR{rrs[1], rrs[0]})
	if !ok {
		t.Fatal("the reversed set is not usable")
	}
	if forward != reversed {
		t.Fatal("the fingerprint depends on the order the anchors arrive in")
	}
	if _, ok := anchorFingerprint(nil); ok {
		t.Fatal("an empty anchor set reported itself usable")
	}
}
