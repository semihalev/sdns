package localroot

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
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
		return root.rrs, nil
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

	// Past the SOA expire horizon the copy is withdrawn, not served stale.
	now = now.Add(time.Duration(root.rrs[0].(*dns.SOA).Expire)*time.Second + time.Second)
	if m.Active() != nil {
		t.Fatal("a copy served past its SOA expire")
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

	expire := time.Duration(root.rrs[0].(*dns.SOA).Expire) * time.Second
	now = now.Add(expire/2 + time.Second)
	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("half-expire refresh: %v", err)
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
