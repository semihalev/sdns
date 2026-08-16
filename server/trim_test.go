package server

import (
	"testing"
	"time"
)

// The trim gate fires on a genuinely idle window, not on an instant. An
// instantaneous Quiesced() is regularly true between two queries of
// steady light traffic — sampling it three times proves nothing. The
// admission counters are a history: a window in which they did not move
// carried no traffic at all.
func TestTrimGateNeedsARealIdleWindow(t *testing.T) {
	start := time.Now()
	at := func(sample int) time.Time { return start.Add(time.Duration(sample) * trimSampleEvery) }

	t.Run("light steady traffic never trims", func(t *testing.T) {
		var g trimGate
		admitted := uint64(0)
		for sample := 0; sample < 40; sample++ {
			// Every sample lands between queries: quiescent at the
			// instant, but the counter has moved since last time.
			admitted += 3
			if g.observe(at(sample), true, admitted) {
				t.Fatalf("sample %d: trimmed under steady traffic; the gate "+
					"read an instant where it needed a history", sample)
			}
		}
	})

	t.Run("a real idle window trims once, then cools down", func(t *testing.T) {
		var g trimGate
		const admitted = 1000
		fired := 0
		firedAt := -1
		for sample := 0; sample < 10; sample++ {
			if g.observe(at(sample), true, admitted) {
				fired++
				firedAt = sample
			}
		}
		if fired != 1 {
			t.Fatalf("fired %d times over a long idle, want exactly once (cooldown)", fired)
		}
		if firedAt < trimAfterIdle-1 {
			t.Fatalf("fired at sample %d, before the idle window was proven", firedAt)
		}
	})

	t.Run("traffic resets the window", func(t *testing.T) {
		var g trimGate
		admitted := uint64(0)
		for sample := 0; sample < 20; sample++ {
			if sample%2 == 0 {
				admitted++ // a query every other sample
			}
			if g.observe(at(sample), true, admitted) {
				t.Fatalf("sample %d: trimmed while queries were still arriving", sample)
			}
		}
	})

	t.Run("in-flight work resets the window", func(t *testing.T) {
		var g trimGate
		for sample := 0; sample < 20; sample++ {
			if g.observe(at(sample), false, 42) {
				t.Fatalf("sample %d: trimmed while not quiescent", sample)
			}
		}
	})
}

// The listeners expose the counters the gate needs: admissions move when
// queries are served, and trim empties the caches those queries filled.
func TestListenerAdmissionCountMoves(t *testing.T) {
	e := newUDPEngine(echoHandler(), nil, false, 1, 1, defaultResourcePlan(1))
	if e.admissions() != 0 {
		t.Fatalf("fresh engine reports %d admissions", e.admissions())
	}
	j := e.take()
	if j == nil {
		t.Fatal("lease refused")
	}
	if e.admissions() != 1 {
		t.Fatalf("admissions = %d after one lease, want 1", e.admissions())
	}
	j.state = udpJobReading
	j.release(udpJobReading)
	if got := e.trimIdle(); got != 1 {
		t.Fatalf("trim dropped %d slabs, want the parked one", got)
	}
}
