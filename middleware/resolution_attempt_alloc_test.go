package middleware

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// resolutionAttemptStep is one recorded attempt: a question, and the endpoint
// it was asked of in the canonical spelling the delegation path already holds.
type resolutionAttemptStep struct {
	q        dns.Question
	endpoint string
}

// resolutionAttemptTrace is the shape a recursion presents to the guard: a
// handful of questions, each asked of a handful of endpoints, every tuple
// distinct.
func resolutionAttemptTrace(questions, endpoints int) []resolutionAttemptStep {
	names := []string{
		"example.com.", "www.example.com.", "cdn.example.com.",
		"a.deep.example.com.", "mail.example.com.", "api.example.com.",
	}
	trace := make([]resolutionAttemptStep, 0, questions*endpoints)
	for i := range questions {
		q := dns.Question{
			Name:   names[i%len(names)],
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}
		for j := range endpoints {
			addr := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{192, 0, 2, byte(j + 1)}), 53)
			trace = append(trace, resolutionAttemptStep{q, addr.String()})
		}
	}
	return trace
}

// TestBeginCanonicalMatchesBegin pins that the two entry points are the same
// guard: an attempt recorded through either must count against the other, or
// the RFC 9520 limit could be evaded by alternating between them.
func TestBeginCanonicalMatchesBegin(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	const canonical = "192.0.2.1:53"

	guard := NewResolutionAttemptGuard()
	for i := range maxResolutionAttempts {
		var err error
		if i%2 == 0 {
			err = guard.BeginCanonical(q, canonical, "udp")
		} else {
			// A spelling the normalizer has to fold to the same identity.
			err = guard.Begin(q, " 192.0.2.1:53 ", "UDP")
		}
		if err != nil {
			t.Fatalf("attempt %d rejected: %v", i+1, err)
		}
	}
	if err := guard.BeginCanonical(q, canonical, "udp"); err == nil {
		t.Fatal("the fourth attempt was admitted; alternating entry points " +
			"split one tuple into two counters")
	}
	if err := guard.Begin(q, "192.0.2.1:53", "udp"); err == nil {
		t.Fatal("the fourth attempt was admitted through the spelled path")
	}
}

// TestBeginCanonicalReportsTheEndpoint keeps the limit error legible.
func TestBeginCanonicalReportsTheEndpoint(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	const canonical = "192.0.2.1:53"

	guard := NewResolutionAttemptGuard()
	for range maxResolutionAttempts {
		if err := guard.BeginCanonical(q, canonical, "udp"); err != nil {
			t.Fatalf("attempt rejected: %v", err)
		}
	}
	err := guard.BeginCanonical(q, canonical, "udp")
	if err == nil {
		t.Fatal("the fourth attempt was admitted")
	}
	var limit *ResolutionAttemptLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("error is %T, want *ResolutionAttemptLimitError", err)
	}
	if limit.Endpoint != canonical {
		t.Fatalf("limit error names endpoint %q, want %q",
			limit.Endpoint, canonical)
	}
}

// TestGuardCostsNothingWithoutAnAttempt pins the cache-hit case. Most requests
// are answered without touching the network, and the guard's storage must not
// be part of what they carry.
func TestGuardCostsNothingWithoutAnAttempt(t *testing.T) {
	allocs := testing.AllocsPerRun(200, func() {
		var guard ResolutionAttemptGuard
		if guard.table != nil {
			t.Fatal("a guard allocated storage before recording an attempt")
		}
	})
	if allocs != 0 {
		t.Fatalf("an unused guard cost %.0f allocations", allocs)
	}
}

// TestBeginCanonicalCostsOneAllocationForATypicalRecursion pins the guard's
// cost against the shape a real request tree presents: the inline table, once,
// and nothing else. The endpoint arrives already spelled, so recording an
// attempt does not normalize it, and a handful of tuples does not need a map.
func TestBeginCanonicalCostsOneAllocationForATypicalRecursion(t *testing.T) {
	const runs = 200
	trace := resolutionAttemptTrace(2, 2)

	// A fresh guard per run, built outside the measurement: the guard
	// itself is one allocation the request tree pays anyway, and what is
	// being measured is what recording attempts adds to it.
	guards := make([]*ResolutionAttemptGuard, runs+2)
	for i := range guards {
		guards[i] = NewResolutionAttemptGuard()
	}
	run := 0

	allocs := testing.AllocsPerRun(runs, func() {
		guard := guards[run]
		run++
		for _, step := range trace {
			if err := guard.BeginCanonical(step.q, step.endpoint, "udp"); err != nil {
				t.Fatalf("attempt rejected: %v", err)
			}
		}
	})
	if allocs != 1 {
		t.Fatalf("a %d-attempt request tree cost %.0f allocations, want 1 "+
			"(the inline table)", len(trace), allocs)
	}
}

// TestResolutionAttemptGuardCountsAcrossTheOverflow pins the limit through the
// boundary between the inline table and the map. A tuple lives in one store or
// the other, and a tuple that moved between them — or was recorded in both —
// would either lose its count or double it.
func TestResolutionAttemptGuardCountsAcrossTheOverflow(t *testing.T) {
	trace := resolutionAttemptTrace(4, 4)
	if len(trace) <= len(new(resolutionAttemptTable).slots) {
		t.Fatal("fixture is wrong: the trace does not overflow the inline table")
	}
	guard := NewResolutionAttemptGuard()

	// Every tuple admits exactly maxResolutionAttempts, wherever it lives.
	for attempt := range maxResolutionAttempts {
		for i, step := range trace {
			if err := guard.BeginCanonical(step.q, step.endpoint, "udp"); err != nil {
				t.Fatalf("tuple %d rejected on attempt %d: %v", i, attempt+1, err)
			}
		}
	}
	for i, step := range trace {
		if err := guard.BeginCanonical(step.q, step.endpoint, "udp"); err == nil {
			t.Fatalf("tuple %d admitted attempt %d", i, maxResolutionAttempts+1)
		}
	}
}

func BenchmarkResolutionAttemptGuard(b *testing.B) {
	for _, shape := range []struct {
		name      string
		questions int
		endpoints int
	}{
		{"attempts=4", 2, 2},
		{"attempts=12", 3, 4},
		{"attempts=36", 6, 6},
	} {
		trace := resolutionAttemptTrace(shape.questions, shape.endpoints)
		b.Run(shape.name+"/canonical", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				guard := NewResolutionAttemptGuard()
				for _, step := range trace {
					_ = guard.BeginCanonical(step.q, step.endpoint, "udp")
				}
			}
		})
		b.Run(shape.name+"/spelled", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				guard := NewResolutionAttemptGuard()
				for _, step := range trace {
					_ = guard.Begin(step.q, step.endpoint, "udp")
				}
			}
		})
	}
}
