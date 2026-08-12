package middleware

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestForkDoesNotCrossRequestGenerations pins the isolation a pooled root
// requires. A root meta is reset and reused by the next request, and a fork
// of the request before it can still be alive — it must keep reading the
// state of the request it belongs to, never the one that took the root over.
func TestForkDoesNotCrossRequestGenerations(t *testing.T) {
	root := new(ResponseMeta)

	first := root.EnsureResolutionAttemptGuard()
	if first == nil {
		t.Fatal("the first request could not establish a retry guard")
	}
	child := root.ForkCut()
	if child.ResolutionAttemptGuard() != first {
		t.Fatal("the fork does not share its own request's retry guard")
	}

	// The root is returned to the pool and taken over by the next request.
	root.Reset()
	second := root.EnsureResolutionAttemptGuard()
	if second == nil {
		t.Fatal("the second request could not establish a retry guard")
	}
	if second == first {
		t.Fatal("the reset root handed the second request the first's guard")
	}

	if got := child.ResolutionAttemptGuard(); got == second {
		t.Fatal("a fork of the first request now reads the second request's " +
			"retry guard: the pooled root's address is not an identity")
	} else if got != first {
		t.Fatalf("a fork of the first request lost its own guard: %v", got)
	}
}

// TestEstablishingUnderResetAlwaysYieldsAHost pins what an operation that is
// about to record something gets while the root is being reset underneath it.
//
// Establishing state is a load, a create and an exchange; a reset landing
// between a lost exchange and a read back would hand the caller nothing to
// record into. Every caller here dereferences what it is given.
func TestEstablishingUnderResetAlwaysYieldsAHost(t *testing.T) {
	root := new(ResponseMeta)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4000 {
				if guard := root.EnsureResolutionAttemptGuard(); guard == nil {
					t.Error("establishing a retry guard yielded nothing to " +
						"record into")
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 4000 {
			root.Reset()
		}
	}()
	wg.Wait()
}

// TestForkResetRacesWithLedgerReaders pins the synchronisation on the fork
// link. Metas are pooled, so one request can reset a root while a sub-query
// of the request before it is still reading the tree through its fork.
func TestForkResetRacesWithLedgerReaders(t *testing.T) {
	parent := new(ResponseMeta)
	parent.EnsureResolutionAttemptGuard()
	child := parent.ForkCut()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 2000 {
			child.Reset()
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			_ = child.ResolutionAttemptGuard()
		}
	}()
	wg.Wait()
}

// TestForkCutSeparatesLineageAndSharesLedgers pins what a sub-query's meta
// keeps to itself and what it shares.
//
// The cut is its own: a sub-query's answer is cached under its own key, so a
// nearly expired request that happens to ask for it must not shorten it.
// Everything else belongs to the request tree — the work ledger, the retry
// guard, and the provenance a nested lookup records — and the tree must see
// what the sub-query records even though those are created lazily.
func TestForkCutSeparatesLineageAndSharesLedgers(t *testing.T) {
	parent := new(ResponseMeta)
	child := parent.ForkCut()
	if child == nil {
		t.Fatal("ForkCut returned nothing")
	}

	// The child's own bound stays with the child until it is merged back.
	childDeadline := time.Now().Add(time.Second)
	child.BoundCutFor(childDeadline, 7)
	if got, _ := parent.Cut(); !got.IsZero() {
		t.Fatalf("the sub-query's deadline reached the request tree on its "+
			"own: parent bound to %v", got)
	}
	if got, key := child.Cut(); !got.Equal(childDeadline) || key != 7 {
		t.Fatalf("child cut = (%v, %d), want (%v, 7)", got, key, childDeadline)
	}

	// A bound the tree already carries does not shorten the sub-query.
	parentDeadline := time.Now().Add(time.Millisecond)
	parent.BoundCutFor(parentDeadline, 3)
	if got, _ := child.Cut(); !got.Equal(childDeadline) {
		t.Fatalf("the request tree's deadline shortened the sub-query: "+
			"child bound to %v, want its own %v", got, childDeadline)
	}

	// Ledgers created through the child are the tree's, not copies. They are
	// created lazily, so a fork that copied their pointers would share
	// nothing here — this is the case that catches it.
	guard := child.EnsureResolutionAttemptGuard()
	if guard == nil {
		t.Fatal("the sub-query could not establish a retry guard")
	}
	if parent.ResolutionAttemptGuard() != guard {
		t.Fatal("a retry guard established by the sub-query is invisible to " +
			"the request tree")
	}

	proof := new(dns.Msg)
	proof.SetQuestion("denied.example.", dns.TypeA)
	proof.Rcode = dns.RcodeNameError
	if !child.markValidatedNegativeProofResponse(proof, proof, ValidatedNegativeProof{
		Subject: "denied.example.", Zone: "example.",
		Kind: ValidatedNegativeProofNSEC, Proof: proof,
	}) {
		t.Fatal("the sub-query could not record provenance")
	}
	if _, ok := parent.validatedNegativeProofForResponse(proof); !ok {
		t.Fatal("provenance recorded by the sub-query is invisible to the " +
			"request tree")
	}
}

// TestForkedCutScopeCostsOneAllocation is the gate the benchmark below only
// reports. A sub-query scope runs once per chase hop and once per DNAME leg,
// so carrying the meta inside the context value rather than forking one and
// wrapping the context around it is a property worth failing on, not a
// number to read afterwards.
//
// Both the warm and the cold shape are measured. AllocsPerRun establishes
// the request's ledgers during its warm-up, so a warm-only gate would never
// see what the first scope of a request costs — which is the one a CNAME or
// DNAME leg actually pays.
func TestForkedCutScopeCostsOneAllocation(t *testing.T) {
	// What a sub-query actually does: take a scope, then pin the request
	// tree's retry guard. Measuring the scope alone would miss a wrapper the
	// pin adds when the scope does not carry the guard itself.
	enterSubQuery := func(t *testing.T, base context.Context) {
		t.Helper()
		ctx, child := WithForkedCut(base)
		if child == nil || ResponseMetaFrom(ctx) != child {
			t.Fatal("the scope did not carry its own meta")
		}
		pinned, guard := EnsureResolutionAttemptGuard(ctx)
		if guard == nil {
			t.Fatal("the sub-query has no retry guard")
		}
		if pinned != ctx {
			t.Fatal("pinning the retry guard wrapped the scope again; the " +
				"scope must carry it")
		}
	}

	t.Run("warm", func(t *testing.T) {
		var meta ResponseMeta
		meta.EnsureResolutionAttemptGuard()
		base := WithResponseMeta(context.Background(), &meta)

		allocs := testing.AllocsPerRun(200, func() { enterSubQuery(t, base) })
		if allocs != 1 {
			t.Fatalf("a sub-query cost %.0f allocations, want 1", allocs)
		}
	})

	t.Run("cold", func(t *testing.T) {
		// The scope, and the request's ledgers it establishes.
		const budget = 2

		var meta ResponseMeta
		base := WithResponseMeta(context.Background(), &meta)

		allocs := testing.AllocsPerRun(200, func() {
			meta.Reset()
			enterSubQuery(t, base)
		})
		if allocs > budget {
			t.Fatalf("the first sub-query of a request cost %.0f "+
				"allocations, budget is %d", allocs, budget)
		}
	})
}

// TestForkedCutScopeKeepsAPinnedGuard pins what the scope may not do with a
// guard it does not own. A detached or custom context can carry one, and
// shadowing it would move that sub-query's retry accounting to a guard
// nobody else is reading.
func TestForkedCutScopeKeepsAPinnedGuard(t *testing.T) {
	var meta ResponseMeta
	own := meta.EnsureResolutionAttemptGuard()

	foreign := NewResolutionAttemptGuard()
	base := WithResolutionAttemptGuard(
		WithResponseMeta(context.Background(), &meta), foreign)

	ctx, _ := WithForkedCut(base)
	got := ResolutionAttemptGuardFrom(ctx)
	if got == own {
		t.Fatal("the scope replaced a pinned guard with the meta's own")
	}
	if got != foreign {
		t.Fatalf("the scope lost the pinned guard: %v", got)
	}
}

// BenchmarkForkedCutScope measures what a chase hop pays to separate its
// lineage. It runs once per sub-query, so the scope must not cost more than
// the separation is worth.
func BenchmarkForkedCutScope(b *testing.B) {
	var meta ResponseMeta
	base := WithResponseMeta(context.Background(), &meta)

	b.Run("embedded", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ctx, child := WithForkedCut(base)
			if child == nil || ResponseMetaFrom(ctx) != child {
				b.Fatal("the scope did not carry its own meta")
			}
		}
	})

	b.Run("separate value node", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			child := meta.ForkCut()
			ctx := WithResponseMeta(base, child)
			if child == nil || ResponseMetaFrom(ctx) != child {
				b.Fatal("the scope did not carry its own meta")
			}
		}
	})
}

// TestForkResetDetachesTheRequestTree pins the reset contract for a fork.
// ResponseMeta values are pooled and reused, so a reset one that still read
// the state of the request it was forked from would hand the next request
// the previous one's retry guard.
func TestForkResetDetachesTheRequestTree(t *testing.T) {
	parent := new(ResponseMeta)
	guard := parent.EnsureResolutionAttemptGuard()
	if guard == nil {
		t.Fatal("the request tree could not establish a retry guard")
	}

	child := parent.ForkCut()
	if child.ResolutionAttemptGuard() != guard {
		t.Fatal("the fork does not share the request tree's retry guard")
	}

	child.Reset()
	if got := child.ResolutionAttemptGuard(); got != nil {
		t.Fatal("a reset fork still reads the state of the request it was " +
			"forked from")
	}
	if parent.ResolutionAttemptGuard() != guard {
		t.Fatal("resetting a fork disturbed the request tree it left")
	}
}
