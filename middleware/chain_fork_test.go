package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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
