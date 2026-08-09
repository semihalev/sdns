package cache

import (
	"context"
	"errors"
	"testing"

	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

func TestDenialProofWorkNSEC3HashBoundary(t *testing.T) {
	limiter := dnssec.NewCryptoLimiter(1)
	work := newDenialProofWork(context.Background(), limiter)

	for i := uint32(0); i < denialProofMaxNSEC3Hashes; i++ {
		release, err := work.BeginNSEC3Hash()
		if err != nil {
			t.Fatalf("hash %d: %v", i+1, err)
		}
		if release == nil {
			t.Fatalf("hash %d returned nil release", i+1)
		}
		release()
	}

	release, err := work.BeginNSEC3Hash()
	if !errors.Is(err, errDenialProofNSEC3HashLimit) {
		t.Fatalf("hash %d error = %v, want local limit", denialProofMaxNSEC3Hashes+1, err)
	}
	if release != nil {
		t.Fatal("rejected hash returned a release function")
	}
}

func TestDenialProofWorkRejectsUnavailableCrypto(t *testing.T) {
	t.Run("nil limiter", func(t *testing.T) {
		work := newDenialProofWork(context.Background(), nil)
		release, err := work.BeginNSEC3Hash()
		if !errors.Is(err, errDenialProofCryptoBusy) {
			t.Fatalf("error = %v, want unavailable crypto", err)
		}
		if release != nil {
			t.Fatal("nil limiter returned a release function")
		}
	})

	t.Run("occupied limiter", func(t *testing.T) {
		limiter := dnssec.NewCryptoLimiter(1)
		heldRelease, ok := limiter.TryAcquire()
		if !ok {
			t.Fatal("failed to occupy crypto limiter")
		}
		defer heldRelease()

		work := newDenialProofWork(context.Background(), limiter)
		release, err := work.BeginNSEC3Hash()
		if !errors.Is(err, errDenialProofCryptoBusy) {
			t.Fatalf("error = %v, want unavailable crypto", err)
		}
		if release != nil {
			t.Fatal("saturated limiter returned a release function")
		}
	})
}

func TestDenialProofWorkReleaseFreesSharedSlot(t *testing.T) {
	limiter := dnssec.NewCryptoLimiter(1)
	work := newDenialProofWork(context.Background(), limiter)

	release, err := work.BeginNSEC3Hash()
	if err != nil {
		t.Fatalf("BeginNSEC3Hash: %v", err)
	}
	if occupiedRelease, ok := limiter.TryAcquire(); ok {
		occupiedRelease()
		t.Fatal("work did not occupy the shared limiter")
	}

	release()
	release() // The adapter makes release idempotent for defensive callers.

	nextRelease, ok := limiter.TryAcquire()
	if !ok {
		t.Fatal("returned release did not free the shared limiter")
	}
	nextRelease()
}

func TestDenialProofWorkRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	limiter := dnssec.NewCryptoLimiter(1)
	work := newDenialProofWork(ctx, limiter)
	release, err := work.BeginNSEC3Hash()
	if !errors.Is(err, errDenialProofContextDone) {
		t.Fatalf("error = %v, want denial-proof context sentinel", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if release != nil {
		t.Fatal("canceled work returned a release function")
	}

	availableRelease, ok := limiter.TryAcquire()
	if !ok {
		t.Fatal("canceled work leaked a shared crypto slot")
	}
	availableRelease()
}

func TestDenialProofWorkDoesNotDebitRequestLedger(t *testing.T) {
	policy := middleware.RecursionWorkPolicy{
		Mode:           middleware.RecursionWorkEnforce,
		MaxNSEC3Hashes: 1,
	}
	ctx, ledger := middleware.EnsureRecursionWork(context.Background(), policy)
	if ledger == nil {
		t.Fatal("enforce policy did not create a recursion-work ledger")
	}

	work := newDenialProofWork(ctx, dnssec.NewCryptoLimiter(1))
	for i := uint32(0); i < denialProofMaxNSEC3Hashes; i++ {
		release, err := work.BeginNSEC3Hash()
		if err != nil {
			t.Fatalf("optional hash %d: %v", i+1, err)
		}
		release()
	}
	if _, err := work.BeginNSEC3Hash(); !errors.Is(err, errDenialProofNSEC3HashLimit) {
		t.Fatalf("optional limit error = %v, want local limit", err)
	}

	snapshot := ledger.Snapshot()
	if snapshot.NSEC3Hashes != 0 {
		t.Fatalf("optional hashes debited request ledger: got %d, want 0", snapshot.NSEC3Hashes)
	}
	if err := middleware.RecursionWorkEnforcementError(ctx); err != nil {
		t.Fatalf("optional hashes latched request enforcement: %v", err)
	}

	if err := middleware.DebitRecursionWork(ctx, middleware.RecursionWorkNSEC3Hash); err != nil {
		t.Fatalf("subsequent required NSEC3 hash: %v", err)
	}
	if got := ledger.Snapshot().NSEC3Hashes; got != 1 {
		t.Fatalf("required hash ledger count = %d, want 1", got)
	}
}
