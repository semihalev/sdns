package cache

import (
	"context"
	"testing"

	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

func TestDenialProofWorkNSEC3MemoStaysPrivate(t *testing.T) {
	ctx := dnssec.EnsureNSEC3HashMemo(context.Background())
	shared := dnssec.NSEC3HashMemoFromContext(ctx)
	if shared == nil {
		t.Fatal("request context has no NSEC3 memo")
	}

	first := newDenialProofWork(ctx, dnssec.NewCryptoLimiter(1))
	access := first.NSEC3HashMemos()
	if access.Read == nil || access.Write == nil {
		t.Fatal("cache denial work has no private NSEC3 memo")
	}
	if access.Read != access.Write {
		t.Fatal("cache denial work does not read and write the same private memo")
	}
	if access.Read == shared || access.Write == shared {
		t.Fatal("cache denial work exposes the request-tree required memo")
	}
	second := newDenialProofWork(ctx, dnssec.NewCryptoLimiter(1))
	if second.memo != first.memo {
		t.Fatal("cache denial work resets its request-tree private memo")
	}
}

func TestDenialProofWorkHashLimitSpansAdapters(t *testing.T) {
	ctx := dnssec.EnsureNSEC3HashMemo(context.Background())
	limiter := dnssec.NewCryptoLimiter(1)
	first := newDenialProofWork(ctx, limiter)
	second := newDenialProofWork(ctx, limiter)

	for i := uint32(0); i < denialProofMaxNSEC3Hashes; i++ {
		work := first
		if i >= denialProofMaxNSEC3Hashes/2 {
			work = second
		}
		release, err := work.BeginNSEC3Hash()
		if err != nil {
			t.Fatalf("optional hash %d: %v", i+1, err)
		}
		release()
	}
	if _, err := second.BeginNSEC3Hash(); err != errDenialProofNSEC3HashLimit {
		t.Fatalf("cross-adapter limit error = %v, want %v",
			err, errDenialProofNSEC3HashLimit)
	}
}
