package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

const denialProofMaxNSEC3Hashes uint32 = 32

var (
	errDenialProofNSEC3HashLimit = errors.New("cache: denial proof NSEC3 hash limit exceeded")
	errDenialProofCryptoBusy     = errors.New("cache: denial proof DNSSEC crypto unavailable")
	errDenialProofContextDone    = errors.New("cache: denial proof context done")
)

// denialProofWork bounds optional cache-side NSEC3 hashing independently from
// the request's recursion-work ledger. Aggressive denial synthesis is only an
// optimization: it must yield immediately when required DNSSEC validation owns
// every shared crypto slot, and exhausting its local allowance must not poison
// the request that will perform the fallback lookup.
type denialProofWork struct {
	ctx     context.Context
	limiter middleware.DNSSECCryptoLimiter
	hashes  atomic.Uint32
}

var _ dnssec.NSEC3Work = (*denialProofWork)(nil)

func newDenialProofWork(
	ctx context.Context,
	limiter middleware.DNSSECCryptoLimiter,
) *denialProofWork {
	return &denialProofWork{ctx: ctx, limiter: limiter}
}

// BeginNSEC3Hash reserves one local hash allowance and one shared crypto slot.
// It deliberately never consults middleware.RecursionWorkFrom or calls any
// recursion-work debit: fallback validation owns that request-local budget.
func (w *denialProofWork) BeginNSEC3Hash() (func(), error) {
	if w == nil || w.ctx == nil {
		return nil, errDenialProofContextDone
	}
	if err := w.ctx.Err(); err != nil {
		return nil, denialProofContextError(err)
	}
	if w.limiter == nil {
		return nil, errDenialProofCryptoBusy
	}
	if !w.reserveHash() {
		return nil, errDenialProofNSEC3HashLimit
	}

	release, ok := w.limiter.TryAcquire()
	if !ok || release == nil {
		if err := w.ctx.Err(); err != nil {
			return nil, denialProofContextError(err)
		}
		return nil, errDenialProofCryptoBusy
	}

	// Cancellation may race the non-blocking acquisition. Do not publish a
	// successful reservation after the lookup has already been abandoned.
	if err := w.ctx.Err(); err != nil {
		release()
		return nil, denialProofContextError(err)
	}

	return sync.OnceFunc(release), nil
}

func (w *denialProofWork) reserveHash() bool {
	for {
		used := w.hashes.Load()
		if used >= denialProofMaxNSEC3Hashes {
			return false
		}
		if w.hashes.CompareAndSwap(used, used+1) {
			return true
		}
	}
}

func denialProofContextError(err error) error {
	return fmt.Errorf("%w: %w", errDenialProofContextDone, err)
}
