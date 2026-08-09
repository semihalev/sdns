package resolver

import (
	"context"
	"errors"
	"sync"

	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

// Aggressive proof classification is optional provenance work performed only
// after the authoritative response has passed exact DNSSEC validation. It
// must not debit the request's required MaxNSEC3Hashes allowance: if reuse is
// too expensive, the response remains valid and simply is not published to
// the RFC 8198 cache.
const resolverAggressiveProofMaxNSEC3Hashes uint32 = 32

var (
	errResolverAggressiveProofHashLimit = errors.New("resolver: aggressive proof NSEC3 hash limit exceeded")
	errResolverAggressiveProofBusy      = errors.New("resolver: aggressive proof crypto unavailable")
)

type resolverAggressiveProofWork struct {
	ctx     context.Context
	limiter *dnssec.CryptoLimiter
	memo    *dnssec.NSEC3HashMemo
}

var _ dnssec.NSEC3Work = (*resolverAggressiveProofWork)(nil)

func newResolverAggressiveProofWork(
	ctx context.Context,
	limiter *dnssec.CryptoLimiter,
) *resolverAggressiveProofWork {
	memo := dnssec.NSEC3HashMemoFromContextScope(
		ctx,
		dnssec.NSEC3HashMemoScopeResolverOptional,
	)
	if memo == nil {
		memo = dnssec.NewNSEC3HashMemo()
	}
	return &resolverAggressiveProofWork{
		ctx:     ctx,
		limiter: limiter,
		memo:    memo,
	}
}

func (w *resolverAggressiveProofWork) BeginNSEC3Hash() (func(), error) {
	if w == nil || w.ctx == nil {
		return nil, context.Canceled
	}
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	if !w.memo.TryReserveWork(resolverAggressiveProofMaxNSEC3Hashes) {
		return nil, errResolverAggressiveProofHashLimit
	}
	if w.limiter == nil {
		// Focused resolver tests use zero-value Resolver instances. Production
		// construction always installs the shared limiter; mirror dnssecWork's
		// existing zero-value convention without weakening that path.
		return func() {}, nil
	}

	release, ok := w.limiter.TryAcquire()
	if !ok || release == nil {
		return nil, errResolverAggressiveProofBusy
	}
	if err := w.ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return sync.OnceFunc(release), nil
}

func (w *resolverAggressiveProofWork) NSEC3HashMemos() dnssec.NSEC3HashMemoAccess {
	if w == nil {
		return dnssec.NSEC3HashMemoAccess{}
	}
	return dnssec.NSEC3HashMemoAccess{
		Read:  dnssec.NSEC3HashMemoFromContext(w.ctx),
		Write: w.memo,
	}
}
