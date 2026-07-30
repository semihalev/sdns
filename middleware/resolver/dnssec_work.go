package resolver

import (
	"context"
	"errors"

	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

// dnssecWorkBudget adapts the request-tree recursion ledger and this
// Resolver's shared crypto semaphore to the narrow contracts used by
// the pure DNSSEC verification package. It deliberately has no DNS message or
// CD-bit input: any cryptographic operation that runs is accounted, including
// explicit validation of internal CD=1 lookups.
type dnssecWorkBudget struct {
	ctx     context.Context
	limiter *dnssec.CryptoLimiter
}

func (w dnssecWorkBudget) CheckDNSKEYCandidate(used uint32) error {
	return middleware.CheckRecursionWorkLocalLimit(
		w.ctx,
		middleware.RecursionWorkDNSKEYCandidate,
		used,
	)
}

func (w dnssecWorkBudget) CheckRRsetSignature(used uint32) error {
	return middleware.CheckRecursionWorkLocalLimit(
		w.ctx,
		middleware.RecursionWorkRRsetSignature,
		used,
	)
}

func (w dnssecWorkBudget) BeginSignature() (func(), error) {
	return w.begin(middleware.RecursionWorkSignature)
}

func (w dnssecWorkBudget) BeginDSDigest() (func(), error) {
	return w.begin(middleware.RecursionWorkDSDigest)
}

func (w dnssecWorkBudget) BeginNSEC3Hash() (func(), error) {
	return w.begin(middleware.RecursionWorkNSEC3Hash)
}

func (w dnssecWorkBudget) begin(kind middleware.RecursionWorkKind) (func(), error) {
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	if err := middleware.DebitRecursionWork(w.ctx, kind); err != nil {
		return nil, err
	}
	if w.limiter == nil {
		// Zero-value Resolvers are useful in focused tests. Production
		// construction always installs the configured resolver-wide gate.
		return func() {}, nil
	}
	release, err := w.limiter.Acquire(w.ctx)
	if err == nil {
		return release, nil
	}
	if rejection := middleware.RejectRecursionWork(
		w.ctx,
		middleware.RecursionWorkConcurrentCrypto,
	); rejection != nil {
		return nil, rejection
	}
	return nil, err
}

func (r *Resolver) dnssecWork(ctx context.Context) dnssecWorkBudget {
	return dnssecWorkBudget{ctx: ctx, limiter: r.cryptoLimiter}
}

func isDNSSECWorkError(err error) bool {
	return dnssec.IsWorkError(err) || errors.Is(err, middleware.ErrRecursionWorkLimit)
}
