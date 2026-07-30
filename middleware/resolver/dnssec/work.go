package dnssec

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// SignatureWork is the resolver-owned work contract used immediately before
// an RRSIG public-key operation. Cheap structural checks and candidate
// deduplication happen before these methods are reached.
type SignatureWork interface {
	CheckDNSKEYCandidate(used uint32) error
	CheckRRsetSignature(used uint32) error
	BeginSignature() (release func(), err error)
}

// DSDigestWork is the resolver-owned work contract used immediately before a
// DNSKEY digest operation.
type DSDigestWork interface {
	CheckDNSKEYCandidate(used uint32) error
	BeginDSDigest() (release func(), err error)
}

// NSEC3Work is the resolver-owned work contract used immediately before each
// hash-backed NSEC3 Match or Cover operation.
type NSEC3Work interface {
	BeginNSEC3Hash() (release func(), err error)
}

// WorkError marks an error returned by the resolver-owned work governor. It
// preserves the original error for errors.Is/errors.As while letting DNSSEC
// candidate loops distinguish a terminal budget/semaphore failure from an
// ordinary bad signature that may have a valid sibling.
type WorkError struct {
	err error
}

func (e *WorkError) Error() string { return e.err.Error() }

func (e *WorkError) Unwrap() error { return e.err }

func wrapWorkError(err error) error {
	if err == nil {
		return nil
	}
	return &WorkError{err: err}
}

// IsWorkError reports whether err originated from a DNSSEC work governor.
func IsWorkError(err error) bool {
	var workErr *WorkError
	return errors.As(err, &workErr)
}

// DNSKEYToDSWithWork computes one DNSKEY digest under the same accounting and
// concurrency gate used by VerifyDSWithWork. It is used when the resolver
// materializes DS records from configured trust anchors.
func DNSKEYToDSWithWork(key *dns.DNSKEY, digestType uint8, work DSDigestWork) (*dns.DS, error) {
	release, err := beginDSDigest(work)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release()
	}
	return key.ToDS(digestType), nil
}

// CryptoLimiter bounds expensive DNSSEC work across all request trees handled
// by one Resolver. Per-tree budgets prevent asymmetric amplification; this
// resolver-level gate prevents many individually-bounded requests from
// running unbounded crypto concurrently.
type CryptoLimiter struct {
	tokens   chan struct{}
	capacity uint32
}

// NewCryptoLimiter constructs a fixed-size crypto semaphore.
func NewCryptoLimiter(maxConcurrent uint32) *CryptoLimiter {
	if maxConcurrent == 0 {
		panic("dnssec: max concurrent crypto operations must be greater than zero")
	}
	return &CryptoLimiter{
		tokens:   make(chan struct{}, maxConcurrent),
		capacity: maxConcurrent,
	}
}

// Acquire waits for one crypto slot or for ctx cancellation. The returned
// release function must be called exactly once after the operation completes.
func (l *CryptoLimiter) Acquire(ctx context.Context) (func(), error) {
	if l == nil {
		return nil, fmt.Errorf("dnssec: crypto limiter is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case l.tokens <- struct{}{}:
		return func() { <-l.tokens }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Capacity reports the configured resolver-wide concurrency ceiling.
func (l *CryptoLimiter) Capacity() uint32 {
	if l == nil {
		return 0
	}
	return l.capacity
}
