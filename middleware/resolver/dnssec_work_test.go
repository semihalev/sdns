package resolver

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

type stagedCancellationContext struct {
	context.Context
	done        chan struct{}
	nilErrCalls int
	errCalls    int
}

func newStagedCancellationContext(parent context.Context, nilErrCalls int) *stagedCancellationContext {
	done := make(chan struct{})
	close(done)
	return &stagedCancellationContext{
		Context:     parent,
		done:        done,
		nilErrCalls: nilErrCalls,
	}
}

func (c *stagedCancellationContext) Done() <-chan struct{} { return c.done }

func (c *stagedCancellationContext) Err() error {
	c.errCalls++
	if c.errCalls <= c.nilErrCalls {
		return nil
	}
	return context.Canceled
}

func TestDNSSECWorkBudgetAppliesToExplicitCDValidation(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	privateKey, err := key.Generate(256)
	if err != nil {
		t.Fatalf("Generate DNSKEY: %v", err)
	}

	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 0, 2, 10},
	}
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   answer.Hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    answer.Hdr.Ttl,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(answer.Hdr.Name)), //nolint:gosec // DNS names have at most 127 labels.
		OrigTtl:     answer.Hdr.Ttl,
		Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // bounded test timestamp
		Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // bounded test timestamp
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("private key type = %T, want crypto.Signer", privateKey)
	}
	if err := sig.Sign(signer, []dns.RR{answer}); err != nil {
		t.Fatalf("Sign RRset: %v", err)
	}

	policy := middleware.RecursionWorkPolicy{
		Mode:                    middleware.RecursionWorkEnforce,
		MaxDNSKEYCandidates:     4,
		MaxRRsetSignatureChecks: 8,
		MaxSignatureChecks:      1,
		MaxDSDigests:            32,
		MaxNSEC3Hashes:          32,
		MaxConcurrentCrypto:     1,
	}
	ctx, ledger := middleware.EnsureRecursionWork(context.Background(), policy)
	r := &Resolver{cryptoLimiter: dnssec.NewCryptoLimiter(1)}
	work := r.dnssecWork(ctx)

	msg := new(dns.Msg)
	msg.SetQuestion(answer.Hdr.Name, dns.TypeA)
	msg.CheckingDisabled = true
	msg.Answer = []dns.RR{answer, sig}

	verified, err := dnssec.VerifyRRSIGWithWork(key.Hdr.Name, map[uint16][]*dns.DNSKEY{
		key.KeyTag(): {key},
	}, msg, work)
	if err != nil || !verified {
		t.Fatalf("explicit CD=1 verification = (%v, %v), want (true, nil)", verified, err)
	}
	if got := ledger.Snapshot().SignatureChecks; got != 1 {
		t.Fatalf("CD=1 signature checks = %d, want 1", got)
	}

	verified, err = dnssec.VerifyRRSIGWithWork(key.Hdr.Name, map[uint16][]*dns.DNSKEY{
		key.KeyTag(): {key},
	}, msg, work)
	if verified || !errors.Is(err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("second explicit CD=1 verification = (%v, %v), want work-limit failure", verified, err)
	}
	var limitErr *middleware.RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.EDECode() != dns.ExtendedErrorCodeDNSSECIndeterminate {
		t.Fatalf("EDE code = %d, want DNSSEC Indeterminate (5)", limitErr.EDECode())
	}
}

func TestDNSSECWorkBudgetMapsSemaphoreExhaustionToPolicyFailure(t *testing.T) {
	policy := middleware.RecursionWorkPolicy{
		Mode:                middleware.RecursionWorkEnforce,
		MaxSignatureChecks:  2,
		MaxDSDigests:        2,
		MaxNSEC3Hashes:      2,
		MaxConcurrentCrypto: 1,
	}
	ctx, ledger := middleware.EnsureRecursionWork(context.Background(), policy)
	r := &Resolver{cryptoLimiter: dnssec.NewCryptoLimiter(1)}

	release, err := r.dnssecWork(ctx).BeginSignature()
	if err != nil {
		t.Fatalf("first BeginSignature: %v", err)
	}

	// The first two Err calls cover dnssecWorkBudget.begin and
	// CryptoLimiter.Acquire preflight. Done is already closed, so the limiter
	// deterministically observes a full slot before cancellation wins.
	waiting := newStagedCancellationContext(ctx, 2)
	nextRelease, nextErr := r.dnssecWork(waiting).BeginDSDigest()
	if !errors.Is(nextErr, middleware.ErrRecursionWorkLimit) || nextRelease != nil {
		t.Fatalf("saturated BeginDSDigest returned release=%t err=%v, want crypto policy failure",
			nextRelease != nil, nextErr)
	}
	var limitErr *middleware.RecursionWorkLimitError
	if !errors.As(nextErr, &limitErr) ||
		limitErr.Kind != middleware.RecursionWorkConcurrentCrypto ||
		limitErr.EDECode() != middleware.DNSSECWorkEDECode {
		t.Fatalf("semaphore error = %#v, want concurrent-crypto EDE 5", limitErr)
	}
	release()

	snapshot := ledger.Snapshot()
	if snapshot.SignatureChecks != 1 || snapshot.DSDigests != 1 {
		t.Fatalf("cancelled wait refunded work: signature=%d DS=%d, want 1/1",
			snapshot.SignatureChecks, snapshot.DSDigests)
	}
	if !snapshot.ConcurrentCryptoExhausted {
		t.Fatal("semaphore exhaustion missing from request-tree provenance")
	}
}

func TestDNSSECWorkBudgetDoesNotMisclassifyPreWaitCancellation(t *testing.T) {
	policy := middleware.RecursionWorkPolicy{
		Mode:                middleware.RecursionWorkEnforce,
		MaxSignatureChecks:  1,
		MaxDSDigests:        1,
		MaxConcurrentCrypto: 1,
	}
	ctx, ledger := middleware.EnsureRecursionWork(context.Background(), policy)
	r := &Resolver{cryptoLimiter: dnssec.NewCryptoLimiter(1)}

	release, err := r.dnssecWork(ctx).BeginSignature()
	if err != nil {
		t.Fatalf("first BeginSignature: %v", err)
	}
	// Cancellation appears at CryptoLimiter.Acquire's preflight, before that
	// limiter has observed contention.
	cancelled := newStagedCancellationContext(ctx, 1)
	nextRelease, err := r.dnssecWork(cancelled).BeginDSDigest()
	release()

	if !errors.Is(err, context.Canceled) || errors.Is(err, middleware.ErrRecursionWorkLimit) ||
		nextRelease != nil {
		t.Fatalf("pre-wait cancellation returned release=%t err=%v, want plain context cancellation",
			nextRelease != nil, err)
	}
	snapshot := ledger.Snapshot()
	if snapshot.ConcurrentCryptoExhausted {
		t.Fatal("pre-wait cancellation was misclassified as concurrent-crypto exhaustion")
	}
	if ledger.EnforcementError() != nil {
		t.Fatalf("pre-wait cancellation latched enforcement error: %v", ledger.EnforcementError())
	}
}
