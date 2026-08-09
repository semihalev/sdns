package dnssec

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

var errTestWorkLimit = errors.New("test DNSSEC work limit")

type countingNSEC3Work struct {
	limit uint32
	calls uint32
}

func (w *countingNSEC3Work) BeginNSEC3Hash() (func(), error) {
	if w.calls >= w.limit {
		return nil, errTestWorkLimit
	}
	w.calls++
	return func() {}, nil
}

func TestCryptoLimiterBoundsAndReleases(t *testing.T) {
	limiter := NewCryptoLimiter(2)
	if got := limiter.Capacity(); got != 2 {
		t.Fatalf("Capacity() = %d, want 2", got)
	}

	release1, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	release2, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := limiter.Acquire(cancelled); !errors.Is(err, context.Canceled) ||
		IsCryptoWaitError(err) || release != nil {
		t.Fatalf("saturated Acquire returned release=%t err=%v, want release=false and context.Canceled",
			release != nil, err)
	}

	release1()
	release3, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	release3()
	release2()

	unsaturated := NewCryptoLimiter(1)
	if release, err := unsaturated.Acquire(cancelled); !errors.Is(err, context.Canceled) ||
		IsCryptoWaitError(err) || release != nil {
		t.Fatalf("unsaturated cancelled Acquire returned release=%t err=%v, want context.Canceled",
			release != nil, err)
	}

	held, err := unsaturated.Acquire(context.Background())
	if err != nil {
		t.Fatalf("saturate limiter: %v", err)
	}
	if _, waitErr := unsaturated.acquireAfterPreflight(cancelled); !errors.Is(waitErr, context.Canceled) ||
		!IsCryptoWaitError(waitErr) {
		t.Fatalf("cancelled saturated wait error = %v, want marked crypto wait cancellation", waitErr)
	}
	held()

	immediate := NewCryptoLimiter(1)
	release, err := immediate.acquireAfterPreflight(cancelled)
	if err != nil || release == nil {
		t.Fatalf("free-slot admission after preflight = release:%t err:%v, want success", release != nil, err)
	}
	release()
}

func TestVerifyNameErrorNSEC3WorkBudgetExactBoundary(t *testing.T) {
	const (
		qname = "a.b.c.work-factor.example."
		limit = 5
	)
	msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
	records := newWorkFactorNSEC3ProofRecords(0, 4)
	work := &countingNSEC3Work{limit: limit}

	if err := VerifyNameErrorWithWork(msg, records, work); err != nil {
		t.Fatalf("VerifyNameErrorWithWork at exact boundary: %v", err)
	}
	if work.calls != limit {
		t.Fatalf("NSEC3 hashes = %d, want exact boundary %d", work.calls, limit)
	}
}

func TestVerifyNameErrorNSEC3WorkBudgetStopsBeforeNextHash(t *testing.T) {
	const limit = 5
	msg := new(dns.Msg).SetQuestion("x.a.b.c.work-factor.example.", dns.TypeA)
	records := newWorkFactorNSEC3ProofRecords(0, 4)
	work := &countingNSEC3Work{limit: limit}

	err := VerifyNameErrorWithWork(msg, records, work)
	if !IsWorkError(err) || !errors.Is(err, errTestWorkLimit) {
		t.Fatalf("VerifyNameErrorWithWork error = %v, want wrapped work limit", err)
	}
	if work.calls != limit {
		t.Fatalf("NSEC3 hashes = %d, want %d before rejection", work.calls, limit)
	}
}

func TestNSEC3CandidatesDeduplicateAndSortDeterministically(t *testing.T) {
	const qname = "a.b.c.work-factor.example."
	base := newWorkFactorNSEC3ProofRecords(0, 4)
	base[0].(*dns.NSEC3).TypeBitMap = []uint16{dns.TypeNS, dns.TypeA}
	semanticDuplicate := *base[0].(*dns.NSEC3)
	semanticDuplicate.Hdr.Ttl++
	semanticDuplicate.TypeBitMap = []uint16{dns.TypeA, dns.TypeNS}
	permuted := append([]dns.RR(nil), base...)
	slices.Reverse(permuted)
	permuted = append(permuted, permuted...)
	permuted = append(permuted, &semanticDuplicate)

	run := func(records []dns.RR) uint32 {
		t.Helper()
		msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
		work := &countingNSEC3Work{limit: 128}
		if err := VerifyNameErrorWithWork(msg, records, work); err != nil {
			t.Fatalf("VerifyNameErrorWithWork: %v", err)
		}
		return work.calls
	}

	want := run(base)
	if got := run(permuted); got != want {
		t.Fatalf("hash calls after permutation+semantic duplicates = %d, want %d", got, want)
	}
}

func TestNSEC3UnusableRecordsDebitNoWork(t *testing.T) {
	tests := []struct {
		name    string
		records []dns.RR
	}{
		{
			name:    "excessive iterations",
			records: newWorkFactorNSEC3ProofRecords(maxNSEC3Iterations+1, 4),
		},
		{
			name: "unsupported hash",
			records: func() []dns.RR {
				records := newWorkFactorNSEC3ProofRecords(0, 4)
				for _, rr := range records {
					rr.(*dns.NSEC3).Hash = 2
				}
				return records
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg).SetQuestion("a.work-factor.example.", dns.TypeA)
			work := &countingNSEC3Work{limit: 1}
			if err := VerifyNameErrorWithWork(msg, tt.records, work); err != ErrNSECMissingCoverage {
				t.Fatalf("VerifyNameErrorWithWork error = %v, want %v", err, ErrNSECMissingCoverage)
			}
			if work.calls != 0 {
				t.Fatalf("unusable NSEC3 records consumed %d hash debits, want 0", work.calls)
			}
		})
	}
}

func TestNSEC3WorkBudgetCoversAllProofPaths(t *testing.T) {
	tests := []struct {
		name string
		run  func(NSEC3Work) error
	}{
		{
			name: "nodata",
			run: func(work NSEC3Work) error {
				msg := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
				return VerifyNODATAWithWork(msg, []dns.RR{
					makeNSEC3("example.com.", "", false, nil),
				}, work)
			},
		},
		{
			name: "delegation",
			run: func(work NSEC3Work) error {
				return VerifyDelegationWithWork("a.b.com.", []dns.RR{
					makeNSEC3("a.b.com.", "", false, []uint16{dns.TypeNS}),
				}, work)
			},
		},
		{
			name: "wildcard",
			run: func(work NSEC3Work) error {
				const nextCloser = "secure.example.com."
				msg := new(dns.Msg)
				msg.Answer = []dns.RR{
					aRR(nextCloser),
					wildcardSig(nextCloser, 2),
				}
				msg.Ns = []dns.RR{makeNSEC3Coverer(t, nextCloser, "example.com.")}
				return VerifyWildcardAnswerWithWork(msg, work)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			work := &countingNSEC3Work{}
			err := tt.run(work)
			if !IsWorkError(err) || !errors.Is(err, errTestWorkLimit) {
				t.Fatalf("error = %v, want wrapped work-limit error", err)
			}
			if work.calls != 0 {
				t.Fatalf("hash calls = %d, want 0 before rejection", work.calls)
			}
		})
	}
}
