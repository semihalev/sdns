package middleware

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
)

func defaultRecursionWorkPolicyForTest(mode RecursionWorkMode) RecursionWorkPolicy {
	return RecursionWorkPolicy{
		Mode:                    mode,
		MaxOutboundQueries:      config.DefaultRecursionFirewallMaxOutboundQueries,
		MaxInternalQueries:      config.DefaultRecursionFirewallMaxInternalQueries,
		MaxDNSKEYCandidates:     config.DefaultRecursionFirewallMaxDNSKEYCandidates,
		MaxRRsetSignatureChecks: config.DefaultRecursionFirewallMaxRRsetSignatureChecks,
		MaxSignatureChecks:      config.DefaultRecursionFirewallMaxSignatureChecks,
		MaxDSDigests:            config.DefaultRecursionFirewallMaxDSDigests,
		MaxNSEC3Hashes:          config.DefaultRecursionFirewallMaxNSEC3Hashes,
		MaxConcurrentCrypto:     config.DefaultRecursionFirewallMaxConcurrentCrypto,
	}
}

func TestMustRecursionWorkPolicyFromConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.RecursionFirewallConfig
		want RecursionWorkPolicy
	}{
		{
			name: "omitted defaults to shadow",
			want: defaultRecursionWorkPolicyForTest(RecursionWorkShadow),
		},
		{
			name: "off with custom limits",
			cfg: config.RecursionFirewallConfig{
				Mode:                    config.RecursionFirewallModeOff,
				MaxOutboundQueries:      9,
				MaxInternalQueries:      7,
				MaxDNSKEYCandidates:     3,
				MaxRRsetSignatureChecks: 5,
				MaxSignatureChecks:      11,
				MaxDSDigests:            13,
				MaxNSEC3Hashes:          17,
				MaxConcurrentCrypto:     19,
			},
			want: RecursionWorkPolicy{
				Mode:                    RecursionWorkOff,
				MaxOutboundQueries:      9,
				MaxInternalQueries:      7,
				MaxDNSKEYCandidates:     3,
				MaxRRsetSignatureChecks: 5,
				MaxSignatureChecks:      11,
				MaxDSDigests:            13,
				MaxNSEC3Hashes:          17,
				MaxConcurrentCrypto:     19,
			},
		},
		{
			name: "enforce with custom limits",
			cfg: config.RecursionFirewallConfig{
				Mode:                    config.RecursionFirewallModeEnforce,
				MaxOutboundQueries:      96,
				MaxInternalQueries:      24,
				MaxDNSKEYCandidates:     4,
				MaxRRsetSignatureChecks: 8,
				MaxSignatureChecks:      32,
				MaxDSDigests:            31,
				MaxNSEC3Hashes:          30,
				MaxConcurrentCrypto:     29,
			},
			want: RecursionWorkPolicy{
				Mode:                    RecursionWorkEnforce,
				MaxOutboundQueries:      96,
				MaxInternalQueries:      24,
				MaxDNSKEYCandidates:     4,
				MaxRRsetSignatureChecks: 8,
				MaxSignatureChecks:      32,
				MaxDSDigests:            31,
				MaxNSEC3Hashes:          30,
				MaxConcurrentCrypto:     29,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MustRecursionWorkPolicyFromConfig(tt.cfg); got != tt.want {
				t.Fatalf("policy = %+v, want %+v", got, tt.want)
			}
		})
	}

	t.Run("invalid mode panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("invalid programmatic mode did not panic")
			}
		}()
		MustRecursionWorkPolicyFromConfig(config.RecursionFirewallConfig{
			Mode: "blocking",
		})
	})
}

func TestRecursionWorkLedgerShadowRecordsLimitCrossings(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 2,
		MaxInternalQueries: 1,
	})

	for range 4 {
		if err := ledger.Debit(RecursionWorkOutboundQuery); err != nil {
			t.Fatalf("shadow outbound debit returned error: %v", err)
		}
	}
	for range 3 {
		if err := ledger.Debit(RecursionWorkInternalQuery); err != nil {
			t.Fatalf("shadow internal debit returned error: %v", err)
		}
	}

	got := ledger.Snapshot()
	if got.Mode != RecursionWorkShadow {
		t.Fatalf("mode = %v, want shadow", got.Mode)
	}
	if got.OutboundQueries != 4 || got.InternalQueries != 3 {
		t.Fatalf("counts = outbound:%d internal:%d, want outbound:4 internal:3",
			got.OutboundQueries, got.InternalQueries)
	}
	if !got.OutboundExhausted || !got.InternalExhausted {
		t.Fatalf("exhausted = outbound:%v internal:%v, want both true",
			got.OutboundExhausted, got.InternalExhausted)
	}
	if got.MaxOutboundQueries != 2 || got.MaxInternalQueries != 1 {
		t.Fatalf("limits = outbound:%d internal:%d, want outbound:2 internal:1",
			got.MaxOutboundQueries, got.MaxInternalQueries)
	}
	if err := ledger.EnforcementError(); err != nil {
		t.Fatalf("shadow EnforcementError = %v, want nil", err)
	}
}

func TestRecursionWorkLedgerShadowRecordsDNSSECCrossings(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:                    RecursionWorkShadow,
		MaxDNSKEYCandidates:     2,
		MaxRRsetSignatureChecks: 3,
		MaxSignatureChecks:      2,
		MaxDSDigests:            2,
		MaxNSEC3Hashes:          2,
		MaxConcurrentCrypto:     7,
	})

	for _, kind := range []RecursionWorkKind{
		RecursionWorkSignature,
		RecursionWorkDSDigest,
		RecursionWorkNSEC3Hash,
	} {
		for range 4 {
			if err := ledger.Debit(kind); err != nil {
				t.Fatalf("shadow debit for kind %v returned error: %v", kind, err)
			}
		}
	}
	if err := ledger.CheckLocal(RecursionWorkDNSKEYCandidate, 2); err != nil {
		t.Fatalf("shadow DNSKEY candidate crossing returned error: %v", err)
	}
	if err := ledger.CheckLocal(RecursionWorkRRsetSignature, 3); err != nil {
		t.Fatalf("shadow RRset signature crossing returned error: %v", err)
	}
	if err := ledger.Reject(RecursionWorkConcurrentCrypto); err != nil {
		t.Fatalf("shadow concurrent-crypto rejection returned error: %v", err)
	}

	got := ledger.Snapshot()
	if got.SignatureChecks != 4 || got.DSDigests != 4 || got.NSEC3Hashes != 4 {
		t.Fatalf("DNSSEC counts = signatures:%d DS:%d NSEC3:%d, want 4 each",
			got.SignatureChecks, got.DSDigests, got.NSEC3Hashes)
	}
	if !got.DNSKEYCandidatesExhausted ||
		!got.RRsetSignatureChecksExhausted ||
		!got.SignatureChecksExhausted ||
		!got.DSDigestsExhausted ||
		!got.NSEC3HashesExhausted ||
		!got.ConcurrentCryptoExhausted {
		t.Fatalf("DNSSEC crossing snapshot = %+v, want every DNSSEC dimension exhausted", got)
	}
	if got.MaxDNSKEYCandidates != 2 ||
		got.MaxRRsetSignatureChecks != 3 ||
		got.MaxSignatureChecks != 2 ||
		got.MaxDSDigests != 2 ||
		got.MaxNSEC3Hashes != 2 ||
		got.MaxConcurrentCrypto != 7 {
		t.Fatalf("DNSSEC limits snapshot = %+v, want configured values", got)
	}
	if err := ledger.EnforcementError(); err != nil {
		t.Fatalf("shadow EnforcementError = %v, want nil", err)
	}
}

func TestRecursionWorkLedgerLocalLimits(t *testing.T) {
	tests := []struct {
		name string
		kind RecursionWorkKind
	}{
		{name: "DNSKEY candidates", kind: RecursionWorkDNSKEYCandidate},
		{name: "RRset signatures", kind: RecursionWorkRRsetSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []RecursionWorkMode{RecursionWorkShadow, RecursionWorkEnforce} {
				t.Run(map[RecursionWorkMode]string{
					RecursionWorkShadow:  "shadow",
					RecursionWorkEnforce: "enforce",
				}[mode], func(t *testing.T) {
					ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
						Mode:                    mode,
						MaxDNSKEYCandidates:     2,
						MaxRRsetSignatureChecks: 2,
					})

					for used := uint32(0); used < 2; used++ {
						if err := ledger.CheckLocal(tt.kind, used); err != nil {
							t.Fatalf("CheckLocal(%d) = %v, want nil", used, err)
						}
					}
					err := ledger.CheckLocal(tt.kind, 2)
					if mode == RecursionWorkShadow {
						if err != nil {
							t.Fatalf("shadow crossing = %v, want nil", err)
						}
						if enforceErr := ledger.EnforcementError(); enforceErr != nil {
							t.Fatalf("shadow EnforcementError = %v, want nil", enforceErr)
						}
					} else {
						var limitErr *RecursionWorkLimitError
						if !errors.As(err, &limitErr) {
							t.Fatalf("enforce crossing type = %T, want *RecursionWorkLimitError", err)
						}
						if limitErr.Kind != tt.kind || limitErr.Limit != 2 {
							t.Fatalf("enforce crossing = {Kind:%v Limit:%d}, want {Kind:%v Limit:2}",
								limitErr.Kind, limitErr.Limit, tt.kind)
						}
						if enforceErr := ledger.EnforcementError(); !errors.Is(enforceErr, ErrRecursionWorkLimit) {
							t.Fatalf("EnforcementError = %v, want ErrRecursionWorkLimit", enforceErr)
						}
					}

					snapshot := ledger.Snapshot()
					exhausted := snapshot.DNSKEYCandidatesExhausted
					if tt.kind == RecursionWorkRRsetSignature {
						exhausted = snapshot.RRsetSignatureChecksExhausted
					}
					if !exhausted {
						t.Fatalf("local kind %v did not record exhaustion: %+v", tt.kind, snapshot)
					}
				})
			}
		})
	}
}

func TestRecursionWorkLedgerLocalLimitConcurrentCrossing(t *testing.T) {
	const attempts = 256

	for _, kind := range []RecursionWorkKind{
		RecursionWorkDNSKEYCandidate,
		RecursionWorkRRsetSignature,
	} {
		t.Run(fmt.Sprintf("kind=%d", kind), func(t *testing.T) {
			ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
				Mode:                    RecursionWorkEnforce,
				MaxDNSKEYCandidates:     1,
				MaxRRsetSignatureChecks: 1,
			})

			start := make(chan struct{})
			results := make([]error, attempts)
			var wg sync.WaitGroup
			wg.Add(attempts)
			for i := range attempts {
				go func() {
					defer wg.Done()
					<-start
					results[i] = ledger.CheckLocal(kind, 1)
				}()
			}
			close(start)
			wg.Wait()

			for _, err := range results {
				var limitErr *RecursionWorkLimitError
				if !errors.As(err, &limitErr) {
					t.Fatalf("concurrent local crossing type = %T, want *RecursionWorkLimitError", err)
				}
				if limitErr.Kind != kind || limitErr.Limit != 1 {
					t.Fatalf("concurrent local crossing = {Kind:%v Limit:%d}, want {Kind:%v Limit:1}",
						limitErr.Kind, limitErr.Limit, kind)
				}
			}

			var firstErr *RecursionWorkLimitError
			if !errors.As(ledger.EnforcementError(), &firstErr) {
				t.Fatal("concurrent local crossing did not latch an enforcement error")
			}
			if firstErr.Kind != kind || firstErr.Limit != 1 {
				t.Fatalf("latched local crossing = {Kind:%v Limit:%d}, want {Kind:%v Limit:1}",
					firstErr.Kind, firstErr.Limit, kind)
			}
		})
	}
}

func TestRecursionWorkLedgerEnforceConcurrentExactCap(t *testing.T) {
	const (
		limit    = uint32(37)
		attempts = 256
	)

	tests := []struct {
		name string
		kind RecursionWorkKind
	}{
		{name: "outbound", kind: RecursionWorkOutboundQuery},
		{name: "internal", kind: RecursionWorkInternalQuery},
		{name: "signature", kind: RecursionWorkSignature},
		{name: "DS digest", kind: RecursionWorkDSDigest},
		{name: "NSEC3 hash", kind: RecursionWorkNSEC3Hash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
				Mode:               RecursionWorkEnforce,
				MaxOutboundQueries: limit,
				MaxInternalQueries: limit,
				MaxSignatureChecks: limit,
				MaxDSDigests:       limit,
				MaxNSEC3Hashes:     limit,
			})

			start := make(chan struct{})
			results := make([]error, attempts)
			var wg sync.WaitGroup
			wg.Add(attempts)
			for i := range attempts {
				go func() {
					defer wg.Done()
					<-start
					results[i] = ledger.Debit(tt.kind)
				}()
			}
			close(start)
			wg.Wait()

			var accepted, rejected uint32
			for _, err := range results {
				if err == nil {
					accepted++
					continue
				}
				rejected++
				if !errors.Is(err, ErrRecursionWorkLimit) {
					t.Errorf("rejection %v does not wrap ErrRecursionWorkLimit", err)
				}
				var limitErr *RecursionWorkLimitError
				if !errors.As(err, &limitErr) {
					t.Errorf("rejection type = %T, want *RecursionWorkLimitError", err)
					continue
				}
				if limitErr.Kind != tt.kind || limitErr.Limit != limit {
					t.Errorf("rejection = {Kind:%v Limit:%d}, want {Kind:%v Limit:%d}",
						limitErr.Kind, limitErr.Limit, tt.kind, limit)
				}
			}

			if accepted != limit {
				t.Fatalf("accepted = %d, want exact cap %d", accepted, limit)
			}
			if rejected != attempts-limit {
				t.Fatalf("rejected = %d, want %d", rejected, attempts-limit)
			}

			snapshot := ledger.Snapshot()
			count, exhausted := aggregateSnapshotForKind(snapshot, tt.kind)
			if count != limit || !exhausted {
				t.Fatalf("snapshot for kind %v = count:%d exhausted:%v, want count:%d exhausted:true",
					tt.kind, count, exhausted, limit)
			}

			var firstErr *RecursionWorkLimitError
			if !errors.As(ledger.EnforcementError(), &firstErr) {
				t.Fatal("EnforcementError did not return a RecursionWorkLimitError")
			}
			if firstErr.Kind != tt.kind || firstErr.Limit != limit {
				t.Fatalf("EnforcementError = {Kind:%v Limit:%d}, want {Kind:%v Limit:%d}",
					firstErr.Kind, firstErr.Limit, tt.kind, limit)
			}
		})
	}
}

func aggregateSnapshotForKind(snapshot RecursionWorkSnapshot, kind RecursionWorkKind) (uint32, bool) {
	switch kind {
	case RecursionWorkOutboundQuery:
		return snapshot.OutboundQueries, snapshot.OutboundExhausted
	case RecursionWorkInternalQuery:
		return snapshot.InternalQueries, snapshot.InternalExhausted
	case RecursionWorkSignature:
		return snapshot.SignatureChecks, snapshot.SignatureChecksExhausted
	case RecursionWorkDSDigest:
		return snapshot.DSDigests, snapshot.DSDigestsExhausted
	case RecursionWorkNSEC3Hash:
		return snapshot.NSEC3Hashes, snapshot.NSEC3HashesExhausted
	default:
		return 0, false
	}
}

func TestRecursionWorkLedgerBestEffortRejectionDoesNotLatch(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 2,
		MaxInternalQueries: 1,
	})

	if err := ledger.DebitBestEffort(RecursionWorkInternalQuery); err != nil {
		t.Fatalf("accepted best-effort debit: %v", err)
	}
	err := ledger.DebitBestEffort(RecursionWorkInternalQuery)
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("rejected best-effort debit = %v, want recursion work limit", err)
	}
	if err := ledger.EnforcementError(); err != nil {
		t.Fatalf("best-effort rejection latched terminal provenance: %v", err)
	}

	snapshot := ledger.Snapshot()
	if snapshot.InternalQueries != 1 || !snapshot.InternalExhausted {
		t.Fatalf("best-effort snapshot = %+v, want internal=1 exhausted=true", snapshot)
	}

	if err := ledger.Debit(RecursionWorkOutboundQuery); err != nil {
		t.Fatalf("required work was poisoned by optional rejection: %v", err)
	}
	if got := ledger.Snapshot().OutboundQueries; got != 1 {
		t.Fatalf("required outbound work = %d, want 1", got)
	}

	// A later required rejection must still become terminal even when the
	// same dimension was first exhausted by best-effort work.
	if err := ledger.Debit(RecursionWorkInternalQuery); !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("required rejection = %v, want recursion work limit", err)
	}
	var limitErr *RecursionWorkLimitError
	if !errors.As(ledger.EnforcementError(), &limitErr) {
		t.Fatal("required rejection did not latch terminal provenance")
	}
	if limitErr.Kind != RecursionWorkInternalQuery {
		t.Fatalf("latched kind = %v, want internal", limitErr.Kind)
	}
}

func TestRecursionWorkFinishWaitsForRetainedAsyncWork(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 8,
		MaxInternalQueries: 8,
	})
	release, ok := ledger.Retain()
	if !ok || release == nil {
		t.Fatal("Retain failed for an active ledger")
	}

	ledger.finish()
	if ledger.finished.Load() {
		t.Fatal("ledger published before retained work completed")
	}
	if err := ledger.Debit(RecursionWorkOutboundQuery); err != nil {
		t.Fatalf("retained-work debit: %v", err)
	}

	release()
	release() // release is deliberately once-safe
	if !ledger.finished.Load() {
		t.Fatal("ledger did not publish after retained work completed")
	}
	if got := ledger.Snapshot().OutboundQueries; got != 1 {
		t.Fatalf("published outbound work = %d, want 1", got)
	}
	if nextRelease, retained := ledger.Retain(); retained || nextRelease != nil {
		t.Fatal("Retain succeeded after final publication")
	}
}

func TestRecursionWorkLimitErrorCarriesSentinelAndPolicyEDE(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 1,
		MaxInternalQueries: 1,
	})
	if err := ledger.Debit(RecursionWorkInternalQuery); err != nil {
		t.Fatalf("first debit: %v", err)
	}

	err := ledger.Debit(RecursionWorkInternalQuery)
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("error %v does not wrap ErrRecursionWorkLimit", err)
	}
	if err.Error() != RecursionWorkEDEText {
		t.Fatalf("error text = %q, want %q", err.Error(), RecursionWorkEDEText)
	}

	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkInternalQuery || limitErr.Limit != 1 {
		t.Fatalf("limit error = {Kind:%v Limit:%d}, want internal limit 1",
			limitErr.Kind, limitErr.Limit)
	}
	if got := limitErr.EDECode(); got != RecursionWorkEDECode {
		t.Fatalf("EDECode = %d, want Other (%d)",
			got, RecursionWorkEDECode)
	}

	code, text := dnsutil.ErrorToEDE(err)
	if code != RecursionWorkEDECode {
		t.Fatalf("ErrorToEDE code = %d, want Other (%d)",
			code, RecursionWorkEDECode)
	}
	if text != RecursionWorkEDEText {
		t.Fatalf("ErrorToEDE text = %q, want %q", text, RecursionWorkEDEText)
	}
}

func TestRecursionWorkDNSSECLimitErrorCarriesIndeterminateEDE(t *testing.T) {
	for _, kind := range []RecursionWorkKind{
		RecursionWorkDNSKEYCandidate,
		RecursionWorkRRsetSignature,
		RecursionWorkSignature,
		RecursionWorkDSDigest,
		RecursionWorkNSEC3Hash,
		RecursionWorkConcurrentCrypto,
	} {
		t.Run(fmt.Sprintf("kind=%d", kind), func(t *testing.T) {
			err := &RecursionWorkLimitError{Kind: kind, Limit: 1}
			if !errors.Is(err, ErrRecursionWorkLimit) {
				t.Fatalf("error %v does not wrap ErrRecursionWorkLimit", err)
			}
			if err.Error() != DNSSECWorkEDEText {
				t.Fatalf("error text = %q, want %q", err.Error(), DNSSECWorkEDEText)
			}
			if got := err.EDECode(); got != DNSSECWorkEDECode {
				t.Fatalf("EDECode = %d, want DNSSEC Indeterminate (%d)",
					got, DNSSECWorkEDECode)
			}

			code, text := dnsutil.ErrorToEDE(err)
			if code != DNSSECWorkEDECode || text != DNSSECWorkEDEText {
				t.Fatalf("ErrorToEDE = (%d, %q), want (%d, %q)",
					code, text, DNSSECWorkEDECode, DNSSECWorkEDEText)
			}
		})
	}
}

func TestRecursionWorkEDEReturnsLatchedKindOrGenericFallback(t *testing.T) {
	t.Run("generic fallback", func(t *testing.T) {
		code, text := RecursionWorkEDE(context.Background())
		if code != RecursionWorkEDECode || text != RecursionWorkEDEText {
			t.Fatalf("fallback EDE = (%d, %q), want (%d, %q)",
				code, text, RecursionWorkEDECode, RecursionWorkEDEText)
		}
	})

	tests := []struct {
		name     string
		kind     RecursionWorkKind
		policy   RecursionWorkPolicy
		wantCode uint16
		wantText string
	}{
		{
			name: "network",
			kind: RecursionWorkOutboundQuery,
			policy: RecursionWorkPolicy{
				Mode:               RecursionWorkEnforce,
				MaxOutboundQueries: 0,
			},
			wantCode: RecursionWorkEDECode,
			wantText: RecursionWorkEDEText,
		},
		{
			name: "DNSSEC",
			kind: RecursionWorkSignature,
			policy: RecursionWorkPolicy{
				Mode:               RecursionWorkEnforce,
				MaxSignatureChecks: 0,
			},
			wantCode: DNSSECWorkEDECode,
			wantText: DNSSECWorkEDEText,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger := NewRecursionWorkLedger(tt.policy)
			ctx := WithRecursionWork(context.Background(), ledger)
			if err := ledger.Debit(tt.kind); !errors.Is(err, ErrRecursionWorkLimit) {
				t.Fatalf("crossing = %v, want ErrRecursionWorkLimit", err)
			}
			code, text := RecursionWorkEDE(ctx)
			if code != tt.wantCode || text != tt.wantText {
				t.Fatalf("latched EDE = (%d, %q), want (%d, %q)",
					code, text, tt.wantCode, tt.wantText)
			}
		})
	}
}

func TestRecursionWorkErrorEDEPrefersDirectTypedError(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 0,
	})
	ctx := WithRecursionWork(context.Background(), ledger)
	if err := ledger.Debit(RecursionWorkOutboundQuery); !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("network crossing = %v, want recursion work limit", err)
	}

	directErr := fmt.Errorf("exchange failed: %w", &RecursionWorkLimitError{
		Kind:  RecursionWorkSignature,
		Limit: 32,
	})
	code, text := RecursionWorkErrorEDE(ctx, directErr)
	if code != DNSSECWorkEDECode || text != DNSSECWorkEDEText {
		t.Fatalf("direct typed error EDE = (%d, %q), want (%d, %q)",
			code, text, DNSSECWorkEDECode, DNSSECWorkEDEText)
	}

	code, text = RecursionWorkErrorEDE(ctx, errors.New("untyped exchange failure"))
	if code != RecursionWorkEDECode || text != RecursionWorkEDEText {
		t.Fatalf("context fallback EDE = (%d, %q), want (%d, %q)",
			code, text, RecursionWorkEDECode, RecursionWorkEDEText)
	}
}

func TestCheckRecursionWorkLocalLimitUsesContextLedger(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:                    RecursionWorkEnforce,
		MaxDNSKEYCandidates:     1,
		MaxRRsetSignatureChecks: 1,
	}
	ledger := NewRecursionWorkLedger(policy)
	ctx := WithRecursionWork(context.Background(), ledger)

	if err := CheckRecursionWorkLocalLimit(ctx, RecursionWorkDNSKEYCandidate, 0); err != nil {
		t.Fatalf("first local check: %v", err)
	}
	err := CheckRecursionWorkLocalLimit(ctx, RecursionWorkDNSKEYCandidate, 1)
	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("crossing type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkDNSKEYCandidate || limitErr.Limit != 1 {
		t.Fatalf("crossing = {Kind:%v Limit:%d}, want DNSKEY candidate limit 1",
			limitErr.Kind, limitErr.Limit)
	}
}

func TestRejectRecursionWorkLatchesConcurrentCryptoExhaustion(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:                RecursionWorkEnforce,
		MaxConcurrentCrypto: 3,
	}
	ledger := NewRecursionWorkLedger(policy)
	ctx := WithRecursionWork(context.Background(), ledger)

	err := RejectRecursionWork(ctx, RecursionWorkConcurrentCrypto)
	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("rejection type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkConcurrentCrypto || limitErr.Limit != 3 {
		t.Fatalf("rejection = {Kind:%v Limit:%d}, want concurrent crypto limit 3",
			limitErr.Kind, limitErr.Limit)
	}
	if limitErr.EDECode() != DNSSECWorkEDECode {
		t.Fatalf("EDE code = %d, want DNSSEC Indeterminate", limitErr.EDECode())
	}
	if !ledger.Snapshot().ConcurrentCryptoExhausted {
		t.Fatal("concurrent crypto exhaustion missing from snapshot")
	}
	if !errors.Is(ledger.EnforcementError(), ErrRecursionWorkLimit) {
		t.Fatal("concurrent crypto rejection did not latch enforcement provenance")
	}
}

func TestRecursionWorkFinishPublishesAggregateDNSSECWork(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxSignatureChecks: 8,
		MaxDSDigests:       8,
		MaxNSEC3Hashes:     8,
	})

	signatureCounter := dnssecWorkTotal.WithLabelValues("signature_checks", "shadow")
	dsCounter := dnssecWorkTotal.WithLabelValues("ds_digests", "shadow")
	nsec3Counter := dnssecWorkTotal.WithLabelValues("nsec3_hashes", "shadow")
	beforeSignatures := signatureCounter.Value()
	beforeDS := dsCounter.Value()
	beforeNSEC3 := nsec3Counter.Value()
	signatureHistogram := dnssecWorkPerRequest.WithLabelValues("signature_checks", "shadow")
	dsHistogram := dnssecWorkPerRequest.WithLabelValues("ds_digests", "shadow")
	nsec3Histogram := dnssecWorkPerRequest.WithLabelValues("nsec3_hashes", "shadow")
	beforeSignatureCount, beforeSignatureSum := histogramCountAndSum(t, signatureHistogram)
	beforeDSCount, beforeDSSum := histogramCountAndSum(t, dsHistogram)
	beforeNSEC3Count, beforeNSEC3Sum := histogramCountAndSum(t, nsec3Histogram)

	for range 2 {
		if err := ledger.Debit(RecursionWorkSignature); err != nil {
			t.Fatalf("signature debit: %v", err)
		}
	}
	for range 3 {
		if err := ledger.Debit(RecursionWorkDSDigest); err != nil {
			t.Fatalf("DS digest debit: %v", err)
		}
	}
	for range 4 {
		if err := ledger.Debit(RecursionWorkNSEC3Hash); err != nil {
			t.Fatalf("NSEC3 hash debit: %v", err)
		}
	}

	ledger.finish()
	if got := signatureCounter.Value() - beforeSignatures; got != 2 {
		t.Fatalf("published signature work = %d, want 2", got)
	}
	if got := dsCounter.Value() - beforeDS; got != 3 {
		t.Fatalf("published DS work = %d, want 3", got)
	}
	if got := nsec3Counter.Value() - beforeNSEC3; got != 4 {
		t.Fatalf("published NSEC3 work = %d, want 4", got)
	}
	assertHistogramDelta(t, signatureHistogram, beforeSignatureCount, beforeSignatureSum, 2)
	assertHistogramDelta(t, dsHistogram, beforeDSCount, beforeDSSum, 3)
	assertHistogramDelta(t, nsec3Histogram, beforeNSEC3Count, beforeNSEC3Sum, 4)

	ledger.finish()
	if got := signatureCounter.Value() - beforeSignatures; got != 2 {
		t.Fatalf("second finish republished signature work: delta=%d", got)
	}
	assertHistogramDelta(t, signatureHistogram, beforeSignatureCount, beforeSignatureSum, 2)
}

func histogramCountAndSum(t *testing.T, observer prometheus.Observer) (uint64, float64) {
	t.Helper()
	m, ok := observer.(prometheus.Metric)
	if !ok {
		t.Fatalf("histogram observer type = %T, want prometheus.Metric", observer)
	}
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}
	histogram := out.GetHistogram()
	if histogram == nil {
		t.Fatal("metric did not contain a histogram")
	}
	return histogram.GetSampleCount(), histogram.GetSampleSum()
}

func assertHistogramDelta(
	t *testing.T,
	observer prometheus.Observer,
	beforeCount uint64,
	beforeSum float64,
	want float64,
) {
	t.Helper()
	count, sum := histogramCountAndSum(t, observer)
	if count-beforeCount != 1 || sum-beforeSum != want {
		t.Fatalf("histogram delta = count:%d sum:%g, want count:1 sum:%g",
			count-beforeCount, sum-beforeSum, want)
	}
}

func TestChainRootAndNestedShareRecursionWorkLedger(t *testing.T) {
	rootPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 9,
		MaxInternalQueries: 7,
	}
	nestedPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 1,
		MaxInternalQueries: 1,
	}

	var (
		rootLedger   *RecursionWorkLedger
		nestedLedger *RecursionWorkLedger
		rootMeta     *ResponseMeta
		nestedMeta   *ResponseMeta
	)

	nested := newChain([]Handler{HandlerFunc(func(ctx context.Context, _ *Chain) {
		nestedLedger = RecursionWorkFrom(ctx)
		nestedMeta = ResponseMetaFrom(ctx)
		if err := DebitRecursionWork(ctx, RecursionWorkOutboundQuery); err != nil {
			t.Fatalf("nested outbound debit: %v", err)
		}
	})}, nestedPolicy)

	root := newChain([]Handler{HandlerFunc(func(ctx context.Context, _ *Chain) {
		rootLedger = RecursionWorkFrom(ctx)
		rootMeta = ResponseMetaFrom(ctx)

		nested.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
		nested.Next(ctx)
	})}, rootPolicy)

	root.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	root.Next(context.Background())

	if rootLedger == nil || nestedLedger == nil {
		t.Fatalf("ledgers = root:%p nested:%p, want both non-nil", rootLedger, nestedLedger)
	}
	if nestedLedger != rootLedger {
		t.Fatalf("nested ledger %p != root ledger %p", nestedLedger, rootLedger)
	}
	if rootMeta != &root.Meta || nestedMeta != rootMeta {
		t.Fatalf("metadata pointers = root:%p nested:%p root backing:%p",
			rootMeta, nestedMeta, &root.Meta)
	}
	if got := nested.Meta.RecursionWork(); got != nil {
		t.Fatalf("nested chain installed its own ledger %p, want inherited root ledger only", got)
	}

	snapshot := rootLedger.Snapshot()
	if snapshot.Mode != RecursionWorkEnforce ||
		snapshot.MaxOutboundQueries != rootPolicy.MaxOutboundQueries ||
		snapshot.MaxInternalQueries != rootPolicy.MaxInternalQueries {
		t.Fatalf("nested policy replaced first policy: snapshot = %+v", snapshot)
	}
	if snapshot.OutboundQueries != 1 {
		t.Fatalf("shared outbound count = %d, want 1", snapshot.OutboundQueries)
	}
	if !rootLedger.finished.Load() {
		t.Fatal("outer Chain did not publish the request-tree completion")
	}
}

func TestLazyChainMaterializesWorkOnFirstUseWithOuterPolicy(t *testing.T) {
	rootPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 9,
		MaxInternalQueries: 7,
	}
	nestedPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 1,
		MaxInternalQueries: 1,
	}

	var (
		before    *RecursionWorkLedger
		ledger    *RecursionWorkLedger
		pinnedCtx context.Context
	)
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		before = RecursionWorkFrom(ctx)
		pinnedCtx, ledger = EnsureRecursionWork(ctx, nestedPolicy)
		if err := DebitRecursionWork(pinnedCtx, RecursionWorkOutboundQuery); err != nil {
			t.Fatalf("outbound debit: %v", err)
		}
		ch.Cancel()
	})}, rootPolicy)
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

	ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()
	ch.Next(ctx)

	if before != nil {
		t.Fatalf("ledger materialized before first use: %p", before)
	}
	if ledger == nil {
		t.Fatal("first work use did not materialize a ledger")
	}
	snapshot := ledger.Snapshot()
	if snapshot.Mode != rootPolicy.Mode ||
		snapshot.MaxOutboundQueries != rootPolicy.MaxOutboundQueries ||
		snapshot.MaxInternalQueries != rootPolicy.MaxInternalQueries ||
		snapshot.OutboundQueries != 1 {
		t.Fatalf("lazy ledger snapshot = %+v, want outer policy and one debit", snapshot)
	}
	if !ledger.finished.Load() {
		t.Fatal("outer Chain did not finish the lazily created ledger")
	}

	ch.Meta.Reset()
	if got := RecursionWorkFrom(pinnedCtx); got != ledger {
		t.Fatalf("pinned context resolved ledger %p after pooled meta reset, want %p", got, ledger)
	}
}

func TestLazyChainSkipsLedgerWhenNoRecursiveWorkRuns(t *testing.T) {
	policy := defaultRecursionWorkPolicyForTest(RecursionWorkShadow)
	var got *RecursionWorkLedger
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		got = RecursionWorkFrom(ctx)
		ch.Cancel()
	})}, policy)
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

	ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()
	ch.Next(ctx)

	if got != nil || ch.Meta.RecursionWork() != nil {
		t.Fatalf("no-work request materialized ledger handler=%p meta=%p", got, ch.Meta.RecursionWork())
	}
}

func TestLazyChainNoWorkContextCannotDebitReusedMetaLedger(t *testing.T) {
	policy := defaultRecursionWorkPolicyForTest(RecursionWorkShadow)
	var contexts []context.Context
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		contexts = append(contexts, ctx)
		if len(contexts) == 2 {
			if err := DebitRecursionWork(ctx, RecursionWorkOutboundQuery); err != nil {
				t.Fatalf("second-request debit: %v", err)
			}
		}
		ch.Cancel()
	})}, policy)

	first := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer first.Cancel()
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	ch.Next(first)
	if got := RecursionWorkFrom(contexts[0]); got != nil {
		t.Fatalf("completed no-work request resolved ledger %p", got)
	}

	second := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer second.Cancel()
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	ch.Next(second)
	secondLedger := RecursionWorkFrom(contexts[1])
	if secondLedger == nil {
		t.Fatal("second request did not materialize its ledger")
	}
	before := secondLedger.Snapshot()

	if got := RecursionWorkFrom(contexts[0]); got != nil {
		t.Fatalf("old context observed reused ledger %p", got)
	}
	_, closedWork := EnsureRecursionWork(contexts[0], policy)
	if closedWork == nil {
		t.Fatal("late ensure returned nil instead of a closed work guard")
	}
	if err := closedWork.EnforcementError(); !errors.Is(err, context.Canceled) {
		t.Fatalf("late ensure error = %v, want context.Canceled", err)
	}
	if err := DebitRecursionWork(contexts[0], RecursionWorkOutboundQuery); !errors.Is(err, context.Canceled) {
		t.Fatalf("late old-context debit = %v, want context.Canceled", err)
	}
	after := secondLedger.Snapshot()
	if after.OutboundQueries != before.OutboundQueries {
		t.Fatalf("old context changed new ledger outbound count from %d to %d",
			before.OutboundQueries, after.OutboundQueries)
	}
	if ch.Meta.RecursionWork() != secondLedger {
		t.Fatalf("pooled meta ledger = %p, want second request ledger %p",
			ch.Meta.RecursionWork(), secondLedger)
	}
}

func TestLazyChainDisabledEnsureUsesEnabledOuterPolicy(t *testing.T) {
	outerPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 7,
		MaxInternalQueries: 5,
	}
	var ledger *RecursionWorkLedger
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		var returned context.Context
		returned, ledger = EnsureRecursionWork(ctx, RecursionWorkPolicy{})
		if returned != ctx {
			t.Fatal("lazy outer ledger added an unnecessary context wrapper")
		}
		ch.Cancel()
	})}, outerPolicy)
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

	ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()
	ch.Next(ctx)

	if ledger == nil {
		t.Fatal("disabled nested policy bypassed the enabled outer policy")
	}
	snapshot := ledger.Snapshot()
	if snapshot.Mode != outerPolicy.Mode ||
		snapshot.MaxOutboundQueries != outerPolicy.MaxOutboundQueries ||
		snapshot.MaxInternalQueries != outerPolicy.MaxInternalQueries {
		t.Fatalf("ledger policy = %+v, want outer policy %+v", snapshot, outerPolicy)
	}
	if !ledger.finished.Load() {
		t.Fatal("outer Chain did not finish the ledger")
	}
}

func TestLazyChainConcurrentFirstDebitsShareOneLedger(t *testing.T) {
	policy := defaultRecursionWorkPolicyForTest(RecursionWorkShadow)
	const workers = 16
	var ledger *RecursionWorkLedger
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- DebitRecursionWork(ctx, RecursionWorkOutboundQuery)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("concurrent debit: %v", err)
			}
		}
		ledger = RecursionWorkFrom(ctx)
		ch.Cancel()
	})}, policy)
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

	ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()
	ch.Next(ctx)

	if ledger == nil {
		t.Fatal("concurrent first debits did not establish a ledger")
	}
	if got := ledger.Snapshot().OutboundQueries; got != workers {
		t.Fatalf("outbound debits = %d, want %d", got, workers)
	}
	if !ledger.finished.Load() {
		t.Fatal("outer Chain did not finish the shared ledger")
	}
}

func TestLazyChainCompletionRacesFirstDebitWithoutLeakingLedger(t *testing.T) {
	policy := defaultRecursionWorkPolicyForTest(RecursionWorkShadow)
	const iterations = 250

	for range iterations {
		var (
			captured context.Context
			debitErr error
			done     = make(chan struct{})
		)
		ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
			captured = ctx
			start := make(chan struct{})
			go func() {
				<-start
				debitErr = DebitRecursionWork(ctx, RecursionWorkOutboundQuery)
				close(done)
			}()
			close(start)
			ch.Cancel()
		})}, policy)
		ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

		ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
		ch.Next(ctx)
		<-done

		ledger := RecursionWorkFrom(captured)
		if ledger == nil {
			if !errors.Is(debitErr, context.Canceled) {
				t.Fatalf("closed racing debit = %v, want context.Canceled", debitErr)
			}
			if leaked := ch.Meta.RecursionWork(); leaked != nil {
				t.Fatalf("closed request leaked unpinned ledger %p into pooled metadata", leaked)
			}
		} else {
			if debitErr != nil {
				t.Fatalf("accepted racing debit: %v", debitErr)
			}
			if !ledger.finished.Load() {
				t.Fatalf("racing request ledger %p was not finished", ledger)
			}
			if got := ledger.Snapshot().OutboundQueries; got != 1 {
				t.Fatalf("racing request outbound count = %d, want 1", got)
			}
		}
		ctx.Cancel()
	}
}

func TestLazyChainCompletionRacesFirstEnsureWithoutLeakingLedger(t *testing.T) {
	policy := defaultRecursionWorkPolicyForTest(RecursionWorkShadow)
	const iterations = 250

	for range iterations {
		var (
			captured context.Context
			returned context.Context
			ledger   *RecursionWorkLedger
			done     = make(chan struct{})
		)
		ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
			captured = ctx
			start := make(chan struct{})
			go func() {
				<-start
				returned, ledger = EnsureRecursionWork(ctx, policy)
				close(done)
			}()
			close(start)
			ch.Cancel()
		})}, policy)
		ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

		ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
		ch.Next(ctx)
		<-done

		if returned != captured {
			t.Fatal("lazy ensure added an unnecessary context wrapper")
		}
		switch ledger {
		case nil:
			t.Fatal("racing ensure returned no ledger")
		case recursionWorkClosed:
			if active := RecursionWorkFrom(captured); active != nil {
				t.Fatalf("closed request exposed ledger %p", active)
			}
			if leaked := ch.Meta.RecursionWork(); leaked != nil {
				t.Fatalf("closed request leaked unpinned ledger %p into pooled metadata", leaked)
			}
			if !errors.Is(ledger.EnforcementError(), context.Canceled) {
				t.Fatalf("closed ledger error = %v, want context.Canceled", ledger.EnforcementError())
			}
		default:
			if active := RecursionWorkFrom(captured); active != ledger {
				t.Fatalf("active racing ledger = %p, want %p", active, ledger)
			}
			if !ledger.finished.Load() {
				t.Fatalf("racing request ledger %p was not finished", ledger)
			}
		}
		ctx.Cancel()
	}
}

func TestRecursionWorkControlLedgersAreImmutable(t *testing.T) {
	const workers = 64
	tests := []struct {
		name    string
		ledger  *RecursionWorkLedger
		state   recursionWorkLedgerState
		wantErr error
	}{
		{name: "pending", ledger: recursionWorkPending, state: recursionWorkLedgerPending},
		{name: "closed", ledger: recursionWorkClosed, state: recursionWorkLedgerClosed, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := make(chan error, workers)
			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for _, err := range []error{
						tc.ledger.Debit(RecursionWorkOutboundQuery),
						tc.ledger.DebitBestEffort(RecursionWorkInternalQuery),
						tc.ledger.CheckLocal(RecursionWorkDNSKEYCandidate, 0),
						tc.ledger.Reject(RecursionWorkConcurrentCrypto),
						tc.ledger.EnforcementError(),
					} {
						if !errors.Is(err, tc.wantErr) {
							errs <- fmt.Errorf("control ledger error = %v, want %v", err, tc.wantErr)
							return
						}
					}
					if release, ok := tc.ledger.Retain(); ok || release != nil {
						errs <- errors.New("control ledger Retain succeeded; want nil, false")
						return
					}
					tc.ledger.finish()
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}

			if got := tc.ledger.Snapshot(); got != (RecursionWorkSnapshot{}) {
				t.Fatalf("control ledger snapshot mutated: %+v", got)
			}
			if tc.ledger.lifecycleState() != tc.state ||
				tc.ledger.refs.Load() != 0 ||
				tc.ledger.finished.Load() {
				t.Fatal("control ledger lifecycle state mutated")
			}
		})
	}
}

func TestLazyOuterChainOwnsQueryerLedgerUntilReturn(t *testing.T) {
	policy := defaultRecursionWorkPolicyForTest(RecursionWorkShadow)
	subHandler := HandlerFunc(func(_ context.Context, ch *Chain) {
		reply := new(dns.Msg)
		reply.SetReply(ch.Request)
		_ = ch.Writer.WriteMsg(reply)
		ch.Cancel()
	})
	sub := newPipeline(
		[]Handler{subHandler},
		map[string]Handler{subHandler.Name(): subHandler},
		[]string{subHandler.Name()},
		policy,
	)
	queryer := NewPipelineQueryer(sub)

	var ledger *RecursionWorkLedger
	outer := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		if _, err := queryer.Query(ctx, recursionWorkTestRequest()); err != nil {
			t.Fatalf("Query: %v", err)
		}
		ledger = RecursionWorkFrom(ctx)
		if ledger == nil {
			t.Fatal("Query did not materialize the outer ledger")
		}
		if ledger.lifecycleState() == recursionWorkLedgerRootDone {
			t.Fatal("nested Query finished the outer ledger")
		}
		ch.Cancel()
	})}, policy)
	outer.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

	ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()
	outer.Next(ctx)

	if ledger == nil || !ledger.finished.Load() {
		t.Fatalf("ledger completion after outer return = ledger:%p finished:%v",
			ledger, ledger != nil && ledger.finished.Load())
	}
	if got := ledger.Snapshot().InternalQueries; got != 1 {
		t.Fatalf("internal query count = %d, want 1", got)
	}
}

func TestChainResetKeepsPinnedLedgerIsolatedFromReuse(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 8,
		MaxInternalQueries: 8,
	}

	var contexts []context.Context
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, _ *Chain) {
		contexts = append(contexts, ctx)
	})}, policy)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	ch.Next(context.Background())
	if len(contexts) != 1 {
		t.Fatalf("first request captured %d contexts, want 1", len(contexts))
	}
	oldCtx := contexts[0]
	oldLedger := RecursionWorkFrom(oldCtx)
	if oldLedger == nil {
		t.Fatal("first request did not establish a ledger")
	}

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	ch.Next(context.Background())
	if len(contexts) != 2 {
		t.Fatalf("second request captured %d contexts total, want 2", len(contexts))
	}
	newCtx := contexts[1]
	newLedger := RecursionWorkFrom(newCtx)
	if newLedger == nil {
		t.Fatal("second request did not establish a ledger")
	}
	if newLedger == oldLedger {
		t.Fatalf("pooled Chain reused old ledger %p for the next request", oldLedger)
	}

	if got := RecursionWorkFrom(oldCtx); got != oldLedger {
		t.Fatalf("old pinned context resolved ledger %p after Reset, want %p", got, oldLedger)
	}
	if got := ResponseMetaFrom(oldCtx).RecursionWork(); got != newLedger {
		t.Fatalf("pooled ResponseMeta now points to %p, want new ledger %p", got, newLedger)
	}

	if err := DebitRecursionWork(oldCtx, RecursionWorkOutboundQuery); err != nil {
		t.Fatalf("old-context debit: %v", err)
	}
	if err := DebitRecursionWork(newCtx, RecursionWorkInternalQuery); err != nil {
		t.Fatalf("new-context debit: %v", err)
	}

	oldSnapshot := oldLedger.Snapshot()
	if oldSnapshot.OutboundQueries != 1 || oldSnapshot.InternalQueries != 0 {
		t.Fatalf("old ledger counts = outbound:%d internal:%d, want outbound:1 internal:0",
			oldSnapshot.OutboundQueries, oldSnapshot.InternalQueries)
	}
	newSnapshot := newLedger.Snapshot()
	if newSnapshot.OutboundQueries != 0 || newSnapshot.InternalQueries != 1 {
		t.Fatalf("new ledger counts = outbound:%d internal:%d, want outbound:0 internal:1",
			newSnapshot.OutboundQueries, newSnapshot.InternalQueries)
	}
}

func TestPipelineQueryerDebitsInternalWorkAndRejectsAtCap(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 4,
		MaxInternalQueries: 1,
	}

	calls := 0
	handler := HandlerFunc(func(_ context.Context, ch *Chain) {
		calls++
		reply := new(dns.Msg)
		reply.SetReply(ch.Request)
		_ = ch.Writer.WriteMsg(reply)
	})
	pipe := newPipeline(
		[]Handler{handler},
		map[string]Handler{handler.Name(): handler},
		[]string{handler.Name()},
		policy,
	)
	queryer := NewPipelineQueryer(pipe)
	ctx, ledger := EnsureRecursionWork(context.Background(), policy)
	req := recursionWorkTestRequest()

	resp, err := queryer.Query(ctx, req)
	if err != nil {
		t.Fatalf("first Query: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first Query response = %#v, want successful DNS message", resp)
	}
	if calls != 1 {
		t.Fatalf("handler calls after first Query = %d, want 1", calls)
	}
	if got := ledger.Snapshot().InternalQueries; got != 1 {
		t.Fatalf("internal count after first Query = %d, want 1", got)
	}

	resp, err = queryer.Query(ctx, req)
	if resp != nil {
		t.Fatalf("rejected Query response = %#v, want nil", resp)
	}
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("rejected Query error = %v, want ErrRecursionWorkLimit", err)
	}
	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("rejected Query error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkInternalQuery || limitErr.Limit != 1 {
		t.Fatalf("rejected Query error = {Kind:%v Limit:%d}, want internal limit 1",
			limitErr.Kind, limitErr.Limit)
	}
	if calls != 1 {
		t.Fatalf("handler calls after rejected Query = %d, want 1", calls)
	}
	snapshot := ledger.Snapshot()
	if snapshot.InternalQueries != 1 || !snapshot.InternalExhausted {
		t.Fatalf("internal snapshot after rejection = count:%d exhausted:%v, want count:1 exhausted:true",
			snapshot.InternalQueries, snapshot.InternalExhausted)
	}
}

func TestPipelineQueryerPropagatesEnforcementAfterSubPipeline(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 0,
		MaxInternalQueries: 2,
	}

	calls := 0
	handler := HandlerFunc(func(ctx context.Context, ch *Chain) {
		calls++
		_ = DebitRecursionWork(ctx, RecursionWorkOutboundQuery)
		reply := new(dns.Msg)
		reply.SetReply(ch.Request)
		_ = ch.Writer.WriteMsg(reply)
	})
	pipe := newPipeline(
		[]Handler{handler},
		map[string]Handler{handler.Name(): handler},
		[]string{handler.Name()},
		policy,
	)
	queryer := NewPipelineQueryer(pipe)
	ctx, ledger := EnsureRecursionWork(context.Background(), policy)

	resp, err := queryer.Query(ctx, recursionWorkTestRequest())
	if resp != nil {
		t.Fatalf("response = %#v, want nil when sub-pipeline exhausts enforcement", resp)
	}
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("Query error = %v, want ErrRecursionWorkLimit", err)
	}
	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("Query error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkOutboundQuery || limitErr.Limit != 0 {
		t.Fatalf("Query error = {Kind:%v Limit:%d}, want outbound limit 0",
			limitErr.Kind, limitErr.Limit)
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	snapshot := ledger.Snapshot()
	if snapshot.InternalQueries != 1 || snapshot.OutboundQueries != 0 || !snapshot.OutboundExhausted {
		t.Fatalf("snapshot = %+v, want one internal debit and rejected outbound debit", snapshot)
	}
}

func recursionWorkTestRequest() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	return req
}
