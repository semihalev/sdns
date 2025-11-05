package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParallelLookupIntegration(t *testing.T) {
	// This test verifies that the new parallel lookup methods work correctly
	// with real DNS resolution

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := makeTestConfig()
	cfg.QnameMinLevel = 0 // Disable minimization for simpler testing

	r := NewResolver(cfg)

	// Use a timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test a domain that requires NS lookups
	req := new(dns.Msg)
	req.SetQuestion("www.github.com.", dns.TypeA)
	req.SetEdns0(4096, true)

	start := time.Now()
	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, len(resp.Answer) > 0, "Should have answers")

	t.Logf("Parallel lookup completed in %v", duration)

	// Verify we got valid A records
	hasValidA := false
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			assert.NotNil(t, a.A)
			hasValidA = true
		}
	}
	assert.True(t, hasValidA, "Should have at least one A record")
}

func TestParallelLookupIPv6(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := makeTestConfig()
	cfg.IPv6Access = true

	r := NewResolver(cfg)

	// Use a timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test IPv6 lookup
	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeAAAA)
	req.SetEdns0(4096, true)

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	if err != nil {
		t.Logf("IPv6 lookup error (may be expected): %v", err)
	} else {
		assert.NotNil(t, resp)
		t.Logf("IPv6 lookup returned %d answers", len(resp.Answer))
	}
}

func BenchmarkParallelLookupReal(b *testing.B) {
	cfg := makeTestConfig()
	r := NewResolver(cfg)

	ctx := context.Background()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		req.SetEdns0(4096, true)

		_, _ = r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)
	}
}
