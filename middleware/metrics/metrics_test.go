package metrics

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func Test_Metrics(t *testing.T) {
	middleware.Register("metrics", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(&config.Config{})

	m := middleware.Get("metrics").(*Metrics)

	if !reflect.DeepEqual("metrics", m.Name()) {
		t.Errorf("m.Name() = %v, want %v", m.Name(), "metrics")
	}

	ch := middleware.NewChain([]middleware.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	ch.Reset(mw, req)

	m.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(dns.RcodeServerFailure, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeServerFailure)
	}

	_ = ch.Writer.WriteMsg(req)
	if !reflect.DeepEqual(true, ch.Writer.Written()) {
		t.Errorf("ch.Writer.Written() = %v, want %v", ch.Writer.Written(), true)
	}

	m.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(dns.RcodeSuccess, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeSuccess)
	}
}

func Test_DomainMetrics(t *testing.T) {
	// Test with domain metrics enabled
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 3,
	}

	m := New(cfg)
	if m.domainQueries == nil {
		t.Fatalf("m.domainQueries is nil")
	}
	if !(m.domainMetricsEnabled) {
		t.Errorf("m.domainMetricsEnabled is false")
	}
	if !reflect.DeepEqual(3, m.domainMetricsLimit) {
		t.Errorf("m.domainMetricsLimit = %v, want %v", m.domainMetricsLimit, 3)
	}

	ch := middleware.NewChain([]middleware.Handler{})

	// Test multiple domains
	domains := []string{"test1.com.", "test2.com.", "test3.com.", "test4.com."}

	for _, domain := range domains {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// Check that only 3 domains are tracked due to limit
	if !reflect.DeepEqual(int32(3), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(3))
	}
}

func Test_DomainMetrics_Disabled(t *testing.T) {
	// Test with domain metrics disabled
	cfg := &config.Config{
		DomainMetrics: false,
	}

	m := New(cfg)
	if m.domainQueries != nil {
		t.Errorf("m.domainQueries = %v, want nil", m.domainQueries)
	}
	if m.domainMetricsEnabled {
		t.Errorf("m.domainMetricsEnabled is true")
	}

	ch := middleware.NewChain([]middleware.Handler{})
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	ch.Reset(mw, req)

	_ = ch.Writer.WriteMsg(req)
	m.ServeDNS(context.Background(), ch)

	// No domains should be tracked
	if !reflect.DeepEqual(int32(0), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(0))
	}
}

func Test_DomainMetrics_Unlimited(t *testing.T) {
	// Test with unlimited domain metrics
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 0, // unlimited
	}

	m := New(cfg)
	if m.domainQueries == nil {
		t.Fatalf("m.domainQueries is nil")
	}
	if !reflect.DeepEqual(0, m.domainMetricsLimit) {
		t.Errorf("m.domainMetricsLimit = %v, want %v", m.domainMetricsLimit, 0)
	}

	ch := middleware.NewChain([]middleware.Handler{})

	// Test many domains
	for i := 0; i < 10; i++ {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("test%d.com.", i), dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// All domains should be tracked (unlimited)
	if !reflect.DeepEqual(int32(10), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(10))
	}
}

func Test_DomainMetrics_TopDomains(t *testing.T) {
	// Test that we keep top domains and remove low-count ones
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 5,
	}

	m := New(cfg)
	// Set last cleanup to past to allow immediate cleanup
	m.lastCleanup = time.Now().Add(-10 * time.Minute)

	ch := middleware.NewChain([]middleware.Handler{})

	// Create domains with different query counts
	domains := []struct {
		name  string
		count int
	}{
		{"popular1.com.", 100},
		{"popular2.com.", 80},
		{"popular3.com.", 60},
		{"popular4.com.", 40},
		{"popular5.com.", 20},
		{"unpopular.com.", 1},
	}

	// Query each domain the specified number of times
	for _, d := range domains {
		for i := 0; i < d.count; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(d.name, dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Should have tracked first 5 domains
	if !reflect.DeepEqual(int32(5), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(5))
	}

	// The unpopular domain should have triggered cleanup but still not be tracked
	_, exists := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("unpopular.com.", ".")))
	if exists {
		t.Errorf("exists is true")
	}
}

func Test_DomainMetrics_EvictionAfterCleanup(t *testing.T) {
	// Test that the system maintains the configured limit
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 3,
	}

	m := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{})

	// Fill up to limit with domains
	for i := 1; i <= 3; i++ {
		for j := 0; j < 10*i; j++ { // Different query counts
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(fmt.Sprintf("domain%d.com.", i), dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Should have 3 domains
	if !reflect.DeepEqual(int32(3), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(3))
	}

	// Try to add a new domain when at limit - it should not be tracked
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("newdomain.com.", dns.TypeA)
	ch.Reset(mw, req)
	_ = ch.Writer.WriteMsg(req)
	m.ServeDNS(context.Background(), ch)

	// Should still have 3 domains (limit enforced)
	if !reflect.DeepEqual(int32(3), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(3))
	}

	// The new domain should not be tracked
	_, exists := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("newdomain.com.", ".")))
	if exists {
		t.Errorf("%s: exists is true", "newdomain.com should not be tracked when at limit")
	}

	// Original domains should still be tracked
	for i := 1; i <= 3; i++ {
		domain := fmt.Sprintf("domain%d.com", i)
		_, exists := m.domainTracker.Load(strings.ToLower(domain))
		if !(exists) {
			t.Errorf("%s: exists is false", fmt.Sprintf("%s should still be tracked", domain))
		}
	}
}

func Test_DomainMetrics_CleanupKeepsTopDomains(t *testing.T) {
	// Test that cleanup keeps top domains when going over limit
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 3,
	}

	m := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{})

	// Add domains up to limit - 1
	domains := []struct {
		name  string
		count int
	}{
		{"domain1.com.", 10},
		{"domain2.com.", 20},
	}

	for _, d := range domains {
		for i := 0; i < d.count; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(d.name, dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Should have 2 domains
	if !reflect.DeepEqual(int32(2), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(2))
	}

	// Add two more domains to go over limit
	newDomains := []struct {
		name  string
		count int
	}{
		{"domain3.com.", 30},
		{"domain4.com.", 5}, // This one has fewer queries
	}

	for _, d := range newDomains {
		for i := 0; i < d.count; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(d.name, dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Force cleanup
	m.lastCleanup = time.Now().Add(-10 * time.Minute)
	m.maybeCleanupDomains()

	// Should be back to limit
	if int(atomic.LoadInt32(&m.domainCount)) > 3 {
		t.Errorf("int(atomic.LoadInt32(&m.domainCount)) = %v, want <= %v", int(atomic.LoadInt32(&m.domainCount)), 3)
	}

	// Top 3 domains should be tracked (domain3, domain2, domain1)
	_, exists := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain3.com.", ".")))
	if !(exists) {
		t.Errorf("%s: exists is false", "domain3.com (30 queries) should be tracked")
	}

	_, exists = m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain2.com.", ".")))
	if !(exists) {
		t.Errorf("%s: exists is false", "domain2.com (20 queries) should be tracked")
	}

	_, exists = m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain1.com.", ".")))
	if !(exists) {
		t.Errorf("%s: exists is false", "domain1.com (10 queries) should be tracked")
	}

	// Lowest count domain should be evicted
	_, exists = m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain4.com.", ".")))
	if exists {
		t.Errorf("%s: exists is true", "domain4.com (5 queries) should have been evicted")
	}
}

func Test_DomainMetrics_SingleLabelFiltering(t *testing.T) {
	// Test that single-label domains are filtered out
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 10,
	}

	m := New(cfg)
	ch := middleware.NewChain([]middleware.Handler{})

	// Test various single-label domains that should be ignored
	singleLabelDomains := []string{
		"com.",
		"localhost.",
		"local.",
		"test.",
		"arpa.",
	}

	for _, domain := range singleLabelDomains {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// No single-label domains should be tracked
	if !reflect.DeepEqual(int32(0), atomic.LoadInt32(&m.domainCount)) {
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), int32(0))
	}

	// Test multi-label domains that should be tracked
	multiLabelDomains := []string{
		"example.com.",
		"subdomain.example.com.",
		"deep.subdomain.example.com.",
		"test.local.",
	}

	for _, domain := range multiLabelDomains {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// All multi-label domains should be tracked
	if want := int32(len(multiLabelDomains)); atomic.LoadInt32(&m.domainCount) != want { //nolint:gosec // G115 - test value
		t.Errorf("atomic.LoadInt32(&m.domainCount) = %v, want %v", atomic.LoadInt32(&m.domainCount), want)
	}

	// Verify each multi-label domain is tracked
	for _, domain := range multiLabelDomains {
		normalized := strings.ToLower(strings.TrimSuffix(domain, "."))
		_, exists := m.domainTracker.Load(normalized)
		if !(exists) {
			t.Errorf("%s: exists is false", fmt.Sprintf("%s should be tracked", domain))
		}
	}
}
