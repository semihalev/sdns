package reflex

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIPTracker_Basic(t *testing.T) {
	tracker := NewIPTracker(100)

	// First few queries should have zero score
	score := tracker.RecordQuery("192.168.1.1", dns.TypeA, 1.0, 50)
	if !reflect.DeepEqual(0.0, score) {
		t.Errorf("%s: score = %v, want %v", "first query should have zero score", score, 0.0)
	}

	if !reflect.DeepEqual(1, tracker.Count()) {
		t.Errorf("tracker.Count() = %v, want %v", tracker.Count(), 1)
	}
}

func TestIPTracker_NormalQueries(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.1"

	// Normal A queries at moderate rate should have low score
	for i := 0; i < 20; i++ {
		tracker.RecordQuery(ip, dns.TypeA, 1.0, 50)
	}

	entry := tracker.GetEntry(ip)
	if entry == nil {
		t.Fatalf("entry is nil")
	}
	if !(entry.HasNormalQ) {
		t.Errorf("entry.HasNormalQ is false")
	}

	score := tracker.calculateScore(entry)
	if score >= 0.5 {
		t.Errorf("%s: score = %v, want < %v", "normal queries should have low score", score, 0.5)
	}
	t.Logf("Normal traffic score: %.2f", score)
}

func TestIPTracker_HighAmpQueries(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.2"

	// Only DNSKEY queries (high amplification)
	for i := 0; i < 20; i++ {
		tracker.RecordQuery(ip, dns.TypeDNSKEY, 20.0, 50)
	}

	entry := tracker.GetEntry(ip)
	if entry == nil {
		t.Fatalf("entry is nil")
	}
	if entry.HasNormalQ {
		t.Errorf("entry.HasNormalQ is true")
	}
	if !reflect.DeepEqual(uint32(20), entry.HighAmpQueries) {
		t.Errorf("entry.HighAmpQueries = %v, want %v", entry.HighAmpQueries, uint32(20))
	}

	score := tracker.calculateScore(entry)
	// Score is 0.45: high-amp ratio (0.25) + no normal queries (0.15) + single type (0.05)
	// This is below blocking threshold (0.7) which is correct -
	// need HIGH RATE to block, not just high-amp types
	if score <= 0.3 {
		t.Errorf("%s: score = %v, want > %v", "high-amp only queries should have elevated score", score, 0.3)
	}
	t.Logf("High-amp traffic score: %.2f", score)
}

func TestIPTracker_TCPClearsScore(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.3"

	// Build up suspicious score
	for i := 0; i < 20; i++ {
		tracker.RecordQuery(ip, dns.TypeDNSKEY, 20.0, 50)
	}

	entry := tracker.GetEntry(ip)
	scoreBefore := tracker.calculateScore(entry)

	// TCP connection proves real IP
	tracker.RecordTCP(ip)

	entry = tracker.GetEntry(ip)
	scoreAfter := tracker.calculateScore(entry)

	if scoreBefore <= 0.3 {
		t.Errorf("%s: scoreBefore = %v, want > %v", "should have elevated score before TCP", scoreBefore, 0.3)
	}
	if !reflect.DeepEqual(0.0, scoreAfter) {
		t.Errorf("%s: scoreAfter = %v, want %v", "TCP should clear score", scoreAfter, 0.0)
	}
}

func TestIPTracker_RecordResponse(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.4"

	tracker.RecordQuery(ip, dns.TypeDNSKEY, 20.0, 50)
	tracker.RecordResponse(ip, 50, 500) // 10x amplification

	entry := tracker.GetEntry(ip)
	if !reflect.DeepEqual(uint64(50), entry.TotalRequestBytes) {
		t.Errorf("entry.TotalRequestBytes = %v, want %v", entry.TotalRequestBytes, uint64(50))
	}
	if !reflect.DeepEqual(uint64(500), entry.TotalResponseBytes) {
		t.Errorf("entry.TotalResponseBytes = %v, want %v", entry.TotalResponseBytes, uint64(500))
	}
}

func TestIPTracker_AmplificationRatio(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.5"

	// Queries with high actual amplification
	for i := 0; i < 20; i++ {
		tracker.RecordQuery(ip, dns.TypeTXT, 10.0, 50)
		tracker.RecordResponse(ip, 50, 1000) // 20x amplification
	}

	entry := tracker.GetEntry(ip)
	score := tracker.calculateScore(entry)

	t.Logf("High amplification ratio score: %.2f", score)
	if score <= 0.4 {
		t.Errorf("%s: score = %v, want > %v", "high amplification should increase score", score, 0.4)
	}
}

func TestIPTracker_BoundedMemory(t *testing.T) {
	maxSize := 10
	tracker := NewIPTracker(maxSize)

	// Add more than max
	for i := 0; i < 20; i++ {
		ip := "192.168.1." + string(rune('0'+i%10)) + string(rune('0'+i/10))
		tracker.RecordQuery(ip, dns.TypeA, 1.0, 50)
	}

	if tracker.Count() > maxSize {
		t.Errorf("tracker.Count() = %v, want <= %v", tracker.Count(), maxSize)
	}
}

func TestIPTracker_Cleanup(t *testing.T) {
	tracker := NewIPTracker(100)

	// Add entries
	tracker.RecordQuery("192.168.1.1", dns.TypeA, 1.0, 50)
	tracker.RecordQuery("192.168.1.2", dns.TypeA, 1.0, 50)
	tracker.RecordQuery("192.168.1.3", dns.TypeA, 1.0, 50)

	if !reflect.DeepEqual(3, tracker.Count()) {
		t.Errorf("tracker.Count() = %v, want %v", tracker.Count(), 3)
	}

	// Age one entry
	tracker.mu.Lock()
	if e, ok := tracker.entries["192.168.1.1"]; ok {
		e.LastSeen = time.Now().Add(-20 * time.Minute)
	}
	tracker.mu.Unlock()

	tracker.Cleanup()
	if !reflect.DeepEqual(2, tracker.Count()) {
		t.Errorf("tracker.Count() = %v, want %v", tracker.Count(), 2)
	}
}

func TestIPTracker_QueryTypeDiversity(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.6"

	// Single query type (suspicious)
	for i := 0; i < 30; i++ {
		tracker.RecordQuery(ip, dns.TypeDNSKEY, 20.0, 50)
	}

	entry := tracker.GetEntry(ip)
	typeCount := popcount16(entry.QueryTypes)
	if !reflect.DeepEqual(1, typeCount) {
		t.Errorf("typeCount = %v, want %v", typeCount, 1)
	}

	score := tracker.calculateScore(entry)
	t.Logf("Single type score: %.2f", score)
}

func TestIPTracker_MixedTypes(t *testing.T) {
	tracker := NewIPTracker(100)
	ip := "192.168.1.7"

	// Mix of query types (less suspicious)
	types := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT}
	for i := 0; i < 30; i++ {
		qtype := types[i%len(types)] //nolint:gosec // safe index
		amp := getAmpFactor(qtype)
		tracker.RecordQuery(ip, qtype, amp, 50)
	}

	entry := tracker.GetEntry(ip)
	typeCount := popcount16(entry.QueryTypes)
	if typeCount < 3 {
		t.Errorf("typeCount = %v, want >= %v", typeCount, 3)
	}
	if !(entry.HasNormalQ) {
		t.Errorf("entry.HasNormalQ is false")
	}

	score := tracker.calculateScore(entry)
	t.Logf("Mixed types score: %.2f", score)
	if score >= 0.5 {
		t.Errorf("%s: score = %v, want < %v", "mixed types with normal queries should be less suspicious", score, 0.5)
	}
}

func TestPopcount16(t *testing.T) {
	if !reflect.DeepEqual(0, popcount16(0)) {
		t.Errorf("popcount16(0) = %v, want %v", popcount16(0), 0)
	}
	if !reflect.DeepEqual(1, popcount16(1)) {
		t.Errorf("popcount16(1) = %v, want %v", popcount16(1), 1)
	}
	if !reflect.DeepEqual(1, popcount16(2)) {
		t.Errorf("popcount16(2) = %v, want %v", popcount16(2), 1)
	}
	if !reflect.DeepEqual(2, popcount16(3)) {
		t.Errorf("popcount16(3) = %v, want %v", popcount16(3), 2)
	}
	if !reflect.DeepEqual(16, popcount16(0xFFFF)) {
		t.Errorf("popcount16(0xFFFF) = %v, want %v", popcount16(0xFFFF), 16)
	}
}

func TestQtypeToBit(t *testing.T) {
	// Test all mapped query types
	tests := []struct {
		qtype    uint16
		expected int
	}{
		{1, 0},    // A
		{2, 1},    // NS
		{5, 2},    // CNAME
		{6, 3},    // SOA
		{12, 4},   // PTR
		{15, 5},   // MX
		{16, 6},   // TXT
		{28, 7},   // AAAA
		{33, 8},   // SRV
		{43, 9},   // DS
		{46, 10},  // RRSIG
		{47, 11},  // NSEC
		{48, 12},  // DNSKEY
		{50, 13},  // NSEC3
		{52, 14},  // TLSA
		{255, 15}, // Unknown (ANY)
		{99, 15},  // Unknown type
	}

	for _, tt := range tests {
		if !reflect.DeepEqual(tt.expected, qtypeToBit(tt.qtype)) {
			t.Errorf("%s: qtypeToBit(tt.qtype) = %v, want %v", fmt.Sprintf("qtype %d", tt.qtype), qtypeToBit(tt.qtype), tt.expected)
		}
	}
}

func TestCalculateScore_EdgeCases(t *testing.T) {
	tracker := NewIPTracker(100)

	t.Run("very high rate with high amp", func(t *testing.T) {
		ip := "10.0.0.1"
		// Simulate high rate attack (>30 QPS)
		for i := 0; i < 100; i++ {
			tracker.RecordQuery(ip, dns.TypeDNSKEY, 20.0, 50)
			tracker.RecordResponse(ip, 50, 2500) // 50x amplification
		}

		entry := tracker.GetEntry(ip)
		score := tracker.calculateScore(entry)
		t.Logf("High rate attack score: %.2f", score)
		if score < 0.7 {
			t.Errorf("%s: score = %v, want >= %v", "high rate attack should have high score", score, 0.7)
		}
	})

	t.Run("moderate rate only high amp", func(t *testing.T) {
		tracker2 := NewIPTracker(100)
		ip := "10.0.0.2"
		// Simulate moderate rate with only high amp queries (>15 QPS)
		for i := 0; i < 50; i++ {
			tracker2.RecordQuery(ip, dns.TypeDNSKEY, 20.0, 50)
		}

		entry := tracker2.GetEntry(ip)
		score := tracker2.calculateScore(entry)
		t.Logf("Moderate rate high-amp score: %.2f", score)
	})

	t.Run("high volume response tracking", func(t *testing.T) {
		tracker3 := NewIPTracker(100)
		ip := "10.0.0.3"
		// High volume with moderate amplification
		for i := 0; i < 100; i++ {
			tracker3.RecordQuery(ip, dns.TypeTXT, 10.0, 50)
			tracker3.RecordResponse(ip, 50, 1500) // 30x amp, >100KB total
		}

		entry := tracker3.GetEntry(ip)
		score := tracker3.calculateScore(entry)
		t.Logf("High volume moderate amp score: %.2f", score)
	})
}

func BenchmarkIPTracker_RecordQuery(b *testing.B) {
	tracker := NewIPTracker(100_000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tracker.RecordQuery("192.168.1.100", dns.TypeA, 1.0, 50)
	}
}

func BenchmarkIPTracker_RecordQueryNewIP(b *testing.B) {
	tracker := NewIPTracker(100_000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ip := "192.168." + string(rune(i/256%256)) + "." + string(rune(i%256))
		tracker.RecordQuery(ip, dns.TypeA, 1.0, 50)
	}
}

func BenchmarkIPTracker_CalculateScore(b *testing.B) {
	tracker := NewIPTracker(100)

	// Create entry with data
	for i := 0; i < 50; i++ {
		tracker.RecordQuery("192.168.1.1", dns.TypeDNSKEY, 20.0, 50)
		tracker.RecordResponse("192.168.1.1", 50, 500)
	}

	entry := tracker.GetEntry("192.168.1.1")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tracker.calculateScore(entry)
	}
}
