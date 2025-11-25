package reflex

import (
	"sync"
	"time"
)

// IPTracker tracks IP behavior for amplification attack detection.
type IPTracker struct {
	mu      sync.RWMutex
	entries map[string]*IPEntry
	maxSize int
}

// IPEntry tracks statistics for a single IP.
type IPEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time

	// Query statistics
	TotalQueries   uint32
	HighAmpQueries uint32  // Queries for high-amplification types
	TotalAmpFactor float64 // Sum of amplification factors

	// Response statistics
	TotalRequestBytes  uint64
	TotalResponseBytes uint64

	// Reputation signals
	HasTCP      bool // Has made TCP connection (proves real IP)
	HasNormalQ  bool // Has made normal queries (A, AAAA)
	QueryTypes  uint16 // Bitmap of query types seen (first 16 types)
}

// NewIPTracker creates a new tracker.
func NewIPTracker(maxSize int) *IPTracker {
	return &IPTracker{
		entries: make(map[string]*IPEntry),
		maxSize: maxSize,
	}
}

// RecordQuery records a UDP query and returns suspicion score (0.0-1.0).
func (t *IPTracker) RecordQuery(ip string, qtype uint16, ampFactor float64, reqSize int) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.entries[ip]
	if !exists {
		// Evict random entry if at capacity
		if len(t.entries) >= t.maxSize {
			t.evictOne()
		}
		entry = &IPEntry{
			FirstSeen: time.Now(),
		}
		t.entries[ip] = entry
	}

	entry.LastSeen = time.Now()
	entry.TotalQueries++
	entry.TotalAmpFactor += ampFactor
	entry.TotalRequestBytes += uint64(reqSize) //nolint:gosec // reqSize is always positive

	// Track query type in bitmap
	// Map common types to bitmap positions
	bitPos := qtypeToBit(qtype)
	if bitPos < 16 {
		entry.QueryTypes |= 1 << bitPos
	}

	// Track if high-amp query
	if ampFactor > 3.0 {
		entry.HighAmpQueries++
	}

	// Track normal queries (A=1, AAAA=28)
	if qtype == 1 || qtype == 28 {
		entry.HasNormalQ = true
	}

	return t.calculateScore(entry)
}

// RecordResponse records response size for amplification ratio tracking.
func (t *IPTracker) RecordResponse(ip string, reqSize, respSize int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, ok := t.entries[ip]; ok {
		entry.TotalResponseBytes += uint64(respSize) //nolint:gosec // respSize is always positive
	}
}

// RecordTCP records that IP made a TCP connection (proves real IP).
func (t *IPTracker) RecordTCP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, ok := t.entries[ip]; ok {
		entry.HasTCP = true
	}
}

// calculateScore returns suspicion score (0.0-1.0).
// Higher score = more likely to be amplification attack source.
//
// Key insight: Amplification attacks have specific patterns:
// 1. Very high query RATE (not just high-amp types)
// 2. Single target domain repeated
// 3. No legitimate behavior signals (TCP, normal queries, query diversity)
//
// We want to avoid false positives on:
// - DNSSEC validators (high-amp types but low rate, diverse domains)
// - Email servers (TXT/MX queries but established behavior)
// - Monitoring systems (repeated queries but low volume)
func (t *IPTracker) calculateScore(e *IPEntry) float64 {
	// TCP connection proves real IP - not spoofed
	if e.HasTCP {
		return 0.0
	}

	// Need significant query volume to judge
	// Low volume is never suspicious (attackers need volume for amplification)
	if e.TotalQueries < 10 {
		return 0.0
	}

	score := 0.0

	// Calculate query rate (queries per second since first seen)
	duration := e.LastSeen.Sub(e.FirstSeen).Seconds()
	if duration < 1.0 {
		duration = 1.0
	}
	queryRate := float64(e.TotalQueries) / duration

	// Factor 1: Query rate - attacks need HIGH volume (0-0.35)
	// Normal resolver: 1-10 QPS, Attack: 50+ QPS from single "IP"
	switch {
	case queryRate > 30:
		score += 0.35
	case queryRate > 15:
		score += 0.20
	case queryRate > 5:
		score += 0.10
	}
	// Low rate = likely legitimate, even with high-amp types

	// Factor 2: High-amp ratio ONLY matters with high rate (0-0.25)
	// DNSSEC validator has high ratio but low rate - OK
	// Attack has high ratio AND high rate - BAD
	highAmpRatio := float64(e.HighAmpQueries) / float64(e.TotalQueries)
	if highAmpRatio > 0.8 && queryRate > 10 {
		score += 0.25
	} else if highAmpRatio > 0.5 && queryRate > 15 {
		score += 0.15
	}

	// Factor 3: No normal queries + high volume (0-0.15)
	// Legitimate clients usually mix A/AAAA with other types
	if !e.HasNormalQ && e.TotalQueries > 30 && queryRate > 5 {
		score += 0.15
	}

	// Factor 4: Actual amplification achieved (0-0.15)
	// This is the strongest signal - actual bytes amplified
	if e.TotalRequestBytes > 0 && e.TotalResponseBytes > 0 {
		actualAmp := float64(e.TotalResponseBytes) / float64(e.TotalRequestBytes)
		// Only suspicious if high amp AND high volume
		if actualAmp > 10.0 && e.TotalResponseBytes > 50000 {
			score += 0.15
		} else if actualAmp > 5.0 && e.TotalResponseBytes > 100000 {
			score += 0.10
		}
	}

	// Factor 5: Single query type at high volume (0-0.10)
	// Attackers often hammer single type, legitimate users vary
	typeCount := popcount16(e.QueryTypes)
	if typeCount == 1 && e.TotalQueries > 50 {
		score += 0.10
	}

	// Negative factors (reduce suspicion)

	// Query type diversity suggests legitimate behavior
	if typeCount >= 4 {
		score -= 0.15
	} else if typeCount >= 2 {
		score -= 0.05
	}

	// Has normal queries - legitimate signal
	if e.HasNormalQ {
		score -= 0.10
	}

	// Long-lived IP with moderate rate - probably real
	if duration > 60 && queryRate < 5 {
		score -= 0.10
	}

	// Clamp to 0.0-1.0
	if score < 0 {
		score = 0
	}
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// evictOne removes the oldest entry (called with lock held).
func (t *IPTracker) evictOne() {
	var oldestIP string
	var oldestTime time.Time

	for ip, e := range t.entries {
		if oldestIP == "" || e.LastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = e.LastSeen
		}
	}

	if oldestIP != "" {
		delete(t.entries, oldestIP)
	}
}

// Cleanup removes old entries.
func (t *IPTracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, entry := range t.entries {
		if entry.LastSeen.Before(cutoff) {
			delete(t.entries, ip)
		}
	}
}

// Count returns number of tracked IPs.
func (t *IPTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

// GetEntry returns entry for testing.
func (t *IPTracker) GetEntry(ip string) *IPEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.entries[ip]; ok {
		cp := *e
		return &cp
	}
	return nil
}

// popcount16 counts set bits in uint16.
func popcount16(x uint16) int {
	count := 0
	for x != 0 {
		count++
		x &= x - 1
	}
	return count
}

// qtypeToBit maps DNS query types to bitmap positions (0-15).
func qtypeToBit(qtype uint16) int {
	switch qtype {
	case 1: // A
		return 0
	case 2: // NS
		return 1
	case 5: // CNAME
		return 2
	case 6: // SOA
		return 3
	case 12: // PTR
		return 4
	case 15: // MX
		return 5
	case 16: // TXT
		return 6
	case 28: // AAAA
		return 7
	case 33: // SRV
		return 8
	case 43: // DS
		return 9
	case 46: // RRSIG
		return 10
	case 47: // NSEC
		return 11
	case 48: // DNSKEY
		return 12
	case 50: // NSEC3
		return 13
	case 52: // TLSA
		return 14
	default:
		return 15 // Other
	}
}
