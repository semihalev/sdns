package mldefense

import (
	"sync"
	"time"
)

// IPProfile tracks behavioral statistics for a single IP address
type IPProfile struct {
	IP                     string
	QueryCount             uint64
	BlockedCount           uint64
	LastQueryTime          time.Time
	FirstSeen              time.Time

	// Exponential Moving Averages (EMA) for online learning
	AvgQueryRate           float64 // Queries per second
	AvgAnomalyScore        float64 // Average anomaly score
	AvgAmplificationFactor float64 // Average amplification potential

	// Query type distribution (for detecting scanning behavior)
	QueryTypeCounts        map[uint16]uint64
	UniqueQueryNames       map[string]bool

	mu                     sync.RWMutex
}

// IPTracker manages profiles for multiple IP addresses
type IPTracker struct {
	profiles        map[string]*IPProfile
	mu              sync.RWMutex
	maxProfiles     int
	cleanupInterval time.Duration
	profileTTL      time.Duration
	lastCleanup     time.Time

	// EMA smoothing factor (alpha)
	// Higher values give more weight to recent observations
	alpha           float64
}

// NewIPTracker creates a new IP tracker
func NewIPTracker(maxProfiles int, cleanupInterval, profileTTL time.Duration) *IPTracker {
	tracker := &IPTracker{
		profiles:        make(map[string]*IPProfile),
		maxProfiles:     maxProfiles,
		cleanupInterval: cleanupInterval,
		profileTTL:      profileTTL,
		alpha:           0.3, // 30% weight to new observations
		lastCleanup:     time.Now(),
	}

	// Start background cleanup goroutine
	go tracker.periodicCleanup()

	return tracker
}

// GetOrCreateProfile retrieves or creates an IP profile
func (t *IPTracker) GetOrCreateProfile(ip string) *IPProfile {
	t.mu.RLock()
	profile, exists := t.profiles[ip]
	t.mu.RUnlock()

	if exists {
		return profile
	}

	// Create new profile
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check again after acquiring write lock
	if profile, exists := t.profiles[ip]; exists {
		return profile
	}

	// Check if we need to clean up before adding
	if len(t.profiles) >= t.maxProfiles {
		t.cleanupOldProfiles()
	}

	profile = &IPProfile{
		IP:              ip,
		FirstSeen:       time.Now(),
		LastQueryTime:   time.Now(),
		QueryTypeCounts: make(map[uint16]uint64),
		UniqueQueryNames: make(map[string]bool),
	}

	t.profiles[ip] = profile
	return profile
}

// UpdateProfile updates an IP profile with new query features
func (p *IPProfile) UpdateProfile(features *QueryFeatures, anomalyScore float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	timeSinceLastQuery := now.Sub(p.LastQueryTime).Seconds()
	if timeSinceLastQuery == 0 {
		timeSinceLastQuery = 0.001 // Avoid division by zero
	}

	// Update query count
	p.QueryCount++
	p.LastQueryTime = now

	// Update query rate using EMA
	instantRate := 1.0 / timeSinceLastQuery
	if p.QueryCount == 1 {
		p.AvgQueryRate = instantRate
	} else {
		// EMA formula: EMA_new = alpha * value + (1 - alpha) * EMA_old
		alpha := 0.3
		p.AvgQueryRate = alpha*instantRate + (1-alpha)*p.AvgQueryRate
	}

	// Update average anomaly score using EMA
	if p.QueryCount == 1 {
		p.AvgAnomalyScore = anomalyScore
	} else {
		p.AvgAnomalyScore = 0.3*anomalyScore + 0.7*p.AvgAnomalyScore
	}

	// Update average amplification factor using EMA
	if p.QueryCount == 1 {
		p.AvgAmplificationFactor = features.AmplificationPotential
	} else {
		p.AvgAmplificationFactor = 0.3*features.AmplificationPotential + 0.7*p.AvgAmplificationFactor
	}

	// Track query type distribution
	p.QueryTypeCounts[features.QueryType]++

	// Track unique query names (limited to prevent memory exhaustion)
	if len(p.UniqueQueryNames) < 1000 {
		p.UniqueQueryNames[features.QueryName] = true
	}
}

// CalculateProfileScore calculates a risk score based on the IP's profile
// Higher score indicates more suspicious behavior
func (p *IPProfile) CalculateProfileScore() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	score := 0.0

	// High query rate (potential DoS or scanning)
	if p.AvgQueryRate > 100 {
		score += 40.0
	} else if p.AvgQueryRate > 50 {
		score += 25.0
	} else if p.AvgQueryRate > 20 {
		score += 10.0
	}

	// High average anomaly score
	if p.AvgAnomalyScore > 50 {
		score += 30.0
	} else if p.AvgAnomalyScore > 30 {
		score += 15.0
	}

	// High average amplification factor
	if p.AvgAmplificationFactor > 50 {
		score += 20.0
	} else if p.AvgAmplificationFactor > 20 {
		score += 10.0
	}

	// Query type diversity (scanning behavior)
	uniqueTypes := len(p.QueryTypeCounts)
	if uniqueTypes > 10 {
		score += 15.0
	} else if uniqueTypes > 5 {
		score += 5.0
	}

	// Very high query count in short time
	if p.QueryCount > 1000 {
		duration := time.Since(p.FirstSeen).Minutes()
		if duration < 1 {
			score += 30.0
		} else if duration < 5 {
			score += 15.0
		}
	}

	return score
}

// ShouldBlock determines if an IP should be blocked based on its profile
func (p *IPProfile) ShouldBlock(threshold float64) bool {
	return p.CalculateProfileScore() >= threshold
}

// periodicCleanup runs periodic cleanup of old profiles
func (t *IPTracker) periodicCleanup() {
	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.Lock()
		t.cleanupOldProfiles()
		t.mu.Unlock()
	}
}

// cleanupOldProfiles removes profiles that haven't been seen recently
// Must be called with write lock held
func (t *IPTracker) cleanupOldProfiles() {
	now := time.Now()

	for ip, profile := range t.profiles {
		profile.mu.RLock()
		lastSeen := profile.LastQueryTime
		profile.mu.RUnlock()

		if now.Sub(lastSeen) > t.profileTTL {
			delete(t.profiles, ip)
		}
	}

	t.lastCleanup = now
}

// GetStats returns tracker statistics
func (t *IPTracker) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return map[string]interface{}{
		"total_profiles": len(t.profiles),
		"max_profiles":   t.maxProfiles,
		"last_cleanup":   t.lastCleanup,
	}
}

// IncrementBlocked increments the blocked count for an IP
func (p *IPProfile) IncrementBlocked() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.BlockedCount++
}
