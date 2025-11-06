package mldefense

import (
	"sync/atomic"
	"time"
)

// MLModel represents the machine learning defense model
type MLModel struct {
	tracker         *IPTracker

	// Thresholds
	queryScoreThreshold   float64 // Threshold for single query anomaly score
	profileScoreThreshold float64 // Threshold for IP profile score
	combinedScoreThreshold float64 // Threshold for combined score

	// Statistics
	totalQueries      uint64
	totalBlocked      uint64
	totalSuspicious   uint64

	// Configuration
	enabled           bool
	blockMode         bool // If false, only log but don't block
	learningMode      bool // If true, collect data but don't block
}

// NewMLModel creates a new ML defense model
func NewMLModel(enabled, blockMode, learningMode bool) *MLModel {
	return &MLModel{
		tracker:                NewIPTracker(
			100000,              // Max 100k IP profiles
			5*time.Minute,       // Cleanup every 5 minutes
			30*time.Minute,      // Profile TTL: 30 minutes
		),
		queryScoreThreshold:    60.0, // Block if single query score > 60
		profileScoreThreshold:  70.0, // Block if IP profile score > 70
		combinedScoreThreshold: 80.0, // Block if combined score > 80
		enabled:                enabled,
		blockMode:              blockMode,
		learningMode:           learningMode,
	}
}

// AnalyzeQuery analyzes a DNS query and returns whether it should be blocked
func (m *MLModel) AnalyzeQuery(features *QueryFeatures, remoteIP string) (shouldBlock bool, reason string, score float64) {
	if !m.enabled || features == nil {
		return false, "", 0.0
	}

	atomic.AddUint64(&m.totalQueries, 1)

	// Calculate query-level anomaly score
	queryScore := features.CalculateAnomalyScore()

	// Get or create IP profile
	profile := m.tracker.GetOrCreateProfile(remoteIP)

	// Update profile with new query
	profile.UpdateProfile(features, queryScore)

	// Calculate profile-level score
	profileScore := profile.CalculateProfileScore()

	// Calculate combined score (weighted average)
	combinedScore := 0.4*queryScore + 0.6*profileScore

	// Determine if should block
	shouldBlock = false
	reason = ""

	if m.learningMode {
		// In learning mode, never block but track suspicious queries
		if combinedScore > m.combinedScoreThreshold {
			atomic.AddUint64(&m.totalSuspicious, 1)
		}
		return false, "learning_mode", combinedScore
	}

	// Check thresholds
	if queryScore >= m.queryScoreThreshold {
		shouldBlock = true
		reason = "high_query_anomaly_score"
	} else if profileScore >= m.profileScoreThreshold {
		shouldBlock = true
		reason = "high_profile_risk_score"
	} else if combinedScore >= m.combinedScoreThreshold {
		shouldBlock = true
		reason = "high_combined_score"
	}

	if shouldBlock {
		atomic.AddUint64(&m.totalBlocked, 1)
		profile.IncrementBlocked()

		// If not in block mode, log but don't actually block
		if !m.blockMode {
			return false, reason + "_logged_only", combinedScore
		}
	}

	return shouldBlock, reason, combinedScore
}

// GetStatistics returns model statistics
func (m *MLModel) GetStatistics() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":            m.enabled,
		"block_mode":         m.blockMode,
		"learning_mode":      m.learningMode,
		"total_queries":      atomic.LoadUint64(&m.totalQueries),
		"total_blocked":      atomic.LoadUint64(&m.totalBlocked),
		"total_suspicious":   atomic.LoadUint64(&m.totalSuspicious),
		"query_threshold":    m.queryScoreThreshold,
		"profile_threshold":  m.profileScoreThreshold,
		"combined_threshold": m.combinedScoreThreshold,
	}

	// Add tracker stats
	trackerStats := m.tracker.GetStats()
	for k, v := range trackerStats {
		stats["tracker_"+k] = v
	}

	return stats
}

// SetThresholds allows dynamic threshold adjustment
func (m *MLModel) SetThresholds(query, profile, combined float64) {
	if query > 0 {
		m.queryScoreThreshold = query
	}
	if profile > 0 {
		m.profileScoreThreshold = profile
	}
	if combined > 0 {
		m.combinedScoreThreshold = combined
	}
}

// GetBlockRate returns the percentage of blocked queries
func (m *MLModel) GetBlockRate() float64 {
	total := atomic.LoadUint64(&m.totalQueries)
	if total == 0 {
		return 0.0
	}
	blocked := atomic.LoadUint64(&m.totalBlocked)
	return float64(blocked) / float64(total) * 100.0
}

// ResetStatistics resets all statistics counters
func (m *MLModel) ResetStatistics() {
	atomic.StoreUint64(&m.totalQueries, 0)
	atomic.StoreUint64(&m.totalBlocked, 0)
	atomic.StoreUint64(&m.totalSuspicious, 0)
}
