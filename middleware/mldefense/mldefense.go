package mldefense

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// MLDefense implements ML-based DNS amplification/reflection attack prevention
type MLDefense struct {
	model *MLModel
	cfg   *config.Config
}

// New creates a new MLDefense middleware instance
func New(cfg *config.Config) *MLDefense {
	if !cfg.MLDefenseEnabled {
		return nil
	}

	zlog.Info("Initializing ML-based DNS attack defense middleware",
		"block_mode", cfg.MLDefenseBlockMode,
		"learning_mode", cfg.MLDefenseLearningMode)

	model := NewMLModel(
		cfg.MLDefenseEnabled,
		cfg.MLDefenseBlockMode,
		cfg.MLDefenseLearningMode,
	)

	// Set custom thresholds if configured
	if cfg.MLDefenseQueryThreshold > 0 || cfg.MLDefenseProfileThreshold > 0 || cfg.MLDefenseCombinedThreshold > 0 {
		model.SetThresholds(
			cfg.MLDefenseQueryThreshold,
			cfg.MLDefenseProfileThreshold,
			cfg.MLDefenseCombinedThreshold,
		)
	}

	mldef := &MLDefense{
		model: model,
		cfg:   cfg,
	}

	// Start metrics updater goroutine
	go mldef.updateMetrics()

	return mldef
}

// updateMetrics periodically updates gauge metrics
func (m *MLDefense) updateMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := m.model.tracker.GetStats()
		if totalProfiles, ok := stats["total_profiles"].(int); ok {
			MLDefenseIPProfilesActive.Set(float64(totalProfiles))
		}

		blockRate := m.model.GetBlockRate()
		MLDefenseBlockRate.Set(blockRate)
	}
}

// Name returns the middleware name
func (m *MLDefense) Name() string {
	return "mldefense"
}

// ServeDNS implements the middleware Handler interface
func (m *MLDefense) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	// Skip internal queries
	if w.Internal() {
		ch.Next(ctx)
		return
	}

	// Extract remote IP
	remoteIPAddr := w.RemoteIP()
	if remoteIPAddr == nil {
		ch.Next(ctx)
		return
	}
	remoteIP := remoteIPAddr.String()

	// Skip loopback addresses
	if isLoopback(remoteIP) {
		ch.Next(ctx)
		return
	}

	// Extract features from the query
	features := ExtractFeatures(req, w.Proto())
	if features == nil {
		ch.Next(ctx)
		return
	}

	// Record metrics
	MLDefenseQueriesTotal.Inc()
	MLDefenseScoreHistogram.Observe(0) // Will be updated after analysis
	MLDefenseAmplificationFactorHistogram.Observe(features.AmplificationPotential)

	// Classify query type risk
	riskLevel := "low"
	if features.IsHighRiskType {
		riskLevel = "high"
	} else if features.AmplificationPotential > 20 {
		riskLevel = "medium"
	}
	MLDefenseQueryTypeCounter.WithLabelValues(dns.TypeToString[features.QueryType], riskLevel).Inc()

	// Analyze query using ML model
	shouldBlock, reason, score := m.model.AnalyzeQuery(features, remoteIP)

	// Update score histogram with actual score
	MLDefenseScoreHistogram.Observe(score)

	if shouldBlock {
		// Record blocked query metrics
		MLDefenseBlockedTotal.WithLabelValues(reason).Inc()

		// Log the blocked query
		zlog.Warn("ML Defense: Blocked suspicious query",
			"remote_ip", remoteIP,
			"query_name", features.QueryName,
			"query_type", dns.TypeToString[features.QueryType],
			"reason", reason,
			"score", score,
			"amplification_factor", features.AmplificationPotential,
			"protocol", features.Protocol)

		// Send REFUSED response
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeRefused)
		w.WriteMsg(msg)

		// Cancel the chain (don't process further)
		ch.Cancel()
		return
	}

	// Log suspicious but not blocked queries for monitoring
	if score > 50.0 {
		MLDefenseSuspiciousTotal.Inc()

		if m.cfg.MLDefenseLogSuspicious {
			zlog.Info("ML Defense: Suspicious query detected",
				"remote_ip", remoteIP,
				"query_name", features.QueryName,
				"query_type", dns.TypeToString[features.QueryType],
				"reason", reason,
				"score", score,
				"amplification_factor", features.AmplificationPotential)
		}
	}

	// Continue to next middleware
	ch.Next(ctx)
}

// GetStatistics returns current statistics
func (m *MLDefense) GetStatistics() map[string]interface{} {
	return m.model.GetStatistics()
}

// isLoopback checks if an IP is a loopback address
func isLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
