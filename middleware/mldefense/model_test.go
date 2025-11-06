package mldefense

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMLModel_AnalyzeQuery(t *testing.T) {
	tests := []struct {
		name           string
		blockMode      bool
		learningMode   bool
		features       *QueryFeatures
		iterations     int
		expectBlock    bool
	}{
		{
			name:         "Normal query should not block",
			blockMode:    true,
			learningMode: false,
			features: &QueryFeatures{
				QueryType:              dns.TypeA,
				AmplificationPotential: 8.0,
				IsHighRiskType:         false,
				Protocol:               "tcp",
			},
			iterations:  1,
			expectBlock: false,
		},
		{
			name:         "High-risk query should block in block mode",
			blockMode:    true,
			learningMode: false,
			features: &QueryFeatures{
				QueryType:              dns.TypeANY,
				AmplificationPotential: 179.0,
				IsHighRiskType:         true,
				Protocol:               "udp",
				HasEDNS:                true,
				EDNSBufferSize:         4096,
			},
			iterations:  1,
			expectBlock: true,
		},
		{
			name:         "High-risk query should NOT block in learning mode",
			blockMode:    true,
			learningMode: true,
			features: &QueryFeatures{
				QueryType:              dns.TypeANY,
				AmplificationPotential: 179.0,
				IsHighRiskType:         true,
				Protocol:               "udp",
			},
			iterations:  1,
			expectBlock: false,
		},
		{
			name:         "Repeated suspicious queries should build profile score",
			blockMode:    true,
			learningMode: false,
			features: &QueryFeatures{
				QueryType:              dns.TypeTXT,
				AmplificationPotential: 73.0,
				IsHighRiskType:         true,
				Protocol:               "udp",
			},
			iterations:  50, // Multiple queries to build profile
			expectBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := NewMLModel(true, tt.blockMode, tt.learningMode)

			var lastBlock bool
			var lastReason string
			var lastScore float64

			for i := 0; i < tt.iterations; i++ {
				lastBlock, lastReason, lastScore = model.AnalyzeQuery(tt.features, "192.168.1.100")
			}

			if lastBlock != tt.expectBlock {
				t.Errorf("AnalyzeQuery() block = %v, want %v (reason: %s, score: %.2f)",
					lastBlock, tt.expectBlock, lastReason, lastScore)
			}

			// Verify statistics
			stats := model.GetStatistics()
			totalQueries := stats["total_queries"].(uint64)
			if int(totalQueries) != tt.iterations {
				t.Errorf("Total queries = %v, want %v", totalQueries, tt.iterations)
			}
		})
	}
}

func TestMLModel_SetThresholds(t *testing.T) {
	model := NewMLModel(true, true, false)

	model.SetThresholds(70.0, 80.0, 90.0)

	if model.queryScoreThreshold != 70.0 {
		t.Errorf("Query threshold = %v, want 70.0", model.queryScoreThreshold)
	}
	if model.profileScoreThreshold != 80.0 {
		t.Errorf("Profile threshold = %v, want 80.0", model.profileScoreThreshold)
	}
	if model.combinedScoreThreshold != 90.0 {
		t.Errorf("Combined threshold = %v, want 90.0", model.combinedScoreThreshold)
	}
}

func TestMLModel_GetBlockRate(t *testing.T) {
	model := NewMLModel(true, true, false)

	// Initially should be 0
	rate := model.GetBlockRate()
	if rate != 0.0 {
		t.Errorf("Initial block rate = %v, want 0.0", rate)
	}

	// Simulate some queries
	normalFeatures := &QueryFeatures{
		QueryType:              dns.TypeA,
		AmplificationPotential: 8.0,
		IsHighRiskType:         false,
		Protocol:               "tcp",
	}

	maliciousFeatures := &QueryFeatures{
		QueryType:              dns.TypeANY,
		AmplificationPotential: 179.0,
		IsHighRiskType:         true,
		Protocol:               "udp",
		HasEDNS:                true,
		EDNSBufferSize:         4096,
	}

	// Send 50 normal queries
	for i := 0; i < 50; i++ {
		model.AnalyzeQuery(normalFeatures, "192.168.1.101")
	}

	// Send 50 malicious queries
	for i := 0; i < 50; i++ {
		model.AnalyzeQuery(maliciousFeatures, "192.168.1.102")
	}

	rate = model.GetBlockRate()
	// Should be around 50% (50 blocked out of 100)
	if rate < 30.0 || rate > 70.0 {
		t.Errorf("Block rate = %v, expected between 30%% and 70%%", rate)
	}
}

func TestMLModel_ResetStatistics(t *testing.T) {
	model := NewMLModel(true, true, false)

	features := &QueryFeatures{
		QueryType:              dns.TypeA,
		AmplificationPotential: 8.0,
		IsHighRiskType:         false,
		Protocol:               "udp",
	}

	// Generate some queries
	for i := 0; i < 10; i++ {
		model.AnalyzeQuery(features, "192.168.1.103")
	}

	// Verify statistics are non-zero
	stats := model.GetStatistics()
	if stats["total_queries"].(uint64) == 0 {
		t.Error("Expected non-zero queries before reset")
	}

	// Reset statistics
	model.ResetStatistics()

	// Verify statistics are zero
	stats = model.GetStatistics()
	if stats["total_queries"].(uint64) != 0 {
		t.Error("Expected zero queries after reset")
	}
	if stats["total_blocked"].(uint64) != 0 {
		t.Error("Expected zero blocked after reset")
	}
}

func TestMLModel_DisabledMode(t *testing.T) {
	model := NewMLModel(false, true, false)

	features := &QueryFeatures{
		QueryType:              dns.TypeANY,
		AmplificationPotential: 179.0,
		IsHighRiskType:         true,
		Protocol:               "udp",
	}

	shouldBlock, _, _ := model.AnalyzeQuery(features, "192.168.1.104")

	if shouldBlock {
		t.Error("Disabled model should never block")
	}
}
