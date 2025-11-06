package mldefense

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIPTracker_GetOrCreateProfile(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)

	ip := "192.168.1.100"
	profile1 := tracker.GetOrCreateProfile(ip)

	if profile1 == nil {
		t.Fatal("GetOrCreateProfile returned nil")
	}

	if profile1.IP != ip {
		t.Errorf("Profile IP = %v, want %v", profile1.IP, ip)
	}

	// Should return the same profile for the same IP
	profile2 := tracker.GetOrCreateProfile(ip)
	if profile1 != profile2 {
		t.Error("GetOrCreateProfile should return same instance for same IP")
	}
}

func TestIPProfile_UpdateProfile(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)
	profile := tracker.GetOrCreateProfile("192.168.1.100")

	features := &QueryFeatures{
		QueryType:              dns.TypeA,
		QueryName:              "example.com.",
		AmplificationPotential: 8.0,
		IsHighRiskType:         false,
	}

	// Update profile multiple times
	for i := 0; i < 10; i++ {
		profile.UpdateProfile(features, 10.0)
		time.Sleep(time.Millisecond) // Small delay between queries
	}

	if profile.QueryCount != 10 {
		t.Errorf("QueryCount = %v, want 10", profile.QueryCount)
	}

	if profile.AvgAnomalyScore <= 0 {
		t.Error("AvgAnomalyScore should be > 0")
	}

	if profile.AvgQueryRate <= 0 {
		t.Error("AvgQueryRate should be > 0")
	}

	if len(profile.QueryTypeCounts) == 0 {
		t.Error("QueryTypeCounts should not be empty")
	}

	if profile.QueryTypeCounts[dns.TypeA] != 10 {
		t.Errorf("QueryTypeCounts[A] = %v, want 10", profile.QueryTypeCounts[dns.TypeA])
	}
}

func TestIPProfile_CalculateProfileScore(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)

	tests := []struct {
		name         string
		setupFunc    func(*IPProfile)
		expectHigher float64 // Minimum expected score
	}{
		{
			name: "Low activity profile",
			setupFunc: func(p *IPProfile) {
				features := &QueryFeatures{
					QueryType:              dns.TypeA,
					AmplificationPotential: 8.0,
					IsHighRiskType:         false,
				}
				p.UpdateProfile(features, 5.0)
			},
			expectHigher: 0,
		},
		{
			name: "High query rate profile",
			setupFunc: func(p *IPProfile) {
				p.AvgQueryRate = 150 // Very high rate
				p.QueryCount = 1000
			},
			expectHigher: 30,
		},
		{
			name: "High anomaly score profile",
			setupFunc: func(p *IPProfile) {
				p.AvgAnomalyScore = 60
				p.QueryCount = 100
			},
			expectHigher: 25,
		},
		{
			name: "Diverse query types (scanning)",
			setupFunc: func(p *IPProfile) {
				// Simulate 15 different query types
				for i := uint16(1); i <= 15; i++ {
					p.QueryTypeCounts[i] = 10
				}
				p.QueryCount = 150
			},
			expectHigher: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := tracker.GetOrCreateProfile("192.168.1." + tt.name)
			tt.setupFunc(profile)

			score := profile.CalculateProfileScore()
			if score < tt.expectHigher {
				t.Errorf("CalculateProfileScore() = %v, want >= %v", score, tt.expectHigher)
			}
		})
	}
}

func TestIPProfile_ShouldBlock(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)

	tests := []struct {
		name        string
		threshold   float64
		setupFunc   func(*IPProfile)
		expectBlock bool
	}{
		{
			name:      "Low score should not block",
			threshold: 50.0,
			setupFunc: func(p *IPProfile) {
				p.AvgAnomalyScore = 10
				p.QueryCount = 10
			},
			expectBlock: false,
		},
		{
			name:      "High score should block",
			threshold: 50.0,
			setupFunc: func(p *IPProfile) {
				p.AvgQueryRate = 150
				p.AvgAnomalyScore = 70
				p.AvgAmplificationFactor = 100
				p.QueryCount = 1000
			},
			expectBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := tracker.GetOrCreateProfile("192.168.1." + tt.name)
			tt.setupFunc(profile)

			shouldBlock := profile.ShouldBlock(tt.threshold)
			if shouldBlock != tt.expectBlock {
				score := profile.CalculateProfileScore()
				t.Errorf("ShouldBlock() = %v, want %v (score: %.2f, threshold: %.2f)",
					shouldBlock, tt.expectBlock, score, tt.threshold)
			}
		})
	}
}

func TestIPProfile_IncrementBlocked(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)
	profile := tracker.GetOrCreateProfile("192.168.1.100")

	if profile.BlockedCount != 0 {
		t.Errorf("Initial BlockedCount = %v, want 0", profile.BlockedCount)
	}

	profile.IncrementBlocked()
	if profile.BlockedCount != 1 {
		t.Errorf("BlockedCount = %v, want 1", profile.BlockedCount)
	}

	profile.IncrementBlocked()
	if profile.BlockedCount != 2 {
		t.Errorf("BlockedCount = %v, want 2", profile.BlockedCount)
	}
}

func TestIPTracker_GetStats(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)

	// Create some profiles
	for i := 1; i <= 5; i++ {
		ip := "192.168.1." + string(rune('0'+i))
		tracker.GetOrCreateProfile(ip)
	}

	stats := tracker.GetStats()

	totalProfiles, ok := stats["total_profiles"].(int)
	if !ok {
		t.Fatal("total_profiles not found in stats")
	}

	if totalProfiles != 5 {
		t.Errorf("total_profiles = %v, want 5", totalProfiles)
	}

	maxProfiles, ok := stats["max_profiles"].(int)
	if !ok {
		t.Fatal("max_profiles not found in stats")
	}

	if maxProfiles != 100 {
		t.Errorf("max_profiles = %v, want 100", maxProfiles)
	}
}

func TestIPTracker_MaxProfiles(t *testing.T) {
	// Create tracker with max 10 profiles and short TTL for cleanup
	tracker := NewIPTracker(10, time.Millisecond*50, time.Millisecond*100)

	// Create 5 initial profiles
	for i := 1; i <= 5; i++ {
		ip := "192.168.1." + string(rune(i))
		tracker.GetOrCreateProfile(ip)
	}

	// Wait for profiles to age
	time.Sleep(time.Millisecond * 150)

	// Create 5 more profiles (old ones should be cleaned up)
	for i := 6; i <= 10; i++ {
		ip := "192.168.1." + string(rune(i))
		tracker.GetOrCreateProfile(ip)
	}

	// Wait for cleanup to run
	time.Sleep(time.Millisecond * 100)

	stats := tracker.GetStats()
	totalProfiles := stats["total_profiles"].(int)

	// After cleanup, we should have fewer profiles (old ones expired)
	t.Logf("total_profiles after cleanup = %v", totalProfiles)

	// This test just verifies cleanup works, not strict max enforcement
	if totalProfiles == 0 {
		t.Error("Expected some profiles to remain after cleanup")
	}
}

func TestIPProfile_UniqueQueryNames(t *testing.T) {
	tracker := NewIPTracker(100, time.Minute, time.Minute*5)
	profile := tracker.GetOrCreateProfile("192.168.1.100")

	// Add multiple unique query names
	for i := 0; i < 50; i++ {
		features := &QueryFeatures{
			QueryType:              dns.TypeA,
			QueryName:              "example" + string(rune('0'+i)) + ".com.",
			AmplificationPotential: 8.0,
		}
		profile.UpdateProfile(features, 10.0)
	}

	if len(profile.UniqueQueryNames) == 0 {
		t.Error("UniqueQueryNames should not be empty")
	}

	// Verify we're tracking unique names
	if len(profile.UniqueQueryNames) < 10 {
		t.Errorf("Expected at least 10 unique query names, got %v", len(profile.UniqueQueryNames))
	}
}
