package server

import (
	"strings"
	"testing"
)

func TestCacheMemoryEstimate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cacheSize int
		want      uint64
	}{
		{name: "default", cacheSize: 0, want: cacheMemoryBaseBytes + 1024*cacheMemoryPerAnswerBytes},
		{name: "configured", cacheSize: 1_000_000, want: cacheMemoryBaseBytes + 1_000_000*cacheMemoryPerAnswerBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheMemoryEstimate(tc.cacheSize); got != tc.want {
				t.Errorf("cacheMemoryEstimate(%d) = %d, want %d", tc.cacheSize, got, tc.want)
			}
		})
	}
}

func TestCacheMemoryEstimateSaturates(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	maxUint64 := ^uint64(0)
	if uint64(maxInt) <= (maxUint64-cacheMemoryBaseBytes)/cacheMemoryPerAnswerBytes {
		t.Skip("int is too small to overflow the estimate")
	}
	if got := cacheMemoryEstimate(maxInt); got != maxUint64 {
		t.Errorf("cacheMemoryEstimate(MaxInt) = %d, want saturation at %d", got, maxUint64)
	}
}

func TestCacheMemoryWarning(t *testing.T) {
	estimate := cacheMemoryEstimate(1_000_000)
	for _, tc := range []struct {
		name   string
		budget uint64
		warn   bool
	}{
		{name: "unknown budget", budget: 0},
		{name: "estimate below budget", budget: estimate + 1},
		{name: "estimate equals budget", budget: estimate},
		{name: "estimate exceeds budget", budget: estimate * 3 / 4, warn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cacheMemoryWarning(1_000_000, tc.budget)
			if (got != "") != tc.warn {
				t.Fatalf("cacheMemoryWarning() = %q, want warning %t", got, tc.warn)
			}
			if tc.warn {
				for _, part := range []string{"cachesize 1000000", "full occupancy", "2.5 GB", "1.9 GB"} {
					if !strings.Contains(got, part) {
						t.Errorf("warning %q does not contain %q", got, part)
					}
				}
			}
		})
	}
}
