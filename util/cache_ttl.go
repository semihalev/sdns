// Package util provides DNS protocol utilities for SDNS.
package util

import (
	"time"

	"github.com/miekg/dns"
)

const (
	// MinCacheTTL is the minimum time to cache any response
	MinCacheTTL = 5 * time.Second
	// MaxCacheTTL is the maximum time to cache any response
	MaxCacheTTL = 24 * time.Hour
)

// CalculateCacheTTL determines the appropriate cache duration for a DNS response.
// It scans all resource records and returns the minimum TTL found, with bounds checking.
func CalculateCacheTTL(msg *dns.Msg, respType ResponseType) time.Duration {
	// Only cache successful responses and negative responses (NXDOMAIN/NODATA)
	switch respType {
	case TypeSuccess, TypeNXDomain, TypeNoRecords:
		// Continue with TTL calculation
	default:
		// Other response types get minimal cache time
		return MinCacheTTL
	}

	// Handle empty responses
	if !hasRecords(msg) {
		return MinCacheTTL
	}

	// Find minimum TTL across all sections
	minTTL := MaxCacheTTL

	// Check Answer section
	for _, rr := range msg.Answer {
		if ttl := getTTL(rr); ttl < minTTL {
			minTTL = ttl
		}
	}

	// Check Authority section
	for _, rr := range msg.Ns {
		if ttl := getTTL(rr); ttl < minTTL {
			minTTL = ttl
		}
	}

	// Check Additional section (excluding OPT)
	for _, rr := range msg.Extra {
		// Skip OPT pseudo-records
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		if ttl := getTTL(rr); ttl < minTTL {
			minTTL = ttl
		}
	}

	// Apply bounds
	if minTTL < MinCacheTTL {
		return MinCacheTTL
	}
	if minTTL > MaxCacheTTL {
		return MaxCacheTTL
	}

	return minTTL
}

// hasRecords checks if the message contains any cacheable records
func hasRecords(msg *dns.Msg) bool {
	// Check if we have any records besides OPT
	totalRecords := len(msg.Answer) + len(msg.Ns)

	// Count non-OPT records in Extra section
	extraRecords := 0
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extraRecords++
		}
	}

	return totalRecords+extraRecords > 0
}

// getTTL extracts TTL from a resource record as a duration
func getTTL(rr dns.RR) time.Duration {
	return time.Duration(rr.Header().Ttl) * time.Second
}
