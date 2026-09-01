// Package dnsutil provides DNS protocol utilities for SDNS.
package dnsutil

import (
	"time"

	"github.com/miekg/dns"
)

const (
	// MinCacheTTL is the minimum time to cache any response.
	MinCacheTTL = 5 * time.Second
	// MaxCacheTTL is the maximum time to cache any response.
	MaxCacheTTL = 24 * time.Hour
)

// CalculateCacheTTL determines the appropriate cache duration for a DNS response.
// It scans all resource records and returns the minimum TTL found, with bounds checking.
// For DNSSEC-signed responses, it also considers RRSIG expiration times.
func CalculateCacheTTL(msg *dns.Msg, respType ResponseType) time.Duration {
	// Only cache successful responses and negative responses (NXDOMAIN/NODATA)
	isNegative := false
	switch respType {
	case TypeSuccess:
		// Continue with TTL calculation
	case TypeNXDomain, TypeNoRecords:
		isNegative = true
	case TypeServerFailure:
		// SERVFAIL responses should be cached for a reasonable time to avoid
		// hammering broken servers, but not too long in case it's temporary
		// Default to 30 seconds, but this will be capped by the negative cache max TTL
		return 30 * time.Second
	default:
		// Other response types get minimal cache time
		return MinCacheTTL
	}

	// Handle empty responses
	if !hasRecords(msg) {
		// A denial carries its lifetime in the SOA of the authority section.
		// With no records at all there is nothing to derive one from, and RFC
		// 2308 §5 says such a response should not be cached: without an SOA
		// there is no way to stop a pair of misconfigured servers looping the
		// denial between them forever.
		if isNegative {
			return 0
		}
		return MinCacheTTL
	}

	// Find minimum TTL across all sections
	minTTL := MaxCacheTTL
	now := time.Now()

	// Check Answer section
	for _, rr := range msg.Answer {
		if ttl := getTTL(rr); ttl < minTTL {
			minTTL = ttl
		}
		// Check RRSIG expiration
		if sig, ok := rr.(*dns.RRSIG); ok {
			if ttl := getRRSIGTTL(sig, now); ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	// Check Authority section. For negative responses, RFC 2308
	// caps the cache TTL at min(SOA header TTL, SOA.Minttl) — a
	// response with SOA header TTL 86400 and Minttl 300 must not
	// be cached for a day.
	for _, rr := range msg.Ns {
		if ttl := getTTL(rr); ttl < minTTL {
			minTTL = ttl
		}
		if isNegative {
			if soa, ok := rr.(*dns.SOA); ok {
				if ttl := time.Duration(soa.Minttl) * time.Second; ttl < minTTL {
					minTTL = ttl
				}
			}
		}
		// Check RRSIG expiration
		if sig, ok := rr.(*dns.RRSIG); ok {
			if ttl := getRRSIGTTL(sig, now); ttl < minTTL {
				minTTL = ttl
			}
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
		// Check RRSIG expiration
		if sig, ok := rr.(*dns.RRSIG); ok {
			if ttl := getRRSIGTTL(sig, now); ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	// Apply bounds
	if minTTL > MaxCacheTTL {
		return MaxCacheTTL
	}

	// RFC 2308 §5 makes the SOA-derived lifetime a ceiling: it says how long a
	// resolver *may* cache the denial. A floor inverts that — a zone that
	// publishes a one-second negative TTL means one second, and holding it for
	// five is the resolver overriding the only party entitled to decide. Zero
	// is a real answer here, and the caller declines to admit the entry.
	//
	// Positive answers keep the floor. Nothing derives it from a zone's own
	// statement about its data, so nothing is being overridden: it is the
	// resolver's own guard against re-resolving a one-second record on every
	// query, and RFC 1035 §3.2.1 leaves that latitude.
	if isNegative {
		if minTTL < 0 {
			return 0
		}
		return minTTL
	}

	if minTTL < MinCacheTTL {
		return MinCacheTTL
	}

	return minTTL
}

// hasRecords checks if the message contains any cacheable records.
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

// getTTL extracts TTL from a resource record as a duration.
func getTTL(rr dns.RR) time.Duration {
	return time.Duration(rr.Header().Ttl) * time.Second
}

// getRRSIGTTL calculates the effective TTL for a RRSIG record based on its expiration time.
// The cache TTL should not exceed the time until the signature expires.
func getRRSIGTTL(sig *dns.RRSIG, now time.Time) time.Duration {
	// Get the regular TTL from the record
	recordTTL := time.Duration(sig.Header().Ttl) * time.Second

	// Calculate time until expiration
	expireTime := time.Unix(int64(sig.Expiration), 0)
	timeUntilExpire := expireTime.Sub(now)

	// An expired signature bounds the answer at zero. Returning the floor here
	// made it a floor wearing a bound's clothes: on the denial path, which
	// takes no floor of its own, it was the one thing still granting five more
	// seconds of life to data whose proof had already lapsed. Positive answers
	// land on their own floor immediately afterwards, so they see no change.
	if timeUntilExpire <= 0 {
		return 0
	}

	// Return the minimum of record TTL and time until expiration
	if timeUntilExpire < recordTTL {
		return timeUntilExpire
	}
	return recordTTL
}
