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
	isReferral := false
	switch respType {
	case TypeSuccess:
		// Continue with TTL calculation
	case TypeReferral:
		// A referral used to return the floor without ever looking at its
		// records, so a signed delegation's expiry and Original TTL bounded
		// nothing. It walks the sections now; its lifetime stays what it was.
		isReferral = true
	case TypeNXDomain, TypeNoRecords:
		isNegative = true
	case TypeServerFailure:
		// SERVFAIL responses should be cached for a reasonable time to avoid
		// hammering broken servers, but not too long in case it's temporary
		// Default to 30 seconds, but this will be capped by the negative cache max TTL
		return 30 * time.Second
	case TypeExpiredSignature:
		// Nothing. The signatures over this data lapsed before it arrived, so
		// there is no interval during which it may be relied on, and the
		// default's five seconds handed the classification straight back what
		// it had just refused. The store already declines it; this is what
		// stops the client that caused the miss from being invited to keep it.
		return 0
	default:
		// Other response types get minimal cache time
		return MinCacheTTL
	}

	// A denial carries its lifetime in the SOA of the authority section, and
	// RFC 2308 §5 says one arriving without that record should not be cached
	// at all: there is nothing to derive a lifetime from, and holding it on a
	// guess is what lets a pair of misconfigured servers loop the denial
	// between them forever. Checked on the SOA itself rather than on the
	// message being empty, because an NXDOMAIN that carries an alias chain and
	// no SOA has records aplenty and still says nothing about how long it
	// holds.
	if isNegative && !hasSOA(msg) {
		return 0
	}

	// Handle empty responses
	if !hasRecords(msg) {
		return MinCacheTTL
	}

	// Two bounds, tracked apart. recordTTL is what the records themselves
	// advertise, and for a denial the SOA's MINIMUM alongside it. hardTTL is
	// what RFC 4035 §5.3.3 fixes for signed data: the smallest of every
	// signature's header TTL, its Original TTL field, and the time left before
	// it expires.
	//
	// They are kept apart because only one of them is negotiable. The floor
	// applied at the end is this resolver's freshness preference and may lift a
	// short recordTTL, but it must never lift anything past hardTTL. An entry
	// served after its signature has lapsed is bogus to every validator
	// downstream, and no local policy is entitled to decide otherwise.
	recordTTL := MaxCacheTTL
	hardTTL := MaxCacheTTL
	signed := false
	now := time.Now()

	// negativeSOA folds in the RFC 2308 cap, min(SOA header TTL, SOA.Minttl):
	// a denial with SOA header TTL 86400 and Minttl 300 must not be cached for
	// a day. It applies to the authority section of a negative answer only.
	bound := func(rr dns.RR, negativeSOA bool) {
		if ttl := getTTL(rr); ttl < recordTTL {
			recordTTL = ttl
		}
		if negativeSOA {
			if soa, ok := rr.(*dns.SOA); ok {
				if ttl := time.Duration(soa.Minttl) * time.Second; ttl < recordTTL {
					recordTTL = ttl
				}
			}
		}
	}

	for _, rr := range msg.Answer {
		bound(rr, false)
	}
	for _, rr := range msg.Ns {
		bound(rr, isNegative)
	}
	for _, rr := range msg.Extra {
		// Skip OPT pseudo-records
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		bound(rr, false)
	}

	// The signature bound is taken per RRset, and within an RRset from the
	// signature that still permits the most. Folding every signature into one
	// minimum let a lapsed sibling speak for an RRset another signature still
	// covers, which is exactly the shape of a key rollover.
	//
	// The additional section is left out, as it is for AD: RFC 4035 §3.2.3
	// makes the answer and authority sections what this resolver vouches
	// for, and nothing validates glue. A lapsed signature over an additional
	// record was zeroing the lifetime of a fully covered answer and sending
	// every query for it back upstream. Its record TTLs still bound below.
	eachSignedRRset([][]dns.RR{msg.Answer, msg.Ns}, now, func(_ bool, usable time.Duration) {
		signed = true
		if usable < hardTTL {
			hardTTL = usable
		}
	})

	// RFC 4035 §5.3.3 names four values and the served lifetime may exceed
	// none of them: the RRset's TTL as received, the RRSIG's TTL, its Original
	// TTL, and the time left before it expires. The first is a record TTL, so
	// on signed data the floor may not lift that either. A signed A record with
	// a one-second TTL was being held for five.
	if signed && recordTTL < hardTTL {
		hardTTL = recordTTL
	}

	minTTL := recordTTL
	if hardTTL < minTTL {
		minTTL = hardTTL
	}
	if minTTL < 0 {
		minTTL = 0
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
	if isNegative {
		return minTTL
	}

	// A referral is held briefly whatever its NS records advertise, which is
	// what it has always done, but never past a signature it carries.
	if isReferral {
		if hardTTL < MinCacheTTL {
			return hardTTL
		}
		return MinCacheTTL
	}

	// Positive answers take a floor, and it is a deliberate deviation rather
	// than a right: RFC 1035 §3.2.1 makes a record's TTL the time after which
	// the source should be consulted again, so holding a one-second record for
	// five seconds is this resolver choosing not to re-resolve on every query.
	// It is a defensible local policy about local data.
	//
	// It is not a licence to outlive a signature. hardTTL is fixed by the
	// protocol, and the floor stops there: past that bound the records are
	// bogus to anything that validates them, which is not a freshness question
	// at all. Unsigned data leaves hardTTL at the maximum, so the floor
	// applies to it exactly as before.
	if minTTL < MinCacheTTL {
		if hardTTL < MinCacheTTL {
			return minTTL
		}
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

// getRRSIGTTL returns the hard ceiling one signature places on the data it
// covers. RFC 4035 §5.3.3 names three bounds and the answer is the smallest:
// the RRSIG's own header TTL, its Original TTL field, and the time left before
// it expires. The Original TTL is not decoration — it is what the signature
// was computed over, so a signer that publishes a large header TTL and a small
// original one has authorised the small one, and reading only the header let a
// denial whose signature said one second live for an hour.
//
// A lapsed signature bounds the data at zero. Returning the cache floor here
// made it a floor wearing a bound's clothes, granting five more seconds of
// life to material whose proof had already run out.
func getRRSIGTTL(sig *dns.RRSIG, now time.Time) time.Duration {
	ttl := time.Duration(sig.Header().Ttl) * time.Second

	if orig := time.Duration(sig.OrigTtl) * time.Second; orig < ttl {
		ttl = orig
	}

	if untilExpiry := time.Unix(int64(sig.Expiration), 0).Sub(now); untilExpiry < ttl {
		ttl = untilExpiry
	}

	if ttl < 0 {
		return 0
	}
	return ttl
}
