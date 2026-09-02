// Package dnsutil provides DNS protocol utilities for SDNS.
package dnsutil

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
)

// ResponseType represents the classification of a DNS response.
type ResponseType int

const (
	// TypeSuccess indicates a positive response with answers.
	TypeSuccess ResponseType = iota
	// TypeNXDomain indicates the queried domain does not exist (NXDOMAIN).
	TypeNXDomain
	// TypeNoRecords indicates the domain exists but has no records of the requested type (NODATA).
	TypeNoRecords
	// TypeReferral indicates a delegation to another nameserver.
	TypeReferral
	// TypeMetaQuery indicates zone transfer or notification queries.
	TypeMetaQuery
	// TypeDynamicUpdate indicates a dynamic DNS update message.
	TypeDynamicUpdate
	// TypeServerFailure indicates a server error occurred.
	TypeServerFailure
	// TypeNotCacheable indicates responses that should not be cached.
	TypeNotCacheable
	// TypeExpiredSignature indicates DNSSEC signatures have expired.
	TypeExpiredSignature
)

// ClassifyResponse analyzes a DNS message and determines its type.
// It also returns the OPT record if present for EDNS0 processing.
// The time parameter is used for checking DNSSEC signature expiration.
func ClassifyResponse(msg *dns.Msg, now time.Time) (ResponseType, *dns.OPT) {
	// Extract OPT record if present
	var opt *dns.OPT
	if o := msg.IsEdns0(); o != nil {
		opt = o
	}

	// Check for errors first
	if msg.Rcode == dns.RcodeServerFailure {
		return TypeServerFailure, opt
	}

	// Check if this is a question-only message (for meta queries)
	if len(msg.Question) > 0 {
		qt := msg.Question[0].Qtype
		if qt == dns.TypeAXFR || qt == dns.TypeIXFR {
			return TypeMetaQuery, opt
		}

		// Dynamic updates
		if msg.Opcode == dns.OpcodeUpdate {
			return TypeDynamicUpdate, opt
		}

		// Notifications
		if msg.Opcode == dns.OpcodeNotify {
			return TypeMetaQuery, opt
		}
	}

	// Check response code
	switch msg.Rcode {
	case dns.RcodeSuccess:
		// Need to check if we have answers or if it's a delegation
		if len(msg.Answer) > 0 {
			// Check for expired DNSSEC signatures
			if hasExpiredSignatures(msg, now) {
				return TypeExpiredSignature, opt
			}
			// An answer section that never reaches the type asked for is a
			// NODATA answer wearing a CNAME chain, and the terminal denial is
			// what decides its lifetime. Classifying it as a success read the
			// alias TTL instead of the SOA the last hop returned, which is the
			// commonest denial shape on the wire.
			if !answerHasQType(msg) && hasSOA(msg) {
				return TypeNoRecords, opt
			}
			return TypeSuccess, opt
		}

		// No answers - check if it's a delegation or NODATA
		if isDelegation(msg) {
			return TypeReferral, opt
		}

		// NODATA response - domain exists but no records of requested type
		if hasSOA(msg) {
			return TypeNoRecords, opt
		}

		// Nothing at all: no answer, no delegation, no SOA. There is no
		// lifetime to derive and nothing to serve, and RFC 2308 §5 wants a
		// negative answer without an SOA left uncached rather than held on a
		// guess.
		return TypeNotCacheable, opt

	case dns.RcodeNameError:
		// NXDOMAIN - domain doesn't exist
		return TypeNXDomain, opt

	default:
		// Other errors
		return TypeServerFailure, opt
	}
}

// isDelegation checks if the response is a referral to another nameserver.
func isDelegation(msg *dns.Msg) bool {
	if len(msg.Question) == 0 || len(msg.Ns) == 0 {
		return false
	}

	// Check for NS records in authority section
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			// It's a delegation if the NS record is for a subdomain
			if dnsname.Sub(ns.Header().Name, msg.Question[0].Name) {
				return true
			}
		}
	}

	return false
}

// hasSOA checks if the response contains a SOA record in the authority section.
func hasSOA(msg *dns.Msg) bool {
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

// HasExpiredSignatures reports whether any RRSIG in msg has already expired.
//
// Exported because the classification cannot carry this on its own. A response
// is named for what it is, a denial, a referral, an answer, and only the
// NOERROR-with-records shape has anywhere to put "and its signatures lapsed".
// An expired NXDOMAIN is still an NXDOMAIN. Callers that need the fact rather
// than the name ask here.
func HasExpiredSignatures(msg *dns.Msg, now time.Time) bool {
	return hasExpiredSignatures(msg, now)
}

// hasExpiredSignatures checks if any RRSIG records have expired.
func hasExpiredSignatures(msg *dns.Msg, now time.Time) bool {
	nowUnix := uint32(now.Unix()) //nolint:gosec // G115 - time conversion for DNS record

	checkRRSIG := func(rr dns.RR) bool {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.Expiration < nowUnix {
				return true
			}
		}
		return false
	}

	// Check all sections
	for _, rr := range msg.Answer {
		if checkRRSIG(rr) {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if checkRRSIG(rr) {
			return true
		}
	}
	for _, rr := range msg.Extra {
		if checkRRSIG(rr) {
			return true
		}
	}

	return false
}

// answerHasQType reports whether the answer section carries a record of the
// type that was asked for. A chain of CNAMEs and their signatures does not:
// those are the road to the answer, not the answer.
func answerHasQType(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}
	qtype := msg.Question[0].Qtype
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}
