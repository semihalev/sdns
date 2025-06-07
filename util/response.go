// Package util provides DNS protocol utilities for SDNS.
package util

import (
	"time"

	"github.com/miekg/dns"
)

// ResponseType represents the classification of a DNS response.
type ResponseType int

const (
	// TypeSuccess indicates a positive response with answers
	TypeSuccess ResponseType = iota
	// TypeNXDomain indicates the queried domain does not exist (NXDOMAIN)
	TypeNXDomain
	// TypeNoRecords indicates the domain exists but has no records of the requested type (NODATA)
	TypeNoRecords
	// TypeReferral indicates a delegation to another nameserver
	TypeReferral
	// TypeMetaQuery indicates zone transfer or notification queries
	TypeMetaQuery
	// TypeDynamicUpdate indicates a dynamic DNS update message
	TypeDynamicUpdate
	// TypeServerFailure indicates a server error occurred
	TypeServerFailure
	// TypeNotCacheable indicates responses that should not be cached
	TypeNotCacheable
	// TypeExpiredSignature indicates DNSSEC signatures have expired
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

		// Certain queries without answers shouldn't be cached
		if !shouldCache(msg) {
			return TypeNotCacheable, opt
		}

		return TypeSuccess, opt

	case dns.RcodeNameError:
		// NXDOMAIN - domain doesn't exist
		return TypeNXDomain, opt

	default:
		// Other errors
		return TypeServerFailure, opt
	}
}

// isDelegation checks if the response is a referral to another nameserver
func isDelegation(msg *dns.Msg) bool {
	if len(msg.Question) == 0 || len(msg.Ns) == 0 {
		return false
	}

	// Check for NS records in authority section
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			// It's a delegation if the NS record is for a subdomain
			if dns.IsSubDomain(ns.Header().Name, msg.Question[0].Name) {
				return true
			}
		}
	}

	return false
}

// hasSOA checks if the response contains an SOA record in the authority section
func hasSOA(msg *dns.Msg) bool {
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

// hasExpiredSignatures checks if any RRSIG records have expired
func hasExpiredSignatures(msg *dns.Msg, now time.Time) bool {
	nowUnix := uint32(now.Unix())

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

// shouldCache determines if a query type should be cached when empty
func shouldCache(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}

	// Don't cache empty DNSKEY responses
	return msg.Question[0].Qtype != dns.TypeDNSKEY
}
