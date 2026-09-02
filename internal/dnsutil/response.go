// Package dnsutil provides DNS protocol utilities for SDNS.
package dnsutil

import (
	"strings"
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

// HasExpiredSignatures reports whether some RRset in the answer or authority
// section has run out of usable signatures.
//
// Per RRset, and only when nothing covering it is left. An RRset may carry
// several signatures, and during a key rollover it routinely carries one from
// the outgoing key beside one from the incoming key. Validation already works
// this way, dnssec.VerifyRRSIG fails an RRset only when no sibling signature
// succeeds, and judging a message on the worst signature anywhere in it would
// have stripped AD from every rollover answer and refused to cache it.
//
// The additional section is left out. AD is a statement about the answer and
// authority sections (RFC 4035 §3.2.3), and a lapsed signature over glue is
// not grounds for withdrawing it.
func HasExpiredSignatures(msg *dns.Msg, now time.Time) bool {
	exhausted := false
	eachSignedRRset([][]dns.RR{msg.Answer, msg.Ns}, now, func(covered bool, _ time.Duration) {
		if !covered {
			exhausted = true
		}
	})
	return exhausted
}

// hasExpiredSignatures is the classifier's view of the same question.
func hasExpiredSignatures(msg *dns.Msg, now time.Time) bool {
	return HasExpiredSignatures(msg, now)
}

// signedRRset names the RRset a signature belongs to, which is what makes two
// signatures siblings. Every field has to agree. Owner and signer fold case,
// as everything else that compares names here does. The signer is part of
// the identity because RFC 4035 §5.3.2 ties a signature to the zone that
// made it: at a delegation the parent's NSEC over the child's name and the
// child's own apex NSEC share owner, class and type while being different
// RRsets under different keys, and one must not vouch for the other. The
// section is part of it for the same reason — the same owner and type can
// sit in the authority section as a proof and in the additional section as
// glue, and those are different data.
type signedRRset struct {
	section int
	owner   string
	signer  string
	class   uint16
	covered uint16
}

// signedRRsetState is one RRset's standing while the signatures are walked.
// Its identity is read off the first signature seen for it, compared in
// place, so the common path folds no names and allocates nothing.
type signedRRsetState struct {
	section int
	first   *dns.RRSIG
	// covered: some signature in its validity period vouches for the RRset.
	covered bool
	// usable: the shortest lifetime the covering signatures permit, and
	// bounded says whether any set it. Zero is a real value here (a
	// signature with an Original TTL of zero authorises no lifetime), so
	// it cannot double as the unset sentinel: with it, the wire order of
	// two siblings decided between a zero and an hour.
	usable  time.Duration
	bounded bool
}

func (s *signedRRsetState) is(section int, sig *dns.RRSIG) bool {
	return s.section == section &&
		s.first.TypeCovered == sig.TypeCovered &&
		s.first.Hdr.Class == sig.Hdr.Class &&
		strings.EqualFold(s.first.Hdr.Name, sig.Hdr.Name) &&
		strings.EqualFold(s.first.SignerName, sig.SignerName)
}

func (s *signedRRsetState) identity() signedRRset {
	return signedRRsetIdentity(s.section, s.first)
}

func signedRRsetIdentity(section int, sig *dns.RRSIG) signedRRset {
	return signedRRset{
		section: section,
		owner:   strings.ToLower(sig.Hdr.Name),
		signer:  strings.ToLower(sig.SignerName),
		class:   sig.Hdr.Class,
		covered: sig.TypeCovered,
	}
}

// signedRRsetInline is how many distinct signed RRsets are tracked in place
// before the walk switches to a map. A response carries one or two outside
// a rollover and a few more during one; only a message stuffed with distinct
// signed RRsets goes past it.
const signedRRsetInline = 8

// eachSignedRRset calls fn once for every RRset in sections that carries a
// signature, reporting whether any of that RRset's signatures is still within
// its validity period, and the shortest lifetime those still-valid ones
// permit.
//
// The two answers are separate because they are separate questions. Whether
// the data may be called authenticated turns on the validity period alone;
// how long it may be kept also takes in the signature's own TTL and its
// Original TTL (RFC 4035 §5.3.3). A signature authorising no lifetime still
// covers the RRset, so it bounds the TTL at nothing without withdrawing AD.
//
// Validity is the validator's own test, RRSIG.ValidityPeriod, and it checks
// both ends: RFC 4035 §5.3.1 requires the current time to sit within the
// inception and expiration bounds, so a signature whose inception has not
// arrived is no more use than one that has lapsed. Siblings outside the
// period are skipped rather than folded in, which is what a key rollover
// needs. Among the survivors the shortest wins, because a downstream
// validator picks its own signature to verify with and may pick that one.
//
// One pass. Up to signedRRsetInline distinct RRsets live in a stack array
// and are matched by comparing names in place, which is every ordinary
// response at no allocation; past that the walk indexes what it has through
// a map of folded identities, so a response filled to the wire limit with
// distinct signed RRsets stays linear instead of paying a quadratic sibling
// scan. This runs more than once on a miss, so the cheap path matters.
// Callbacks come in order of first appearance.
func eachSignedRRset(sections [][]dns.RR, now time.Time, fn func(covered bool, usable time.Duration)) {
	var inline [signedRRsetInline]signedRRsetState
	groups := inline[:0]
	var index map[signedRRset]int

	for section, records := range sections {
		for _, rr := range records {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}

			at := -1
			if index == nil {
				for i := range groups {
					if groups[i].is(section, sig) {
						at = i
						break
					}
				}
				if at < 0 && len(groups) == signedRRsetInline {
					index = make(map[signedRRset]int, 2*signedRRsetInline)
					for i := range groups {
						index[groups[i].identity()] = i
					}
				}
			}
			if at < 0 && index != nil {
				id := signedRRsetIdentity(section, sig)
				if i, ok := index[id]; ok {
					at = i
				} else {
					groups = append(groups, signedRRsetState{section: section, first: sig})
					at = len(groups) - 1
					index[id] = at
				}
			} else if at < 0 {
				groups = append(groups, signedRRsetState{section: section, first: sig})
				at = len(groups) - 1
			}

			if !sig.ValidityPeriod(now) {
				// Outside its period, spent or not yet begun. It says
				// nothing about the RRset while a sibling still covers it,
				// and if none does, covered stays false.
				continue
			}
			state := &groups[at]
			state.covered = true
			if ttl := getRRSIGTTL(sig, now); !state.bounded || ttl < state.usable {
				state.usable, state.bounded = ttl, true
			}
		}
	}
	for i := range groups {
		fn(groups[i].covered, groups[i].usable)
	}
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
