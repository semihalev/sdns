package dnssec

import (
	"strings"

	"github.com/miekg/dns"
)

// VerifyWildcardAnswer enforces the RFC 4035 §5.3.4 / RFC 5155 §8.8
// requirement for positive answers synthesized from a wildcard.
//
// An RRSIG whose Labels field is smaller than the label count of the
// RRset owner name signals that the RRset was expanded from a wildcard
// (*.<closest-encloser>). miekg's RRSIG.Verify accepts such a signature
// against any owner name deeper than the wildcard because it canonicalises
// the owner back to "*.<closest-encloser>" before hashing. On its own that
// lets an attacker replay a zone's legitimately-signed wildcard RRSIG over
// a concrete name that actually exists and hand it back with AD=1 — a
// forged-but-"authenticated" answer. RFC 4035 closes this by additionally
// requiring proof that the owner name has no closer match than the
// wildcard, i.e. that the "next closer" name does not exist.
//
// For every wildcard-expanded RRSIG in the Answer section this checks that
// the Authority section carries an NSEC or NSEC3 covering the next closer
// name. Those denial records live in the same response and have already
// been cryptographically validated by VerifyRRSIG (they belong to the
// signer zone and carry their own RRSIGs), so only their semantic coverage
// is checked here. An attacker cannot satisfy the check by replaying a
// genuine signed NSEC/NSEC3: no such record covers a name that exists.
//
// Callers must invoke this only after VerifyRRSIG has returned true for
// resp; a false or error result means the answer must be treated as bogus.
func VerifyWildcardAnswer(resp *dns.Msg) error {
	var nsecSet, nsec3Set []dns.RR
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NSEC:
			nsecSet = append(nsecSet, rr)
		case *dns.NSEC3:
			nsec3Set = append(nsec3Set, rr)
		}
	}

	for _, rr := range resp.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}

		owner := strings.ToLower(dns.Fqdn(sig.Header().Name))
		labels := dns.SplitDomainName(owner)
		// Labels >= owner label count means an exact (non-wildcard) owner.
		// A malformed over-count is rejected by RRSIG.Verify itself, so it
		// never reaches here with ok=true; treat it as non-wildcard.
		if int(sig.Labels) >= len(labels) {
			continue
		}

		// Closest encloser is the last sig.Labels labels of the owner; the
		// next closer name is one label longer, towards the owner name.
		nextCloser := dns.Fqdn(strings.Join(labels[len(labels)-int(sig.Labels)-1:], "."))
		if !nextCloserDenied(nextCloser, nsecSet, nsec3Set) {
			return ErrWildcardNoDenial
		}
	}

	return nil
}

// nextCloserDenied reports whether some NSEC or NSEC3 in the response
// proves the next closer name does not exist.
func nextCloserDenied(nextCloser string, nsecSet, nsec3Set []dns.RR) bool {
	for _, rr := range nsecSet {
		n := rr.(*dns.NSEC)
		if nsecCovers(n.Header().Name, n.NextDomain, nextCloser) {
			return true
		}
	}
	for _, rr := range nsec3Set {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		if nsec3Covers(n, nextCloser) {
			return true
		}
	}
	return false
}
