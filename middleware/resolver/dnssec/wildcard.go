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
	return VerifyWildcardAnswerWithWork(resp, nil)
}

// VerifyWildcardAnswerWithWork is VerifyWildcardAnswer with request-tree
// accounting for every NSEC3 hash operation.
func VerifyWildcardAnswerWithWork(resp *dns.Msg, work NSEC3Work) error {
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
		denied, err := nextCloserDeniedWithWork(nextCloser, nsecSet, nsec3Set, work)
		if err != nil {
			return err
		}
		if !denied {
			return ErrWildcardNoDenial
		}
	}

	return nil
}

// nextCloserDeniedWithWork reports whether some NSEC or NSEC3 in the response
// proves the next closer name does not exist.
func nextCloserDeniedWithWork(
	nextCloser string,
	nsecSet, nsec3Set []dns.RR,
	work NSEC3Work,
) (bool, error) {
	for _, rr := range nsecSet {
		n := rr.(*dns.NSEC)
		if nsecCovers(n.Header().Name, n.NextDomain, nextCloser) {
			return true, nil
		}
	}
	nsec3Set = normalizeNSEC3Set(nsec3Set)
	match := nsec3Operation{kind: nsec3MatchOperation, work: work}
	cover := nsec3Operation{kind: nsec3CoverOperation, work: work}
	for _, rr := range nsec3Set {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		denied, err := nsec3CoversWithWork(n, nextCloser, match, cover)
		if err != nil {
			return false, err
		}
		if denied {
			return true, nil
		}
	}
	return false, nil
}
