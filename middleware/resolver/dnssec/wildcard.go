package dnssec

import (
	"github.com/miekg/dns"

	"github.com/semihalev/sdns/internal/dnsname"
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
	_, err := VerifyWildcardAnswerForZoneWithWork(resp, "", work)
	return err
}

// VerifyWildcardAnswerForZoneWithWork binds NSEC3 witnesses to signer and
// reports whether every denial interval is fully authenticated. An Opt-Out
// next-closer interval validates only an insecure answer and therefore
// returns secure=false without turning the response into SERVFAIL.
func VerifyWildcardAnswerForZoneWithWork(
	resp *dns.Msg,
	signer string,
	work NSEC3Work,
) (secure bool, err error) {
	var nsecSet, nsec3Set []dns.RR
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NSEC:
			nsecSet = append(nsecSet, rr)
		case *dns.NSEC3:
			nsec3Set = append(nsec3Set, rr)
		}
	}

	secure = true
	for _, rr := range resp.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}

		owner, err := newAggressiveCanonicalName(sig.Header().Name)
		if err != nil {
			return false, err
		}
		// Labels >= owner label count means an exact (non-wildcard) owner.
		// A malformed over-count is rejected by RRSIG.Verify itself, so it
		// never reaches here with ok=true; treat it as non-wildcard.
		if int(sig.Labels) >= len(owner.labels) {
			continue
		}

		// Closest encloser is the last sig.Labels labels of the owner; the
		// next closer name is one label longer, towards the owner name. Work
		// from canonical wire labels: Unicode case folding is not DNS
		// canonicalization and can alias distinct octet names (for example,
		// Kelvin sign and ASCII "k").
		nextCloserName := owner.suffix(int(sig.Labels) + 1)
		var nb [dnsname.MaxPresentationLength]byte
		pres, ok := dnsname.AppendPresentation(nb[:0], nextCloserName.wire)
		if !ok {
			return false, aggressiveFallback("invalid wildcard next-closer name")
		}
		nextCloser := string(pres)
		denied, authenticated, err := nextCloserDeniedWithWork(
			nextCloser,
			signer,
			nsecSet,
			nsec3Set,
			work,
		)
		if err != nil {
			return false, err
		}
		if !denied {
			return false, ErrWildcardNoDenial
		}
		if !authenticated {
			secure = false
		}
	}

	return secure, nil
}

// nextCloserDeniedWithWork reports whether some NSEC or NSEC3 in the response
// proves the next closer name does not exist.
func nextCloserDeniedWithWork(
	nextCloser string,
	signer string,
	nsecSet, nsec3Set []dns.RR,
	work NSEC3Work,
) (denied bool, secure bool, err error) {
	for _, rr := range nsecSet {
		n := rr.(*dns.NSEC)
		if nsecCovers(n.Header().Name, n.NextDomain, nextCloser) {
			return true, true, nil
		}
	}
	if len(nsec3Set) == 0 {
		return false, false, nil
	}
	prepared, err := prepareNSEC3Set(nsec3Set, signer)
	if err != nil {
		return false, false, err
	}
	evaluator := newNSEC3RingEvaluator(prepared, work)
	_, cover, err := evaluator.lookup(nextCloser)
	if err != nil {
		return false, false, err
	}
	if cover != nil {
		return true, cover.rr.Flags&1 == 0, nil
	}
	return false, false, nil
}
