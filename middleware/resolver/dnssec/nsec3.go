package dnssec

import (
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// maxNSEC3Iterations caps the hash-iteration count this validator is
// willing to process. Per RFC 9276 §3.2 any value above 100 SHOULD be
// treated as insecure; modern DNSSEC guidance recommends iterations=0.
// An NSEC3 advertising e.g. 65535 iterations costs O(iterations ×
// labels) SHA-1 rounds per name tested, and every validation walks the
// full ancestor chain and every NSEC3 in the response — exactly the
// asymmetric work an attacker-authored zone needs to force DoS work on
// a recursive resolver. NSEC3 records above the cap are skipped (the
// proof then fails via ErrNSECMissingCoverage), which matches
// conservative validator behaviour on the bogus side of the RFC 9276
// "insecure vs bogus" tradeoff.
const maxNSEC3Iterations = 150

// nsec3Safe reports whether an NSEC3 RR is within the iteration cap and
// therefore safe to hash against. Keeping the check at the RR level
// (rather than rejecting the whole RRset) lets a zone that mixes safe
// and unsafe iteration counts still validate through the safe ones.
func nsec3Safe(n *dns.NSEC3) bool {
	return n.Iterations <= maxNSEC3Iterations
}

// nsec3Covers reports strict NSEC3 interval coverage. An exact owner match
// proves that the name exists and therefore must never be accepted as a
// denial-of-existence cover, even if the DNS library's Cover method includes
// the owner boundary for an ordinary interval.
func nsec3Covers(n *dns.NSEC3, name string) bool {
	return !n.Match(name) && n.Cover(name)
}

func typesSet(set []uint16, types ...uint16) bool {
	tm := make(map[uint16]struct{}, len(types))
	for _, t := range types {
		tm[t] = struct{}{}
	}
	for _, t := range set {
		if _, ok := tm[t]; ok {
			return true
		}
	}
	return false
}

func findClosestEncloser(name string, nsec []dns.RR) (string, string) {
	labelIndices := dns.Split(name)
	nc := name

	// RFC 5155 Section 7.2.1: Start from the full name and work up
	for i := 0; i < len(labelIndices); i++ {
		z := name[labelIndices[i]:]

		// Check if this ancestor has a matching NSEC3
		_, err := findMatching(z, nsec)
		if err != nil {
			continue
		}

		// Found a matching NSEC3 for this ancestor
		if i != 0 {
			nc = name[labelIndices[i-1]:]
		}

		// Return the closest encloser and next closer name
		// The actual verification of next closer coverage happens in VerifyNameError
		return z, nc
	}
	return "", ""
}

func findMatching(name string, nsec []dns.RR) ([]uint16, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		if n.Match(name) {
			return n.TypeBitMap, nil
		}
	}
	return nil, ErrNSECMissingCoverage
}

func findCoverer(name string, nsec []dns.RR) ([]uint16, bool, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		if nsec3Covers(n, name) {
			return n.TypeBitMap, (n.Flags & 1) == 1, nil
		}
	}
	return nil, false, ErrNSECMissingCoverage
}

// VerifyNameError verifies an NXDOMAIN proof using NSEC3 records (RFC
// 5155 §8.4): closest encloser exists, an NSEC3 covers the next closer
// name, and an NSEC3 covers the wildcard at the closest encloser.
func VerifyNameError(msg *dns.Msg, nsec []dns.RR) error {
	q := msg.Question[0]
	qname := q.Name

	if dname := dnsutil.DnameTarget(msg); dname != "" {
		qname = dname
	}

	ce, nc := findClosestEncloser(qname, nsec)
	if ce == "" {
		return ErrNSECMissingCoverage
	}

	// RFC 5155 §8.4 requires a full NSEC3 NXDOMAIN proof:
	//   1. Closest encloser exists (established above).
	//   2. An NSEC3 covers the next closer name (proving QNAME is
	//      absent below the closest encloser).
	//   3. An NSEC3 covers the wildcard at the closest encloser
	//      (proving *.closest-encloser cannot synthesize QNAME).
	// Accepting a wildcard-only proof lets a signed zone claim any
	// name is absent as long as some wildcard slot is unallocated —
	// that is not a real name-error proof, so require all three.
	if _, _, err := findCoverer(nc, nsec); err != nil {
		return err
	}
	if _, _, err := findCoverer("*."+ce, nsec); err != nil {
		return err
	}
	return nil
}

// VerifyNODATA verifies a NODATA proof using NSEC3 records (RFC 5155
// §8.5–§8.7), including the DS-specific opt-out branch.
func VerifyNODATA(msg *dns.Msg, nsec []dns.RR) error {
	q := msg.Question[0]
	qname := q.Name

	if dname := dnsutil.DnameTarget(msg); dname != "" {
		qname = dname
	}

	if types, err := findMatching(qname, nsec); err == nil {
		// Exact-owner NODATA (RFC 5155 §8.5).
		if typesSet(types, q.Qtype, dns.TypeCNAME) {
			return ErrNSECTypeExists
		}
		// DS queries are only authoritative in the parent zone. An
		// exact-match NSEC3 whose bitmap contains SOA is the child-
		// zone apex and cannot prove DS non-existence at the
		// delegation point; mirrors the same SOA rejection
		// VerifyNODATANSEC performs so a child-signed denial can't
		// masquerade as a parent-side proof.
		if q.Qtype == dns.TypeDS && typesSet(types, dns.TypeSOA) {
			return ErrNSECBadDelegation
		}
		return nil
	}

	// No exact match — two valid cases remain.
	ce, nc := findClosestEncloser(qname, nsec)
	if ce == "" {
		return ErrNSECMissingCoverage
	}

	if q.Qtype == dns.TypeDS {
		// RFC 5155 §8.6: DS NODATA without exact match requires an
		// NSEC3 covering the next closer name with the Opt-Out bit
		// set. Without that bit the proof cannot distinguish "DS
		// absent" from "DS unsigned because this delegation was
		// opted out" — accepting a non-opt-out cover would let a
		// signed child be silently demoted to insecure during
		// findDS chain walks.
		_, optOut, err := findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		if !optOut {
			return ErrNSECOptOut
		}
		return nil
	}

	// RFC 5155 §8.7: wildcard NODATA proof —
	//   1. An NSEC3 covers the next closer name (qname has no
	//      direct match below the closest encloser).
	//   2. An NSEC3 matches the wildcard at the closest encloser
	//      and its type bitmap does not contain qtype or CNAME.
	if _, _, err := findCoverer(nc, nsec); err != nil {
		return err
	}
	wildcardTypes, err := findMatching("*."+ce, nsec)
	if err != nil {
		return err
	}
	if typesSet(wildcardTypes, q.Qtype, dns.TypeCNAME) {
		return ErrNSECTypeExists
	}
	return nil
}

// VerifyDelegation verifies an insecure-delegation claim using NSEC3.
// The delegation is authenticated either by an exact-match NSEC3 with
// NS set (and DS / SOA cleared) or, for opt-out spans, by an NSEC3
// covering the next closer name with the Opt-Out bit set.
func VerifyDelegation(delegation string, nsec []dns.RR) error {
	types, err := findMatching(delegation, nsec)
	if err != nil {
		ce, nc := findClosestEncloser(delegation, nsec)
		if ce == "" {
			return ErrNSECMissingCoverage
		}
		_, optOut, err := findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		if !optOut {
			return ErrNSECOptOut
		}
		return nil
	}
	return verifyDelegationTypes(types)
}

func verifyDelegationTypes(types []uint16) error {
	if !typesSet(types, dns.TypeNS) {
		return ErrNSECNSMissing
	}
	if typesSet(types, dns.TypeDS, dns.TypeSOA) {
		return ErrNSECBadDelegation
	}
	return nil
}
