package resolver

import (
	"strings"

	"github.com/miekg/dns"
)

// maxNSEC3Iterations caps the hash-iteration count this validator is
// willing to process. Per RFC 9276 §3.2 any value above 100 SHOULD be
// treated as insecure; modern DNSSEC guidance recommends iterations=0.
// An NSEC3 advertising e.g. 65535 iterations costs O(iterations ×
// labels) SHA-1 rounds per name tested, and every validation walks the
// full ancestor chain and every NSEC3 in the response — exactly the
// asymmetric work an attacker-authored zone needs to force DoS work on
// a recursive resolver. NSEC3 records above the cap are skipped (the
// proof then fails via errNSECMissingCoverage), which matches
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
		// The actual verification of next closer coverage happens in verifyNameError
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
	return nil, errNSECMissingCoverage
}

func findCoverer(name string, nsec []dns.RR) ([]uint16, bool, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		if n.Cover(name) {
			return n.TypeBitMap, (n.Flags & 1) == 1, nil
		}
	}
	return nil, false, errNSECMissingCoverage
}

func verifyNameError(msg *dns.Msg, nsec []dns.RR) error {
	q := msg.Question[0]
	qname := q.Name

	if dname := getDnameTarget(msg); dname != "" {
		qname = dname
	}

	ce, nc := findClosestEncloser(qname, nsec)
	if ce == "" {
		return errNSECMissingCoverage
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

func verifyNODATA(msg *dns.Msg, nsec []dns.RR) error {
	q := msg.Question[0]
	qname := q.Name

	if dname := getDnameTarget(msg); dname != "" {
		qname = dname
	}

	if types, err := findMatching(qname, nsec); err == nil {
		// Exact-owner NODATA (RFC 5155 §8.5).
		if typesSet(types, q.Qtype, dns.TypeCNAME) {
			return errNSECTypeExists
		}
		// DS queries are only authoritative in the parent zone. An
		// exact-match NSEC3 whose bitmap contains SOA is the child-
		// zone apex and cannot prove DS non-existence at the
		// delegation point; mirrors the same SOA rejection
		// verifyNODATANSEC performs so a child-signed denial can't
		// masquerade as a parent-side proof.
		if q.Qtype == dns.TypeDS && typesSet(types, dns.TypeSOA) {
			return errNSECBadDelegation
		}
		return nil
	}

	// No exact match — two valid cases remain.
	ce, nc := findClosestEncloser(qname, nsec)
	if ce == "" {
		return errNSECMissingCoverage
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
			return errNSECOptOut
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
		return errNSECTypeExists
	}
	return nil
}

// verifyDelegationNSEC verifies an insecure-delegation claim using NSEC
// records (RFC 4035 §5.2). It must find an NSEC whose owner equals the
// delegation name and whose type bitmap contains NS but neither DS nor
// SOA. Anything looser would let a malicious parent strip the DS from a
// signed child and have the resolver treat the child as insecure.
func verifyDelegationNSEC(delegation string, nsecSet []dns.RR) error {
	delegation = strings.ToLower(dns.Fqdn(delegation))
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if strings.ToLower(dns.Fqdn(nsec.Header().Name)) != delegation {
			continue
		}
		if !typesSet(nsec.TypeBitMap, dns.TypeNS) {
			return errNSECNSMissing
		}
		if typesSet(nsec.TypeBitMap, dns.TypeDS, dns.TypeSOA) {
			return errNSECBadDelegation
		}
		return nil
	}
	return errNSECMissingCoverage
}

func verifyDelegation(delegation string, nsec []dns.RR) error {
	types, err := findMatching(delegation, nsec)
	if err != nil {
		ce, nc := findClosestEncloser(delegation, nsec)
		if ce == "" {
			return errNSECMissingCoverage
		}
		_, optOut, err := findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		if !optOut {
			return errNSECOptOut
		}
		return nil
	}
	if !typesSet(types, dns.TypeNS) {
		return errNSECNSMissing
	}
	if typesSet(types, dns.TypeDS, dns.TypeSOA) {
		return errNSECBadDelegation
	}
	return nil
}

// NSEC (non-hashed) verification functions

// verifyNameErrorNSEC verifies NXDOMAIN using NSEC records (RFC 4035 §3.1.3.2).
// The proof requires two NSEC records: one that covers QNAME (proving
// QNAME does not exist) and one that covers the wildcard at the closest
// encloser of QNAME (proving no wildcard match could synthesize the
// answer). Accepting wildcard coverage from an arbitrary ancestor lets a
// mismatched proof pass, so the wildcard is derived from the covering
// NSEC's owner/next labels, not from any ancestor of QNAME.
func verifyNameErrorNSEC(msg *dns.Msg, nsecSet []dns.RR) error {
	if len(nsecSet) == 0 {
		return errNSECMissingCoverage
	}

	q := msg.Question[0]
	qname := q.Name
	if dname := getDnameTarget(msg); dname != "" {
		qname = dname
	}

	var covering *dns.NSEC
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if nsecCovers(nsec.Header().Name, nsec.NextDomain, qname) {
			covering = nsec
			break
		}
	}
	if covering == nil {
		return errNSECMissingCoverage
	}

	ce := closestEncloserFromNSEC(qname, covering)
	if ce == "" {
		return errNSECMissingCoverage
	}

	// RFC 4592 §4.2: wildcards are not defined at the root zone, so if
	// the closest encloser is the root, there is no wildcard proof to
	// require.
	if ce == "." {
		return nil
	}

	wildcard := "*." + ce
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if nsecCovers(nsec.Header().Name, nsec.NextDomain, wildcard) {
			return nil
		}
	}
	return errNSECMissingCoverage
}

// closestEncloserFromNSEC derives the closest encloser of qname from the
// NSEC that covers it. The closest encloser is the longest ancestor of
// qname shared (by trailing labels) with the NSEC owner or its next
// name, since both of those names exist in the zone. Per RFC 4035
// §3.1.3.2, the result must be a proper ancestor of qname.
func closestEncloserFromNSEC(qname string, nsec *dns.NSEC) string {
	qn := strings.ToLower(dns.Fqdn(qname))
	qLabels := dns.SplitDomainName(qn)

	shared := func(other string) int {
		ol := dns.SplitDomainName(strings.ToLower(dns.Fqdn(other)))
		count := 0
		for i, j := len(qLabels)-1, len(ol)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
			if qLabels[i] != ol[j] {
				break
			}
			count++
		}
		return count
	}

	n := shared(nsec.Header().Name)
	if s := shared(nsec.NextDomain); s > n {
		n = s
	}
	// The closest encloser is a proper ancestor of qname, so cap at
	// len(qLabels)-1 even if owner or next happens to share all labels
	// (which would only occur for a malformed NSEC covering its own
	// name).
	if n >= len(qLabels) {
		n = len(qLabels) - 1
	}
	if n <= 0 {
		return "."
	}
	return dns.Fqdn(strings.Join(qLabels[len(qLabels)-n:], "."))
}

// verifyNODATANSEC verifies NODATA using NSEC records (RFC 4035 Section 3.1.3.1).
func verifyNODATANSEC(msg *dns.Msg, nsecSet []dns.RR) error {
	if len(nsecSet) == 0 {
		return errNSECMissingCoverage
	}

	q := msg.Question[0]
	qname := q.Name

	// Check if DNAME redirection applies
	if dname := getDnameTarget(msg); dname != "" {
		qname = dname
	}

	// For NODATA, we need a NSEC record for the exact name
	// showing that the queried type doesn't exist
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)

		// Check if this NSEC is for the queried name
		if dns.CanonicalName(nsec.Header().Name) == dns.CanonicalName(qname) {
			// Reject the queried type or CNAME: a CNAME bit at the
			// exact owner means the name aliases elsewhere, so the
			// server is lying by returning NODATA instead of
			// following the alias. The NSEC3 path already rejects
			// both and the NSEC path must match for consistency.
			if typesSet(nsec.TypeBitMap, q.Qtype, dns.TypeCNAME) {
				return errNSECTypeExists
			}

			// DS queries are only authoritative in the parent zone.
			// Reject an NSEC whose bitmap contains SOA — that NSEC
			// belongs to the child-zone apex and cannot prove DS
			// non-existence at the delegation point. The NS bit is
			// not required: findDS() may probe ordinary non-
			// delegation names while walking the chain, and their
			// legitimate NSECs will list whatever types the name
			// actually has (typically no NS, no SOA, no DS), which
			// is a perfectly valid DS NODATA proof.
			if q.Qtype == dns.TypeDS && typesSet(nsec.TypeBitMap, dns.TypeSOA) {
				return errNSECBadDelegation
			}

			return nil
		}
	}

	// Wildcard NODATA (RFC 4035 §3.1.3.4): when qname has no exact
	// NSEC owner, the proof is
	//   1. An NSEC covering qname — proves qname doesn't exist
	//      directly.
	//   2. An NSEC whose owner is *.<closest-encloser> whose type
	//      bitmap does not contain qtype or CNAME — proves the
	//      wildcard synthesis that would otherwise answer qname
	//      doesn't carry the queried type.
	var covering *dns.NSEC
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if nsecCovers(nsec.Header().Name, nsec.NextDomain, qname) {
			covering = nsec
			break
		}
	}
	if covering == nil {
		return errNSECMissingCoverage
	}
	ce := closestEncloserFromNSEC(qname, covering)
	if ce == "" {
		return errNSECMissingCoverage
	}
	wildcard := strings.ToLower(dns.Fqdn("*." + ce))
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if strings.ToLower(dns.Fqdn(nsec.Header().Name)) != wildcard {
			continue
		}
		if typesSet(nsec.TypeBitMap, q.Qtype, dns.TypeCNAME) {
			return errNSECTypeExists
		}
		if q.Qtype == dns.TypeDS && typesSet(nsec.TypeBitMap, dns.TypeSOA) {
			return errNSECBadDelegation
		}
		return nil
	}
	return errNSECMissingCoverage
}

// canonicalNameCompare returns -1, 0, or 1 ordering a and b per RFC 4034
// §6.1 (canonical DNS name order): labels are compared right-to-left using
// lowercase byte-wise comparison, with shorter names sorting before longer
// ones when one is a strict suffix of the other. Plain string comparison
// disagrees with this order for names like "example.com." vs
// "a.example.com.", so any proof built on byte-wise compares produces
// both false positives and false negatives.
func canonicalNameCompare(a, b string) int {
	aLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(a)))
	bLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(b)))
	i, j := len(aLabels)-1, len(bLabels)-1
	for i >= 0 && j >= 0 {
		if c := strings.Compare(aLabels[i], bLabels[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case len(aLabels) < len(bLabels):
		return -1
	case len(aLabels) > len(bLabels):
		return 1
	}
	return 0
}

// nsecCovers reports whether an NSEC whose owner is `owner` and whose
// NextDomain is `next` proves the non-existence of `name`. It uses
// canonical DNS name ordering (RFC 4034 §6.1).
func nsecCovers(owner, next, name string) bool {
	cmpON := canonicalNameCompare(owner, next)
	cmpNameOwner := canonicalNameCompare(name, owner)
	cmpNameNext := canonicalNameCompare(name, next)

	// Single-name zone sentinel: owner == next means the NSEC covers
	// every name except the owner itself.
	if cmpON == 0 {
		return cmpNameOwner != 0
	}

	if cmpON < 0 {
		// Normal interval: owner < next.
		return cmpNameOwner > 0 && cmpNameNext < 0
	}

	// Wrap around the zone apex: owner > next, so the NSEC covers names
	// greater than owner or less than next.
	return cmpNameOwner > 0 || cmpNameNext < 0
}
