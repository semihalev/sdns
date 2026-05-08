package dnssec

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// VerifyDelegationNSEC verifies an insecure-delegation claim using NSEC
// records (RFC 4035 §5.2). It must find an NSEC whose owner equals the
// delegation name and whose type bitmap contains NS but neither DS nor
// SOA. Anything looser would let a malicious parent strip the DS from a
// signed child and have the resolver treat the child as insecure.
func VerifyDelegationNSEC(delegation string, nsecSet []dns.RR) error {
	delegation = strings.ToLower(dns.Fqdn(delegation))
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if strings.ToLower(dns.Fqdn(nsec.Header().Name)) != delegation {
			continue
		}
		if !typesSet(nsec.TypeBitMap, dns.TypeNS) {
			return ErrNSECNSMissing
		}
		if typesSet(nsec.TypeBitMap, dns.TypeDS, dns.TypeSOA) {
			return ErrNSECBadDelegation
		}
		return nil
	}
	return ErrNSECMissingCoverage
}

// VerifyNameErrorNSEC verifies NXDOMAIN using NSEC records (RFC 4035
// §3.1.3.2). The proof requires two NSEC records: one that covers QNAME
// (proving QNAME does not exist) and one that covers the wildcard at the
// closest encloser of QNAME (proving no wildcard match could synthesize
// the answer). Accepting wildcard coverage from an arbitrary ancestor
// lets a mismatched proof pass, so the wildcard is derived from the
// covering NSEC's owner/next labels, not from any ancestor of QNAME.
func VerifyNameErrorNSEC(msg *dns.Msg, nsecSet []dns.RR) error {
	if len(nsecSet) == 0 {
		return ErrNSECMissingCoverage
	}

	q := msg.Question[0]
	qname := q.Name
	if dname := dnsutil.DnameTarget(msg); dname != "" {
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
		return ErrNSECMissingCoverage
	}

	ce := closestEncloserFromNSEC(qname, covering)
	if ce == "" {
		return ErrNSECMissingCoverage
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
	return ErrNSECMissingCoverage
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

// VerifyNODATANSEC verifies NODATA using NSEC records (RFC 4035 §3.1.3.1).
func VerifyNODATANSEC(msg *dns.Msg, nsecSet []dns.RR) error {
	if len(nsecSet) == 0 {
		return ErrNSECMissingCoverage
	}

	q := msg.Question[0]
	qname := q.Name

	// Check if DNAME redirection applies
	if dname := dnsutil.DnameTarget(msg); dname != "" {
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
				return ErrNSECTypeExists
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
				return ErrNSECBadDelegation
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
		return ErrNSECMissingCoverage
	}
	ce := closestEncloserFromNSEC(qname, covering)
	if ce == "" {
		return ErrNSECMissingCoverage
	}
	wildcard := strings.ToLower(dns.Fqdn("*." + ce))
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		if strings.ToLower(dns.Fqdn(nsec.Header().Name)) != wildcard {
			continue
		}
		if typesSet(nsec.TypeBitMap, q.Qtype, dns.TypeCNAME) {
			return ErrNSECTypeExists
		}
		if q.Qtype == dns.TypeDS && typesSet(nsec.TypeBitMap, dns.TypeSOA) {
			return ErrNSECBadDelegation
		}
		return nil
	}
	return ErrNSECMissingCoverage
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
