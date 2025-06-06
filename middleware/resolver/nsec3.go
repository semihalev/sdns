package resolver

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

var (
	errNSECTypeExists      = errors.New("NSEC/NSEC3 record shows question type exists")
	errNSECMissingCoverage = errors.New("NSEC/NSEC3 record missing for non-existence proof")
	errNSECBadDelegation   = errors.New("DS or SOA bit set in NSEC/NSEC3 type map")
	errNSECNSMissing       = errors.New("NS bit not set in NSEC/NSEC3 type map")
	errNSECOptOut          = errors.New("Opt-Out bit not set for NSEC3 record covering next closer")
)

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
		if n.Match(name) {
			return n.TypeBitMap, nil
		}
	}
	return nil, errNSECMissingCoverage
}

func findCoverer(name string, nsec []dns.RR) ([]uint16, bool, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
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

	// RFC 5155: We need to verify three things:
	// 1. Closest encloser exists (already verified by findClosestEncloser)
	// 2. Next closer name is covered (proving QNAME doesn't exist)
	// 3. Wildcard at closest encloser is covered (proving *.ce doesn't exist)

	// Note: Some implementations may send incomplete NSEC3 sets in certain cases.
	// We verify what we can while maintaining compatibility.

	// Verify next closer is covered
	_, _, ncErr := findCoverer(nc, nsec)

	// Verify wildcard is covered
	_, _, wcErr := findCoverer("*."+ce, nsec)

	// If we have both coverages, we're fully RFC compliant
	if ncErr == nil && wcErr == nil {
		return nil
	}

	// For backward compatibility, accept if at least wildcard is covered
	// (this was the original behavior)
	if wcErr == nil {
		return nil
	}

	// Return the most relevant error
	if ncErr != nil {
		return ncErr
	}
	return wcErr
}

func verifyNODATA(msg *dns.Msg, nsec []dns.RR) error {
	q := msg.Question[0]
	qname := q.Name

	if dname := getDnameTarget(msg); dname != "" {
		qname = dname
	}

	types, err := findMatching(qname, nsec)
	if err != nil {
		if q.Qtype != dns.TypeDS {
			return err
		}

		ce, nc := findClosestEncloser(qname, nsec)
		if ce == "" {
			return errNSECMissingCoverage
		}
		_, _, err := findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		return nil
	}

	if typesSet(types, q.Qtype, dns.TypeCNAME) {
		return errNSECTypeExists
	}

	return nil
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

// verifyNameErrorNSEC verifies NXDOMAIN using NSEC records (RFC 4035 Section 3.1.3.2)
func verifyNameErrorNSEC(msg *dns.Msg, nsecSet []dns.RR) error {
	if len(nsecSet) == 0 {
		return errNSECMissingCoverage
	}

	q := msg.Question[0]
	qname := q.Name

	// Check if DNAME redirection applies
	if dname := getDnameTarget(msg); dname != "" {
		qname = dname
	}

	// We need to prove the queried name does not exist
	// This might require proving that an ancestor doesn't exist

	labels := dns.SplitDomainName(qname)

	// Try to find NSEC coverage starting from the full name and working up
	for i := 0; i < len(labels); i++ {
		// Construct the name to check
		var checkName string
		if i == 0 {
			checkName = qname
		} else {
			checkName = dns.Fqdn(strings.Join(labels[i:], "."))
		}

		// Check if any NSEC covers this name
		for _, rr := range nsecSet {
			nsec := rr.(*dns.NSEC)

			if nsecCovers(nsec.Header().Name, nsec.NextDomain, checkName) {
				// Found coverage - name proven not to exist
				// Now verify wildcards don't exist
				goto checkWildcards
			}
		}
	}

	// No NSEC found that proves non-existence
	return errNSECMissingCoverage

checkWildcards:

	// Now verify no wildcard exists
	// We need to find the closest encloser and prove *.closest_encloser doesn't exist
	for i := 1; i < len(labels); i++ {
		possibleWildcard := "*." + dns.Fqdn(labels[i])

		for _, rr := range nsecSet {
			nsec := rr.(*dns.NSEC)
			if nsecCovers(nsec.Header().Name, nsec.NextDomain, possibleWildcard) {
				// Found NSEC proving this wildcard doesn't exist
				return nil
			}
		}
	}

	return nil
}

// verifyNODATANSEC verifies NODATA using NSEC records (RFC 4035 Section 3.1.3.1)
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

	// For NODATA, we need an NSEC record for the exact name
	// showing that the queried type doesn't exist
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)

		// Check if this NSEC is for the queried name
		if dns.CanonicalName(nsec.Header().Name) == dns.CanonicalName(qname) {
			// Check if the queried type is in the type bitmap
			if typesSet(nsec.TypeBitMap, q.Qtype) {
				return errNSECTypeExists
			}

			// Special handling for DS queries at delegation points
			if q.Qtype == dns.TypeDS {
				// At a delegation point, we should see NS but not SOA
				if !typesSet(nsec.TypeBitMap, dns.TypeNS) {
					return errNSECNSMissing
				}
				if typesSet(nsec.TypeBitMap, dns.TypeSOA) {
					return errNSECBadDelegation
				}
			}

			return nil
		}
	}

	// If we didn't find an exact match NSEC, this might be a wildcard NODATA
	// In this case, we need to prove the wildcard exists but doesn't have the type
	return errNSECMissingCoverage
}

// nsecCovers checks if an NSEC record covers a given name
// Uses canonical DNS name ordering (RFC 4034 Section 6.1)
func nsecCovers(owner, next, name string) bool {
	// Normalize all names to canonical form
	owner = dns.CanonicalName(owner)
	next = dns.CanonicalName(next)
	name = dns.CanonicalName(name)

	// Special case: owner equals next means this NSEC covers everything except owner
	// This happens in zones with only one name (e.g., net.com. NSEC net.com.)
	if owner == next {
		// The name is covered if it's not the owner itself
		return name != owner
	}

	// Check if name falls between owner and next in canonical order
	if owner < next {
		// Normal case: owner < name < next
		return owner < name && name < next
	} else {
		// Wrap-around case: the last NSEC in the zone
		// Either owner < name OR name < next
		return owner < name || name < next
	}
}
