package dnssec

import (
	"fmt"
	"sort"
	"strings"

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

// nsec3Safe reports whether an NSEC3 RR uses the only standardized hash
// algorithm and is within the iteration cap. Keeping the check at the RR
// level (rather than rejecting the whole RRset) lets a zone that mixes safe
// and unusable records still validate through the usable ones. Unsupported
// algorithms are skipped before work accounting because HashName performs no
// cryptographic work for them.
func nsec3Safe(n *dns.NSEC3) bool {
	return n.Hash == dns.SHA1 && n.Iterations <= maxNSEC3Iterations
}

type nsec3Predicate func(*dns.NSEC3, string) bool

func normalizeNSEC3Set(records []dns.RR) []dns.RR {
	type keyedRecord struct {
		key string
		rr  dns.RR
	}
	seen := make(map[string]struct{}, len(records))
	normalized := make([]keyedRecord, 0, len(records))
	for _, record := range records {
		nsec3, ok := record.(*dns.NSEC3)
		if !ok || nsec3 == nil {
			continue
		}
		types := append([]uint16(nil), nsec3.TypeBitMap...)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		key := fmt.Sprintf(
			"%s|%d|%d|%d|%d|%s|%s|%v",
			strings.ToLower(dns.Fqdn(nsec3.Header().Name)),
			nsec3.Header().Class,
			nsec3.Hash,
			nsec3.Flags,
			nsec3.Iterations,
			strings.ToUpper(nsec3.Salt),
			strings.ToUpper(nsec3.NextDomain),
			types,
		)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, keyedRecord{key: key, rr: nsec3})
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].key < normalized[j].key
	})
	result := make([]dns.RR, len(normalized))
	for i := range normalized {
		result[i] = normalized[i].rr
	}
	return result
}

type nsec3Operation struct {
	predicate nsec3Predicate
	work      NSEC3Work
}

func (op nsec3Operation) run(n *dns.NSEC3, name string) (bool, error) {
	if op.work == nil {
		return op.predicate(n, name), nil
	}
	release, err := op.work.BeginNSEC3Hash()
	if err != nil {
		return false, wrapWorkError(err)
	}
	if release != nil {
		defer release()
	}
	return op.predicate(n, name), nil
}

// nsec3CoversWithWork reports strict NSEC3 interval coverage. An exact owner
// match proves that the name exists and therefore must never be accepted as a
// denial-of-existence cover, even if the DNS library's Cover method includes
// the owner boundary for an ordinary interval.
func nsec3CoversWithWork(
	n *dns.NSEC3,
	name string,
	match nsec3Operation,
	cover nsec3Operation,
) (bool, error) {
	exact, err := match.run(n, name)
	if err != nil || exact {
		return false, err
	}
	return cover.run(n, name)
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
	return findClosestEncloserWith(name, nsec, (*dns.NSEC3).Match)
}

func findClosestEncloserWith(name string, nsec []dns.RR, match nsec3Predicate) (string, string) {
	ce, nc, _ := findClosestEncloserWithWork(
		name,
		nsec,
		nsec3Operation{predicate: match},
	)
	return ce, nc
}

func findClosestEncloserWithWork(
	name string,
	nsec []dns.RR,
	match nsec3Operation,
) (string, string, error) {
	labelIndices := dns.Split(name)
	nc := name

	// RFC 5155 Section 7.2.1: Start from the full name and work up
	for i := 0; i < len(labelIndices); i++ {
		z := name[labelIndices[i]:]

		// Check if this ancestor has a matching NSEC3
		_, err := findMatchingWithWork(z, nsec, match)
		if err != nil {
			if err != ErrNSECMissingCoverage {
				return "", "", err
			}
			continue
		}

		// Found a matching NSEC3 for this ancestor
		if i != 0 {
			nc = name[labelIndices[i-1]:]
		}

		// Return the closest encloser and next closer name
		// The actual verification of next closer coverage happens in VerifyNameError
		return z, nc, nil
	}
	return "", "", nil
}

func findMatching(name string, nsec []dns.RR) ([]uint16, error) {
	return findMatchingWith(name, nsec, (*dns.NSEC3).Match)
}

func findMatchingWith(name string, nsec []dns.RR, match nsec3Predicate) ([]uint16, error) {
	return findMatchingWithWork(name, nsec, nsec3Operation{predicate: match})
}

func findMatchingWithWork(
	name string,
	nsec []dns.RR,
	match nsec3Operation,
) ([]uint16, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		matched, err := match.run(n, name)
		if err != nil {
			return nil, err
		}
		if matched {
			return n.TypeBitMap, nil
		}
	}
	return nil, ErrNSECMissingCoverage
}

func findCovererWithWork(
	name string,
	nsec []dns.RR,
	match nsec3Operation,
	cover nsec3Operation,
) ([]uint16, bool, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if !nsec3Safe(n) {
			continue
		}
		covered, err := nsec3CoversWithWork(n, name, match, cover)
		if err != nil {
			return nil, false, err
		}
		if covered {
			return n.TypeBitMap, (n.Flags & 1) == 1, nil
		}
	}
	return nil, false, ErrNSECMissingCoverage
}

// VerifyNameError verifies an NXDOMAIN proof using NSEC3 records (RFC
// 5155 §8.4): closest encloser exists, an NSEC3 covers the next closer
// name, and an NSEC3 covers the wildcard at the closest encloser.
func VerifyNameError(msg *dns.Msg, nsec []dns.RR) error {
	return VerifyNameErrorWithWork(msg, nsec, nil)
}

// VerifyNameErrorWithWork is VerifyNameError with request-tree work
// accounting and the resolver-wide crypto semaphore enabled.
func VerifyNameErrorWithWork(msg *dns.Msg, nsec []dns.RR, work NSEC3Work) error {
	return verifyNameErrorWithOperations(
		msg,
		nsec,
		nsec3Operation{predicate: (*dns.NSEC3).Match, work: work},
		nsec3Operation{predicate: (*dns.NSEC3).Cover, work: work},
	)
}

// verifyNameErrorWith is VerifyNameError with injectable NSEC3 hash-backed
// match/cover operations. It keeps production behaviour unchanged while
// allowing bounded-work tests to count every hash operation actually reached.
func verifyNameErrorWith(
	msg *dns.Msg,
	nsec []dns.RR,
	match nsec3Predicate,
	cover nsec3Predicate,
) error {
	return verifyNameErrorWithOperations(
		msg,
		nsec,
		nsec3Operation{predicate: match},
		nsec3Operation{predicate: cover},
	)
}

func verifyNameErrorWithOperations(
	msg *dns.Msg,
	nsec []dns.RR,
	match nsec3Operation,
	cover nsec3Operation,
) error {
	nsec = normalizeNSEC3Set(nsec)
	q := msg.Question[0]
	qname := q.Name

	if dname := dnsutil.DnameTarget(msg); dname != "" {
		qname = dname
	}

	ce, nc, err := findClosestEncloserWithWork(qname, nsec, match)
	if err != nil {
		return err
	}
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
	if _, _, err := findCovererWithWork(nc, nsec, match, cover); err != nil {
		return err
	}
	if _, _, err := findCovererWithWork("*."+ce, nsec, match, cover); err != nil {
		return err
	}
	return nil
}

// VerifyNODATA verifies a NODATA proof using NSEC3 records (RFC 5155
// §8.5–§8.7), including the DS-specific opt-out branch.
func VerifyNODATA(msg *dns.Msg, nsec []dns.RR) error {
	return VerifyNODATAWithWork(msg, nsec, nil)
}

// VerifyNODATAWithWork is VerifyNODATA with request-tree work accounting and
// the resolver-wide crypto semaphore enabled.
func VerifyNODATAWithWork(msg *dns.Msg, nsec []dns.RR, work NSEC3Work) error {
	nsec = normalizeNSEC3Set(nsec)
	match := nsec3Operation{predicate: (*dns.NSEC3).Match, work: work}
	cover := nsec3Operation{predicate: (*dns.NSEC3).Cover, work: work}
	q := msg.Question[0]
	qname := q.Name

	if dname := dnsutil.DnameTarget(msg); dname != "" {
		qname = dname
	}

	if types, err := findMatchingWithWork(qname, nsec, match); err == nil {
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
	} else if err != ErrNSECMissingCoverage {
		return err
	}

	// No exact match — two valid cases remain.
	ce, nc, err := findClosestEncloserWithWork(qname, nsec, match)
	if err != nil {
		return err
	}
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
		_, optOut, err := findCovererWithWork(nc, nsec, match, cover)
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
	if _, _, err := findCovererWithWork(nc, nsec, match, cover); err != nil {
		return err
	}
	wildcardTypes, err := findMatchingWithWork("*."+ce, nsec, match)
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
	return VerifyDelegationWithWork(delegation, nsec, nil)
}

// VerifyDelegationWithWork is VerifyDelegation with request-tree work
// accounting and the resolver-wide crypto semaphore enabled.
func VerifyDelegationWithWork(delegation string, nsec []dns.RR, work NSEC3Work) error {
	nsec = normalizeNSEC3Set(nsec)
	match := nsec3Operation{predicate: (*dns.NSEC3).Match, work: work}
	cover := nsec3Operation{predicate: (*dns.NSEC3).Cover, work: work}
	types, err := findMatchingWithWork(delegation, nsec, match)
	if err != nil {
		if err != ErrNSECMissingCoverage {
			return err
		}
		ce, nc, findErr := findClosestEncloserWithWork(delegation, nsec, match)
		if findErr != nil {
			return findErr
		}
		if ce == "" {
			return ErrNSECMissingCoverage
		}
		_, optOut, err := findCovererWithWork(nc, nsec, match, cover)
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
