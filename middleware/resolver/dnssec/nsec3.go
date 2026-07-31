package dnssec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// maxNSEC3Iterations caps the hash-iteration count this validator is
// willing to process. RFC 9276 recommends iterations=0 and permits validators
// to treat higher values as insecure or return SERVFAIL; this implementation
// retains its established fail-closed interoperability ceiling of 150.
// An NSEC3 advertising e.g. 65535 iterations costs O(iterations ×
// labels) SHA-1 rounds per name tested. The ring below removes the former
// record-count multiplier, but a validator must still hash the ancestor chain;
// the cap bounds that remaining attacker-controlled asymmetry. Records above
// the cap are skipped and the proof fails via ErrNSECMissingCoverage, matching
// the established fail-closed side of RFC 9276's insecure/SERVFAIL choice.
const maxNSEC3Iterations = 150

// nsec3Safe reports whether an NSEC3 RR uses the only standardized hash
// algorithm and is within the iteration cap. Keeping the check at the RR
// level (rather than rejecting the whole RRset) lets a zone that mixes safe
// and unusable records still validate through the usable ones. Unsupported
// algorithms are skipped before work accounting, so no cryptographic work is
// attempted for them.
func nsec3Safe(n *dns.NSEC3) bool {
	return n != nil &&
		n.Hash == dns.SHA1 &&
		n.Iterations <= maxNSEC3Iterations &&
		(n.Flags == 0 || n.Flags == 1)
}

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
		key := nsec3IdentityKey(nsec3, types)
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

func nsec3IdentityKey(nsec3 *dns.NSEC3, sortedTypes []uint16) string {
	canonicalOwner, err := newAggressiveCanonicalName(nsec3.Header().Name)
	owner := canonicalOwner.wire
	if err != nil {
		owner = []byte(dns.Fqdn(nsec3.Header().Name))
	}
	salt := strings.ToUpper(nsec3.Salt)
	nextDomain := strings.ToUpper(nsec3.NextDomain)
	key := make([]byte, 0, len(owner)+len(salt)+len(nextDomain)+9+2*len(sortedTypes))

	// NUL separators are unambiguous for valid textual DNS names and NSEC3's
	// hexadecimal/base32 fields. Fixed-width integers preserve the existing
	// owner/class/hash/flags ordering without reflection-based formatting.
	key = append(key, owner...)
	key = append(key, 0)
	key = appendUint16(key, nsec3.Header().Class)
	key = append(key, nsec3.Hash, nsec3.Flags)
	key = appendUint16(key, nsec3.Iterations)
	key = append(key, salt...)
	key = append(key, 0)
	key = append(key, nextDomain...)
	key = append(key, 0)
	for _, rrtype := range sortedTypes {
		key = appendUint16(key, rrtype)
	}
	return string(key)
}

func appendUint16(dst []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(dst, encoded[:]...)
}

type nsec3RingEntry struct {
	rr        *dns.NSEC3
	ownerHash []byte
	nextHash  []byte
}

// preparedNSEC3Set is one immutable NSEC3 ring. The complete key is
// (canonical signer zone, class, algorithm, iterations, decoded salt).
// Entries are sorted by owner hash, so exact matches use binary search; cover
// selection scans only byte intervals to detect overlaps and never re-hashes
// once per record.
type preparedNSEC3Set struct {
	zone       aggressiveCanonicalName
	qclass     uint16
	parameters aggressiveNSEC3Parameters
	entries    []nsec3RingEntry
}

// prepareNSEC3Set binds every usable record to one signer zone and one
// (algorithm, iterations, salt) chain before semantic validation starts.
// RFC 5155 §7.2 requires all NSEC3 RRs in one response to use the same
// parameter tuple, even when multiple valid chains coexist in the zone. Its
// §8.2 explicitly permits a validator to treat a mixed-parameter response as
// bogus. This implementation deliberately takes that fail-closed option
// rather than choosing a chain or risking closest-encloser, next-closer, and
// wildcard witnesses being assembled across chains. Binding owners to the
// exact RRSIG signer also excludes an extra label below the signer zone.
func prepareNSEC3Set(records []dns.RR, signer string) (preparedNSEC3Set, error) {
	normalized := normalizeNSEC3Set(records)
	var (
		result     preparedNSEC3Set
		parameters aggressiveNSEC3Parameters
		haveParams bool
		haveClass  bool
	)
	if signer != "" {
		zone, err := newAggressiveCanonicalName(signer)
		if err != nil {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		result.zone = zone
	}

	owners := make(map[string]string, len(normalized))
	for _, rr := range normalized {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok || !nsec3Safe(nsec3) {
			// RFC 5155 §8.1-8.2 requires unknown algorithms and
			// undefined flags to be ignored, without charging hash work.
			continue
		}
		if nsec3.Header().Rrtype != dns.TypeNSEC3 ||
			nsec3.Header().Class == 0 {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		if !haveClass {
			result.qclass = nsec3.Header().Class
			haveClass = true
		} else if nsec3.Header().Class != result.qclass {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		owner, err := newAggressiveCanonicalName(nsec3.Header().Name)
		if err != nil || len(owner.labels) < 1 {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		if signer == "" && len(result.zone.wire) == 0 {
			result.zone = owner.suffix(len(owner.labels) - 1)
		}
		if len(owner.labels) != len(result.zone.labels)+1 ||
			!owner.isSubdomainOf(result.zone) {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		ownerHash, err := decodeAggressiveNSEC3Hash(owner.labels[0])
		if err != nil || int(nsec3.HashLength) != len(ownerHash) {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		nextHash, err := decodeAggressiveNSEC3Hash([]byte(nsec3.NextDomain))
		if err != nil {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		salt, err := hex.DecodeString(nsec3.Salt)
		if err != nil || len(salt) != int(nsec3.SaltLength) {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		current := aggressiveNSEC3Parameters{
			hash:       nsec3.Hash,
			iterations: nsec3.Iterations,
			salt:       salt,
		}
		if !haveParams {
			parameters = current
			haveParams = true
		} else if current.hash != parameters.hash ||
			current.iterations != parameters.iterations ||
			!bytes.Equal(current.salt, parameters.salt) {
			// Deliberately reject the whole non-conforming response under
			// RFC 5155 §7.2 and the validator option in §8.2. A server with
			// multiple chains must select one homogeneous chain to serve.
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}

		// normalizeNSEC3Set has already removed semantic duplicates.
		// Two remaining records at one hash owner are a detectable chain
		// collision/conflict and cannot safely participate in a proof.
		hashKey := string(ownerHash)
		types := append([]uint16(nil), nsec3.TypeBitMap...)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		identity := nsec3IdentityKey(
			nsec3,
			types,
		)
		if previous, exists := owners[hashKey]; exists && previous != identity {
			return preparedNSEC3Set{}, ErrNSECMissingCoverage
		}
		owners[hashKey] = identity
		result.entries = append(result.entries, nsec3RingEntry{
			rr:        nsec3,
			ownerHash: ownerHash,
			nextHash:  nextHash,
		})
	}
	if !haveParams || !haveClass || len(result.entries) == 0 {
		return preparedNSEC3Set{}, ErrNSECMissingCoverage
	}
	result.parameters = parameters
	sort.Slice(result.entries, func(i, j int) bool {
		return bytes.Compare(
			result.entries[i].ownerHash,
			result.entries[j].ownerHash,
		) < 0
	})
	return result, nil
}

type nsec3RingEvaluator struct {
	ring   preparedNSEC3Set
	work   NSEC3Work
	hashes map[string][]byte
}

func newNSEC3RingEvaluator(
	ring preparedNSEC3Set,
	work NSEC3Work,
) *nsec3RingEvaluator {
	return &nsec3RingEvaluator{
		ring:   ring,
		work:   work,
		hashes: make(map[string][]byte),
	}
}

func (e *nsec3RingEvaluator) hash(name string) ([]byte, error) {
	canonical, err := newAggressiveCanonicalName(name)
	if err != nil || !canonical.isSubdomainOf(e.ring.zone) {
		return nil, ErrNSECMissingCoverage
	}
	localKey := string(canonical.wire)
	if value, ok := e.hashes[localKey]; ok {
		return value, nil
	}

	compute := func() ([]byte, error) {
		if e.work != nil {
			release, workErr := e.work.BeginNSEC3Hash()
			if workErr != nil {
				return nil, wrapWorkError(workErr)
			}
			if release != nil {
				defer release()
			}
		}
		return calculateAggressiveNSEC3Hash(canonical, e.ring.parameters), nil
	}
	value, err := nsec3HashWithMemo(
		e.work,
		aggressiveNSEC3HashMemoKey(
			canonical,
			e.ring.zone,
			e.ring.qclass,
			e.ring.parameters,
		),
		compute,
	)
	if err != nil {
		return nil, err
	}
	e.hashes[localKey] = value
	return value, nil
}

// lookup returns the unique exact match or strict covering interval. A
// selected overlap, or a match that is simultaneously covered by another
// interval, is ambiguous and must never become denial proof material.
func (e *nsec3RingEvaluator) lookup(
	name string,
) (match, cover *nsec3RingEntry, err error) {
	value, err := e.hash(name)
	if err != nil {
		return nil, nil, err
	}
	index := sort.Search(len(e.ring.entries), func(i int) bool {
		return bytes.Compare(e.ring.entries[i].ownerHash, value) >= 0
	})
	if index < len(e.ring.entries) &&
		bytes.Equal(e.ring.entries[index].ownerHash, value) {
		match = &e.ring.entries[index]
	}

	for i := range e.ring.entries {
		entry := &e.ring.entries[i]
		if bytes.Equal(entry.ownerHash, value) ||
			!aggressiveNSEC3Covers(&aggressiveNSEC3Entry{
				rr:        entry.rr,
				ownerHash: entry.ownerHash,
				nextHash:  entry.nextHash,
			}, value) {
			continue
		}
		if cover != nil {
			return nil, nil, ErrNSECMissingCoverage
		}
		cover = entry
	}
	if match != nil && cover != nil {
		return nil, nil, ErrNSECMissingCoverage
	}
	return match, cover, nil
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
	prepared, err := prepareNSEC3Set(nsec, "")
	if err != nil {
		return "", ""
	}
	proof, _ := findClosestEncloserWithWork(
		name,
		newNSEC3RingEvaluator(prepared, nil),
	)
	return proof.name, proof.nextCloser
}

type nsec3ClosestEncloserProof struct {
	name       string
	nextCloser string
	types      []uint16
}

func findClosestEncloserWithWork(
	name string,
	evaluator *nsec3RingEvaluator,
) (nsec3ClosestEncloserProof, error) {
	labelIndices := dns.Split(name)
	nc := name

	// RFC 5155 Section 7.2.1: Start from the full name and work up
	for i := 0; i < len(labelIndices); i++ {
		z := name[labelIndices[i]:]

		// Check if this ancestor has a matching NSEC3
		types, err := findMatchingWithWork(z, evaluator)
		if err != nil {
			if err != ErrNSECMissingCoverage {
				return nsec3ClosestEncloserProof{}, err
			}
			continue
		}

		// Found a matching NSEC3 for this ancestor
		if i != 0 {
			nc = name[labelIndices[i-1]:]
		}

		// Return the closest encloser and next closer name
		// The actual verification of next closer coverage happens in VerifyNameError
		return nsec3ClosestEncloserProof{
			name:       z,
			nextCloser: nc,
			types:      types,
		}, nil
	}
	return nsec3ClosestEncloserProof{}, nil
}

func validateNSEC3ClosestEncloser(proof nsec3ClosestEncloserProof) error {
	if proof.name == "" {
		return ErrNSECMissingCoverage
	}
	if typesSet(proof.types, dns.TypeDNAME) ||
		(typesSet(proof.types, dns.TypeNS) &&
			!typesSet(proof.types, dns.TypeSOA)) {
		return ErrNSECBadDelegation
	}
	return nil
}

func findMatching(name string, nsec []dns.RR) ([]uint16, error) {
	prepared, err := prepareNSEC3Set(nsec, "")
	if err != nil {
		return nil, err
	}
	return findMatchingWithWork(name, newNSEC3RingEvaluator(prepared, nil))
}

func findMatchingWithWork(
	name string,
	evaluator *nsec3RingEvaluator,
) ([]uint16, error) {
	match, _, err := evaluator.lookup(name)
	if err != nil {
		return nil, err
	}
	if match != nil {
		return match.rr.TypeBitMap, nil
	}
	return nil, ErrNSECMissingCoverage
}

func findCovererWithWork(
	name string,
	evaluator *nsec3RingEvaluator,
) ([]uint16, bool, error) {
	_, cover, err := evaluator.lookup(name)
	if err != nil {
		return nil, false, err
	}
	if cover != nil {
		return cover.rr.TypeBitMap, (cover.rr.Flags & 1) == 1, nil
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
	_, err := VerifyNameErrorForZoneWithWork(msg, nsec, "", work)
	return err
}

// VerifyNameErrorForZoneWithWork validates an NSEC3 NXDOMAIN proof against
// the exact RRSIG signer zone. secure is false only when a required covering
// interval has Opt-Out set; the response remains usable as insecure data but
// MUST NOT carry AD or seed shared aggressive denial state.
func VerifyNameErrorForZoneWithWork(
	msg *dns.Msg,
	nsec []dns.RR,
	signer string,
	work NSEC3Work,
) (secure bool, err error) {
	prepared, err := prepareNSEC3Set(nsec, signer)
	if err != nil {
		return false, err
	}
	if prepared.qclass != msg.Question[0].Qclass {
		return false, ErrNSECMissingCoverage
	}
	return verifyNameErrorWithRing(
		msg,
		newNSEC3RingEvaluator(prepared, work),
	)
}

func verifyNameErrorWithRing(
	msg *dns.Msg,
	evaluator *nsec3RingEvaluator,
) (bool, error) {
	q := msg.Question[0]
	qname := q.Name

	if dname := dnsutil.DnameTarget(msg); dname != "" {
		qname = dname
	}

	closest, err := findClosestEncloserWithWork(qname, evaluator)
	if err != nil {
		return false, err
	}
	if err := validateNSEC3ClosestEncloser(closest); err != nil {
		return false, err
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
	_, nextOptOut, err := findCovererWithWork(
		closest.nextCloser,
		evaluator,
	)
	if err != nil {
		return false, err
	}
	_, _, err = findCovererWithWork(
		"*."+closest.name,
		evaluator,
	)
	if err != nil {
		return false, err
	}
	// RFC 5155 §9.2 ties AD specifically to the closest-encloser proof's
	// next-closer cover. The wildcard cover is still mandatory for NXDOMAIN,
	// while its Opt-Out bit alone does not make the response insecure.
	return !nextOptOut, nil
}

// VerifyNODATA verifies a NODATA proof using NSEC3 records (RFC 5155
// §8.5–§8.7), including the DS-specific opt-out branch.
func VerifyNODATA(msg *dns.Msg, nsec []dns.RR) error {
	return VerifyNODATAWithWork(msg, nsec, nil)
}

// VerifyNODATAWithWork is VerifyNODATA with request-tree work accounting and
// the resolver-wide crypto semaphore enabled.
func VerifyNODATAWithWork(msg *dns.Msg, nsec []dns.RR, work NSEC3Work) error {
	_, err := VerifyNODATAForZoneWithWork(msg, nsec, "", work)
	return err
}

// VerifyNODATAForZoneWithWork is the signer-bound form of
// VerifyNODATAWithWork. secure follows RFC 5155 §9.2: an Opt-Out
// next-closer proof is accepted only with AD cleared.
func VerifyNODATAForZoneWithWork(
	msg *dns.Msg,
	nsec []dns.RR,
	signer string,
	work NSEC3Work,
) (secure bool, err error) {
	prepared, err := prepareNSEC3Set(nsec, signer)
	if err != nil {
		return false, err
	}
	q := msg.Question[0]
	if prepared.qclass != q.Qclass {
		return false, ErrNSECMissingCoverage
	}
	evaluator := newNSEC3RingEvaluator(prepared, work)
	qname := q.Name

	if dname := dnsutil.DnameTarget(msg); dname != "" {
		qname = dname
	}

	if types, err := findMatchingWithWork(qname, evaluator); err == nil {
		// Exact-owner NODATA (RFC 5155 §8.5).
		if typesSet(types, q.Qtype, dns.TypeCNAME) {
			return false, ErrNSECTypeExists
		}
		// DS queries are only authoritative in the parent zone. An
		// exact-match NSEC3 whose bitmap contains SOA is the child-
		// zone apex and cannot prove DS non-existence at the
		// delegation point; mirrors the same SOA rejection
		// VerifyNODATANSEC performs so a child-signed denial can't
		// masquerade as a parent-side proof.
		if q.Qtype == dns.TypeDS && typesSet(types, dns.TypeSOA) {
			return false, ErrNSECBadDelegation
		}
		return true, nil
	} else if err != ErrNSECMissingCoverage {
		return false, err
	}

	// No exact match — two valid cases remain.
	closest, err := findClosestEncloserWithWork(qname, evaluator)
	if err != nil {
		return false, err
	}
	if err := validateNSEC3ClosestEncloser(closest); err != nil {
		return false, err
	}

	if q.Qtype == dns.TypeDS {
		// RFC 5155 §8.6: DS NODATA without exact match requires an
		// NSEC3 covering the next closer name with the Opt-Out bit
		// set. Without that bit the proof cannot distinguish "DS
		// absent" from "DS unsigned because this delegation was
		// opted out" — accepting a non-opt-out cover would let a
		// signed child be silently demoted to insecure during
		// findDS chain walks.
		_, optOut, err := findCovererWithWork(
			closest.nextCloser,
			evaluator,
		)
		if err != nil {
			return false, err
		}
		if !optOut {
			return false, ErrNSECOptOut
		}
		return false, nil
	}

	// RFC 5155 §8.7: wildcard NODATA proof —
	//   1. An NSEC3 covers the next closer name (qname has no
	//      direct match below the closest encloser).
	//   2. An NSEC3 matches the wildcard at the closest encloser
	//      and its type bitmap does not contain qtype or CNAME.
	_, optOut, err := findCovererWithWork(
		closest.nextCloser,
		evaluator,
	)
	if err != nil {
		return false, err
	}
	wildcardTypes, err := findMatchingWithWork("*."+closest.name, evaluator)
	if err != nil {
		return false, err
	}
	if typesSet(wildcardTypes, q.Qtype, dns.TypeCNAME) {
		return false, ErrNSECTypeExists
	}
	return !optOut, nil
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
	return VerifyDelegationForZoneWithWork(delegation, "", nsec, work)
}

// VerifyDelegationForZoneWithWork binds an insecure-delegation proof to the
// parent signer before evaluating exact-match or Opt-Out semantics.
func VerifyDelegationForZoneWithWork(
	delegation string,
	signer string,
	nsec []dns.RR,
	work NSEC3Work,
) error {
	prepared, err := prepareNSEC3Set(nsec, signer)
	if err != nil {
		return err
	}
	evaluator := newNSEC3RingEvaluator(prepared, work)
	types, err := findMatchingWithWork(delegation, evaluator)
	if err != nil {
		if err != ErrNSECMissingCoverage {
			return err
		}
		closest, findErr := findClosestEncloserWithWork(delegation, evaluator)
		if findErr != nil {
			return findErr
		}
		if err := validateNSEC3ClosestEncloser(closest); err != nil {
			return err
		}
		_, optOut, err := findCovererWithWork(
			closest.nextCloser,
			evaluator,
		)
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
