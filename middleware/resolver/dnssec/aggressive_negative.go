package dnssec

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 5155 fixes the NSEC3 digest size to SHA-1.
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// AggressiveNegativeResult is a DNSSEC proof that can synthesize either an
// NXDOMAIN response or a NOERROR/NODATA response. Proof contains only the
// input NSEC or NSEC3 records needed for that conclusion; callers add the
// independently validated SOA and matching RRSIG RRsets when constructing
// the wire response.
type AggressiveNegativeResult struct {
	Rcode int
	Proof []dns.RR
}

// EvaluateAggressiveNSEC evaluates DNSSEC-validated NSEC records for
// aggressive negative caching as described by RFC 8198. The caller remains
// responsible for establishing the records' cryptographic provenance and
// lifetime. Any incomplete, inconsistent, or inapplicable proof returns an
// error so the caller can fall back to ordinary resolution.
func EvaluateAggressiveNSEC(
	q dns.Question,
	zone string,
	records []dns.RR,
) (AggressiveNegativeResult, error) {
	qname, signer, err := validateAggressiveQuestion(q, zone)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	entries, err := newAggressiveNSECEntries(records, q.Qclass, signer)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	return evaluateAggressiveNSECEntries(q, qname, signer, entries)
}

// PreparedNSEC is an NSEC record whose owner and next-domain names are
// already in canonical form.
//
// Canonicalizing a name allocates, and it is a pure function of the record,
// so a caller holding NSEC records across many queries, a denial-proof
// cache is why this exists, can pay for it once when the record is
// admitted instead of on every evaluation. The canonical form is immutable
// once built and may be shared by concurrent evaluations.
type PreparedNSEC struct {
	entry aggressiveNSECEntry
}

// PrepareAggressiveNSEC canonicalizes rr's names for later evaluation. The
// result keeps rr itself, which the evaluator hands back in its proof, so
// the caller must not mutate the record afterwards.
func PrepareAggressiveNSEC(rr *dns.NSEC) (PreparedNSEC, error) {
	if rr == nil || rr.Header().Rrtype != dns.TypeNSEC {
		return PreparedNSEC{}, aggressiveFallback("record is not an NSEC")
	}
	owner, err := newAggressiveCanonicalName(rr.Header().Name)
	if err != nil {
		return PreparedNSEC{}, err
	}
	next, err := newAggressiveCanonicalName(rr.NextDomain)
	if err != nil {
		return PreparedNSEC{}, err
	}
	// These are held for the record's whole time in the cache, so they are
	// sized down rather than left as views into a 255-octet scratch buffer.
	return PreparedNSEC{
		entry: aggressiveNSECEntry{
			rr:    rr,
			owner: owner.compact(),
			next:  next.compact(),
		},
	}, nil
}

// EvaluateAggressiveNSECPrepared is EvaluateAggressiveNSEC over records
// canonicalized ahead of time by PrepareAggressiveNSEC. It applies the same
// set-level validation and reaches the same verdict; only the per-record
// canonicalization is already paid for.
func EvaluateAggressiveNSECPrepared(
	q dns.Question,
	zone string,
	prepared []PreparedNSEC,
) (AggressiveNegativeResult, error) {
	qname, signer, err := validateAggressiveQuestion(q, zone)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	entries, err := aggressiveNSECEntriesFromPrepared(prepared, q.Qclass, signer)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	return evaluateAggressiveNSECEntries(q, qname, signer, entries)
}

// AggressiveNSECSet is a prepared NSEC collection whose set-level invariants,
// class homogeneity, signer containment, interval conflicts, were checked
// once at construction. Those checks are static properties of the stored
// set; re-running them per query rebuilt the entry slice on every negative
// answer, which was the resolver's single largest allocator under
// NXDOMAIN-heavy load.
type AggressiveNSECSet struct {
	entries []aggressiveNSECEntry
	signer  aggressiveCanonicalName
	qclass  uint16
}

// NewAggressiveNSECSet validates prepared as one aggressive-answer set for
// zone. The checks are exactly EvaluateAggressiveNSECPrepared's set-level
// checks, a set rejected here would be rejected on every evaluation.
func NewAggressiveNSECSet(prepared []PreparedNSEC, zone string) (*AggressiveNSECSet, error) {
	if len(prepared) == 0 {
		return nil, ErrNSECMissingCoverage
	}
	signer, err := newAggressiveCanonicalName(zone)
	if err != nil {
		return nil, err
	}
	first := prepared[0].entry.rr
	if first == nil {
		return nil, aggressiveFallback("NSEC set is not homogeneous")
	}
	qclass := first.Header().Class
	entries, err := aggressiveNSECEntriesFromPrepared(prepared, qclass, signer)
	if err != nil {
		return nil, err
	}
	return &AggressiveNSECSet{entries: entries, signer: signer, qclass: qclass}, nil
}

// EvaluateAggressiveNSECSet is EvaluateAggressiveNSECPrepared over a
// pre-validated set: per query only the question is canonicalized and
// classified; the entry table is used as stored.
func EvaluateAggressiveNSECSet(
	q dns.Question,
	set *AggressiveNSECSet,
) (AggressiveNegativeResult, error) {
	if set == nil || len(set.entries) == 0 {
		return AggressiveNegativeResult{}, ErrNSECMissingCoverage
	}
	qname, err := validateAggressiveQuestionSigner(q, set.signer)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	if q.Qclass != set.qclass {
		// The stored records' class is uniform; a query in another class
		// fails the same homogeneity check the per-query path applies.
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC set is not homogeneous")
	}
	return evaluateAggressiveNSECEntries(q, qname, set.signer, set.entries)
}

func evaluateAggressiveNSECEntries(
	q dns.Question,
	qname aggressiveCanonicalName,
	signer aggressiveCanonicalName,
	entries []aggressiveNSECEntry,
) (AggressiveNegativeResult, error) {
	qproof, err := classifyAggressiveNSECName(qname, entries)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	switch qproof.state {
	case aggressiveNameExact:
		if !aggressiveNODATAType(q.Qtype) {
			return AggressiveNegativeResult{}, aggressiveFallback("query type cannot synthesize NODATA")
		}
		if err := validateAggressiveExactNODATA(q.Qtype, qproof.nsec.TypeBitMap); err != nil {
			return AggressiveNegativeResult{}, err
		}
		return AggressiveNegativeResult{
			Rcode: dns.RcodeSuccess,
			Proof: []dns.RR{qproof.nsec},
		}, nil

	case aggressiveNameENT:
		if !aggressiveNODATAType(q.Qtype) {
			return AggressiveNegativeResult{}, aggressiveFallback("query type cannot synthesize ENT NODATA")
		}
		return AggressiveNegativeResult{
			Rcode: dns.RcodeSuccess,
			Proof: []dns.RR{qproof.nsec},
		}, nil

	case aggressiveNameAbsent:
		// A signed zone apex necessarily exists. Treat a denial of the
		// signer itself as inconsistent rather than manufacturing NXDOMAIN.
		if qname.equal(signer) {
			return AggressiveNegativeResult{}, aggressiveFallback("NSEC denies the signer zone apex")
		}
	default:
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC does not classify the query name")
	}

	closestEncloser, ok := closestEncloserFromAggressiveNSEC(qname, qproof.entry)
	if !ok || !closestEncloser.isSubdomainOf(signer) {
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC closest encloser is unavailable")
	}

	source := closestEncloser.prepend([]byte{'*'})
	sourceProof, err := classifyAggressiveNSECName(source, entries)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	proof := appendAggressiveProof(nil, qproof.nsec)
	switch sourceProof.state {
	case aggressiveNameExact:
		if !aggressiveNODATAType(q.Qtype) || q.Qtype == dns.TypeDS {
			return AggressiveNegativeResult{}, aggressiveFallback("wildcard NODATA is unavailable for the query type")
		}
		if aggressiveDelegationBitmap(sourceProof.nsec.TypeBitMap) ||
			typesSet(sourceProof.nsec.TypeBitMap, dns.TypeDNAME) {
			return AggressiveNegativeResult{}, ErrNSECBadDelegation
		}
		if err := validateAggressiveExactNODATA(q.Qtype, sourceProof.nsec.TypeBitMap); err != nil {
			return AggressiveNegativeResult{}, err
		}
		return AggressiveNegativeResult{
			Rcode: dns.RcodeSuccess,
			Proof: appendAggressiveProof(proof, sourceProof.nsec),
		}, nil

	case aggressiveNameENT:
		if !aggressiveNODATAType(q.Qtype) || q.Qtype == dns.TypeDS {
			return AggressiveNegativeResult{}, aggressiveFallback("wildcard ENT NODATA is unavailable for the query type")
		}
		return AggressiveNegativeResult{
			Rcode: dns.RcodeSuccess,
			Proof: appendAggressiveProof(proof, sourceProof.nsec),
		}, nil

	case aggressiveNameAbsent:
		return AggressiveNegativeResult{
			Rcode: dns.RcodeNameError,
			Proof: appendAggressiveProof(proof, sourceProof.nsec),
		}, nil

	default:
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC does not classify the wildcard source")
	}
}

// EvaluateAggressiveNSEC3 evaluates one homogeneous set of DNSSEC-validated
// NSEC3 records for aggressive negative caching. It implements the
// non-Opt-Out RFC 5155 closest-encloser, name-error, exact NODATA, and
// wildcard NODATA paths. The DS Opt-Out NODATA branch is deliberately not
// synthesized: an Opt-Out covering record always causes a fail-closed
// fallback.
func EvaluateAggressiveNSEC3(
	q dns.Question,
	zone string,
	records []dns.RR,
	work NSEC3Work,
) (AggressiveNegativeResult, error) {
	qname, signer, err := validateAggressiveQuestion(q, zone)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	entries, parameters, err := newAggressiveNSEC3Entries(records, q.Qclass, signer)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	hasher := aggressiveNSEC3Hasher{
		parameters: parameters,
		zone:       signer,
		qclass:     q.Qclass,
		work:       work,
		hashes:     make(map[string][]byte),
	}

	qhash, err := hasher.hash(qname)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	qmatch, _, err := lookupAggressiveNSEC3(qhash, entries)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	if qmatch != nil {
		if !aggressiveNODATAType(q.Qtype) {
			return AggressiveNegativeResult{}, aggressiveFallback("query type cannot synthesize NSEC3 NODATA")
		}
		if err := validateAggressiveExactNODATA(q.Qtype, qmatch.rr.TypeBitMap); err != nil {
			return AggressiveNegativeResult{}, err
		}
		return AggressiveNegativeResult{
			Rcode: dns.RcodeSuccess,
			Proof: []dns.RR{qmatch.rr},
		}, nil
	}
	if qname.equal(signer) {
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC3 denies the signer zone apex")
	}

	closest, nextCloser, err := findAggressiveNSEC3ClosestEncloser(
		qname,
		signer,
		entries,
		&hasher,
	)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	if typesSet(closest.rr.TypeBitMap, dns.TypeDNAME) ||
		(typesSet(closest.rr.TypeBitMap, dns.TypeNS) &&
			!typesSet(closest.rr.TypeBitMap, dns.TypeSOA)) {
		return AggressiveNegativeResult{}, ErrNSECBadDelegation
	}

	nextHash, err := hasher.hash(nextCloser)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	nextMatch, nextCover, err := lookupAggressiveNSEC3(nextHash, entries)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	if nextMatch != nil || nextCover == nil {
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC3 next-closer cover is unavailable")
	}
	if nextCover.rr.Flags&1 != 0 {
		return AggressiveNegativeResult{}, ErrNSECOptOut
	}

	wildcard := closest.name.prepend([]byte{'*'})
	wildcardHash, err := hasher.hash(wildcard)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}
	wildcardMatch, wildcardCover, err := lookupAggressiveNSEC3(wildcardHash, entries)
	if err != nil {
		return AggressiveNegativeResult{}, err
	}

	proof := appendAggressiveProof(nil, closest.rr)
	proof = appendAggressiveProof(proof, nextCover.rr)
	if wildcardMatch != nil {
		if !aggressiveNODATAType(q.Qtype) || q.Qtype == dns.TypeDS {
			return AggressiveNegativeResult{}, aggressiveFallback("NSEC3 wildcard NODATA is unavailable for the query type")
		}
		if aggressiveDelegationBitmap(wildcardMatch.rr.TypeBitMap) ||
			typesSet(wildcardMatch.rr.TypeBitMap, dns.TypeDNAME) {
			return AggressiveNegativeResult{}, ErrNSECBadDelegation
		}
		if err := validateAggressiveExactNODATA(q.Qtype, wildcardMatch.rr.TypeBitMap); err != nil {
			return AggressiveNegativeResult{}, err
		}
		return AggressiveNegativeResult{
			Rcode: dns.RcodeSuccess,
			Proof: appendAggressiveProof(proof, wildcardMatch.rr),
		}, nil
	}
	if wildcardCover == nil {
		return AggressiveNegativeResult{}, aggressiveFallback("NSEC3 wildcard cover is unavailable")
	}
	if wildcardCover.rr.Flags&1 != 0 {
		return AggressiveNegativeResult{}, ErrNSECOptOut
	}

	return AggressiveNegativeResult{
		Rcode: dns.RcodeNameError,
		Proof: appendAggressiveProof(proof, wildcardCover.rr),
	}, nil
}

// AggressiveNSEC3Usable is a cheap, record-local preflight for an NSEC3
// candidate. It does not validate the owner name, signer zone, class, salt,
// or tuple homogeneity; EvaluateAggressiveNSEC3 performs those set-level
// checks before using a record.
func AggressiveNSEC3Usable(n *dns.NSEC3) bool {
	return n != nil &&
		n.Hash == dns.SHA1 &&
		n.Iterations <= maxNSEC3Iterations &&
		(n.Flags == 0 || n.Flags == 1)
}

type aggressiveCanonicalName struct {
	labels [][]byte
	wire   []byte
}

func newAggressiveCanonicalName(name string) (aggressiveCanonicalName, error) {
	if name == "" {
		return aggressiveCanonicalName{}, aggressiveFallback("empty domain name")
	}

	// A name's wire form never exceeds its presentation length by more than
	// the root label, and escape sequences only make it shorter, so the text
	// bounds the buffer. The 255-octet ceiling is not merely a cap here:
	// PackDomainName does not enforce the wire-format limit itself, so the
	// buffer is what rejects an over-long name.
	fqdn := dns.Fqdn(name)
	packed := make([]byte, min(len(fqdn)+1, 255))
	end, err := dns.PackDomainName(fqdn, packed, 0, nil, false)
	if err != nil || end == 0 || end > len(packed) {
		return aggressiveCanonicalName{}, aggressiveFallback("invalid domain name")
	}
	packed = packed[:end]

	// Every label but the root is preceded by a separator in the text, so the
	// separator count bounds the label count. Escaped dots only overcount.
	labels := make([][]byte, 0, strings.Count(fqdn, "."))
	for offset := 0; ; {
		if offset >= len(packed) {
			return aggressiveCanonicalName{}, aggressiveFallback("unterminated domain name")
		}
		length := int(packed[offset])
		offset++
		if length == 0 {
			if offset != len(packed) {
				return aggressiveCanonicalName{}, aggressiveFallback("trailing domain-name data")
			}
			break
		}
		if length > 63 || offset+length > len(packed) {
			return aggressiveCanonicalName{}, aggressiveFallback("invalid domain-name label")
		}
		label := packed[offset : offset+length]
		for i, octet := range label {
			if octet >= 'A' && octet <= 'Z' {
				label[i] = octet + ('a' - 'A')
			}
		}
		labels = append(labels, label)
		offset += length
	}

	return aggressiveCanonicalName{labels: labels, wire: packed}, nil
}

func newAggressiveCanonicalNameFromLabels(labels [][]byte) aggressiveCanonicalName {
	wireLength := 1
	for _, label := range labels {
		wireLength += 1 + len(label)
	}
	wire := make([]byte, 0, wireLength)
	copiedLabels := make([][]byte, 0, len(labels))
	for _, label := range labels {
		if len(label) > 63 {
			panic("dnssec: aggressive canonical label exceeds 63 octets")
		}
		copied := append([]byte(nil), label...)
		copiedLabels = append(copiedLabels, copied)
		wire = append(wire, byte(len(copied))) //nolint:gosec // DNS labels are bounded to 63 octets above.
		wire = append(wire, copied...)
	}
	wire = append(wire, 0)
	return aggressiveCanonicalName{labels: copiedLabels, wire: wire}
}

// compact returns an equivalent name sized to what it holds. Construction
// packs into a buffer bounded by the presentation form and keeps a view of
// it, which costs nothing for a name built and dropped inside one evaluation
// but retains the slack for a name kept in a cache entry. Only retained names
// pay the copy.
func (name aggressiveCanonicalName) compact() aggressiveCanonicalName {
	if len(name.wire) == 0 || cap(name.wire) == len(name.wire) {
		return name
	}

	wire := make([]byte, len(name.wire))
	copy(wire, name.wire)

	labels := make([][]byte, len(name.labels))
	offset := 0
	for i, label := range name.labels {
		offset++ // length octet
		labels[i] = wire[offset : offset+len(label)]
		offset += len(label)
	}
	return aggressiveCanonicalName{labels: labels, wire: wire}
}

func (name aggressiveCanonicalName) compare(other aggressiveCanonicalName) int {
	i, j := len(name.labels)-1, len(other.labels)-1
	for i >= 0 && j >= 0 {
		if compared := bytes.Compare(name.labels[i], other.labels[j]); compared != 0 {
			return compared
		}
		i--
		j--
	}
	switch {
	case len(name.labels) < len(other.labels):
		return -1
	case len(name.labels) > len(other.labels):
		return 1
	default:
		return 0
	}
}

func (name aggressiveCanonicalName) equal(other aggressiveCanonicalName) bool {
	return bytes.Equal(name.wire, other.wire)
}

func (name aggressiveCanonicalName) isSubdomainOf(parent aggressiveCanonicalName) bool {
	if len(name.labels) < len(parent.labels) {
		return false
	}
	offset := len(name.labels) - len(parent.labels)
	for i := range parent.labels {
		if !bytes.Equal(name.labels[offset+i], parent.labels[i]) {
			return false
		}
	}
	return true
}

func (name aggressiveCanonicalName) isStrictSubdomainOf(parent aggressiveCanonicalName) bool {
	return len(name.labels) > len(parent.labels) && name.isSubdomainOf(parent)
}

func (name aggressiveCanonicalName) suffix(labelCount int) aggressiveCanonicalName {
	if labelCount == 0 {
		return newAggressiveCanonicalNameFromLabels(nil)
	}
	return newAggressiveCanonicalNameFromLabels(name.labels[len(name.labels)-labelCount:])
}

func (name aggressiveCanonicalName) prepend(label []byte) aggressiveCanonicalName {
	labels := make([][]byte, 0, len(name.labels)+1)
	labels = append(labels, label)
	labels = append(labels, name.labels...)
	return newAggressiveCanonicalNameFromLabels(labels)
}

func validateAggressiveQuestion(
	q dns.Question,
	zone string,
) (aggressiveCanonicalName, aggressiveCanonicalName, error) {
	signer, err := newAggressiveCanonicalName(zone)
	if err != nil {
		return aggressiveCanonicalName{}, aggressiveCanonicalName{}, err
	}
	qname, err := validateAggressiveQuestionSigner(q, signer)
	if err != nil {
		return aggressiveCanonicalName{}, aggressiveCanonicalName{}, err
	}
	return qname, signer, nil
}

// validateAggressiveQuestionSigner is validateAggressiveQuestion for a caller
// that already holds the signer's canonical form.
func validateAggressiveQuestionSigner(
	q dns.Question,
	signer aggressiveCanonicalName,
) (aggressiveCanonicalName, error) {
	if q.Qtype == dns.TypeNone ||
		q.Qclass == 0 ||
		q.Qclass == dns.ClassANY ||
		q.Qclass == dns.ClassNONE {
		return aggressiveCanonicalName{}, aggressiveFallback("unsupported question")
	}
	qname, err := newAggressiveCanonicalName(q.Name)
	if err != nil {
		return aggressiveCanonicalName{}, err
	}
	if !qname.isSubdomainOf(signer) {
		return aggressiveCanonicalName{}, aggressiveFallback("question is outside signer zone")
	}
	return qname, nil
}

func aggressiveNODATAType(qtype uint16) bool {
	switch qtype {
	case dns.TypeNone,
		dns.TypeOPT,
		dns.TypeTKEY,
		dns.TypeTSIG,
		dns.TypeIXFR,
		dns.TypeAXFR,
		dns.TypeMAILB,
		dns.TypeMAILA,
		dns.TypeANY:
		return false
	default:
		return true
	}
}

func validateAggressiveExactNODATA(qtype uint16, bitmap []uint16) error {
	if typesSet(bitmap, qtype, dns.TypeCNAME) {
		return ErrNSECTypeExists
	}
	if qtype == dns.TypeDS && typesSet(bitmap, dns.TypeSOA) {
		return ErrNSECBadDelegation
	}
	if qtype != dns.TypeDS && aggressiveDelegationBitmap(bitmap) {
		return ErrNSECBadDelegation
	}
	return nil
}

func aggressiveDelegationBitmap(bitmap []uint16) bool {
	return typesSet(bitmap, dns.TypeNS) && !typesSet(bitmap, dns.TypeSOA)
}

type aggressiveNameState uint8

const (
	aggressiveNameUnknown aggressiveNameState = iota
	aggressiveNameExact
	aggressiveNameENT
	aggressiveNameAbsent
)

type aggressiveNSECEntry struct {
	rr    *dns.NSEC
	owner aggressiveCanonicalName
	next  aggressiveCanonicalName
}

type aggressiveNSECProof struct {
	state aggressiveNameState
	nsec  *dns.NSEC
	entry *aggressiveNSECEntry
}

func newAggressiveNSECEntries(
	records []dns.RR,
	qclass uint16,
	zone aggressiveCanonicalName,
) ([]aggressiveNSECEntry, error) {
	if len(records) == 0 {
		return nil, ErrNSECMissingCoverage
	}

	entries := make([]aggressiveNSECEntry, 0, len(records))
	for _, record := range records {
		nsec, ok := record.(*dns.NSEC)
		if !ok || nsec == nil ||
			nsec.Header().Rrtype != dns.TypeNSEC ||
			nsec.Header().Class != qclass {
			return nil, aggressiveFallback("NSEC set is not homogeneous")
		}
		prepared, err := PrepareAggressiveNSEC(nsec)
		if err != nil {
			return nil, err
		}
		entries, err = appendAggressiveNSECEntry(entries, prepared.entry, zone)
		if err != nil {
			return nil, err
		}
	}
	if len(entries) == 0 {
		return nil, ErrNSECMissingCoverage
	}
	return entries, nil
}

// aggressiveNSECEntriesFromPrepared is newAggressiveNSECEntries for records
// canonicalized ahead of time. The set-level checks are unchanged; only the
// per-record name canonicalization is absent, having happened once already.
func aggressiveNSECEntriesFromPrepared(
	prepared []PreparedNSEC,
	qclass uint16,
	zone aggressiveCanonicalName,
) ([]aggressiveNSECEntry, error) {
	if len(prepared) == 0 {
		return nil, ErrNSECMissingCoverage
	}

	entries := make([]aggressiveNSECEntry, 0, len(prepared))
	for _, candidate := range prepared {
		nsec := candidate.entry.rr
		if nsec == nil ||
			nsec.Header().Rrtype != dns.TypeNSEC ||
			nsec.Header().Class != qclass {
			return nil, aggressiveFallback("NSEC set is not homogeneous")
		}
		var err error
		entries, err = appendAggressiveNSECEntry(entries, candidate.entry, zone)
		if err != nil {
			return nil, err
		}
	}
	if len(entries) == 0 {
		return nil, ErrNSECMissingCoverage
	}
	return entries, nil
}

// appendAggressiveNSECEntry admits one canonicalized record into the set:
// it must lie inside the signer zone, must not describe a singleton
// interval below the apex, and must not contradict a record already
// admitted for the same owner. An exact repeat is dropped.
func appendAggressiveNSECEntry(
	entries []aggressiveNSECEntry,
	candidate aggressiveNSECEntry,
	zone aggressiveCanonicalName,
) ([]aggressiveNSECEntry, error) {
	if !candidate.owner.isSubdomainOf(zone) || !candidate.next.isSubdomainOf(zone) {
		return nil, aggressiveFallback("NSEC record crosses signer zone")
	}
	if candidate.owner.equal(candidate.next) && !candidate.owner.equal(zone) {
		return nil, aggressiveFallback("non-apex NSEC has a singleton interval")
	}

	for i := range entries {
		if !entries[i].owner.equal(candidate.owner) {
			continue
		}
		if !entries[i].next.equal(candidate.next) ||
			!aggressiveTypeBitmapsEqual(entries[i].rr.TypeBitMap, candidate.rr.TypeBitMap) {
			return nil, aggressiveFallback("conflicting NSEC owners")
		}
		return entries, nil
	}
	return append(entries, candidate), nil
}

func classifyAggressiveNSECName(
	name aggressiveCanonicalName,
	entries []aggressiveNSECEntry,
) (aggressiveNSECProof, error) {
	for i := range entries {
		entry := &entries[i]
		if !name.isStrictSubdomainOf(entry.owner) {
			continue
		}
		if aggressiveDelegationBitmap(entry.rr.TypeBitMap) ||
			typesSet(entry.rr.TypeBitMap, dns.TypeDNAME) {
			return aggressiveNSECProof{}, ErrNSECBadDelegation
		}
	}

	var exact *aggressiveNSECEntry
	var covering *aggressiveNSECEntry
	state := aggressiveNameUnknown
	for i := range entries {
		entry := &entries[i]
		if name.equal(entry.owner) {
			if exact != nil {
				return aggressiveNSECProof{}, aggressiveFallback("multiple exact NSEC records")
			}
			exact = entry
			continue
		}

		covered, candidateState := aggressiveNSECClassifyInterval(name, entry)
		if !covered {
			continue
		}
		if covering != nil {
			return aggressiveNSECProof{}, aggressiveFallback("overlapping NSEC intervals")
		}
		covering = entry
		state = candidateState
	}

	if exact != nil {
		if covering != nil {
			return aggressiveNSECProof{}, aggressiveFallback("NSEC exact owner is also covered")
		}
		return aggressiveNSECProof{
			state: aggressiveNameExact,
			nsec:  exact.rr,
			entry: exact,
		}, nil
	}
	if covering == nil {
		return aggressiveNSECProof{}, ErrNSECMissingCoverage
	}
	return aggressiveNSECProof{state: state, nsec: covering.rr, entry: covering}, nil
}

// aggressiveNSECClassifyInterval implements the RFC 8198 Appendix B
// procedure. It intentionally differs from a generic circular interval test:
// the wrap case is constrained to names below NextDomain, and a descendant
// NextDomain identifies an empty non-terminal rather than NXDOMAIN.
func aggressiveNSECClassifyInterval(
	name aggressiveCanonicalName,
	entry *aggressiveNSECEntry,
) (bool, aggressiveNameState) {
	if name.compare(entry.owner) <= 0 || name.equal(entry.next) {
		return false, aggressiveNameUnknown
	}

	switch entry.next.compare(entry.owner) {
	case 1:
		if name.compare(entry.next) >= 0 {
			return false, aggressiveNameUnknown
		}
	default:
		if !name.isSubdomainOf(entry.next) {
			return false, aggressiveNameUnknown
		}
	}

	if entry.next.isStrictSubdomainOf(name) {
		return true, aggressiveNameENT
	}
	return true, aggressiveNameAbsent
}

func closestEncloserFromAggressiveNSEC(
	qname aggressiveCanonicalName,
	cover *aggressiveNSECEntry,
) (aggressiveCanonicalName, bool) {
	if cover == nil || len(qname.labels) == 0 {
		return aggressiveCanonicalName{}, false
	}
	ownerShared := aggressiveSharedSuffixLabels(qname, cover.owner)
	nextShared := aggressiveSharedSuffixLabels(qname, cover.next)
	shared := ownerShared
	if nextShared > shared {
		shared = nextShared
	}
	if shared >= len(qname.labels) {
		shared = len(qname.labels) - 1
	}
	if shared < 0 {
		return aggressiveCanonicalName{}, false
	}
	return qname.suffix(shared), true
}

func aggressiveSharedSuffixLabels(a, b aggressiveCanonicalName) int {
	count := 0
	for i, j := len(a.labels)-1, len(b.labels)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if !bytes.Equal(a.labels[i], b.labels[j]) {
			break
		}
		count++
	}
	return count
}

type aggressiveNSEC3Parameters struct {
	hash       uint8
	iterations uint16
	salt       []byte
}

type aggressiveNSEC3Entry struct {
	rr        *dns.NSEC3
	ownerHash []byte
	nextHash  []byte
}

func newAggressiveNSEC3Entries(
	records []dns.RR,
	qclass uint16,
	zone aggressiveCanonicalName,
) ([]aggressiveNSEC3Entry, aggressiveNSEC3Parameters, error) {
	if len(records) == 0 {
		return nil, aggressiveNSEC3Parameters{}, ErrNSECMissingCoverage
	}

	var parameters aggressiveNSEC3Parameters
	entries := make([]aggressiveNSEC3Entry, 0, len(records))
	for index, record := range records {
		nsec3, ok := record.(*dns.NSEC3)
		if !ok || !AggressiveNSEC3Usable(nsec3) ||
			nsec3.Header().Rrtype != dns.TypeNSEC3 ||
			nsec3.Header().Class != qclass {
			return nil, aggressiveNSEC3Parameters{},
				aggressiveFallback("NSEC3 set is not homogeneous or usable")
		}

		salt, err := hex.DecodeString(nsec3.Salt)
		if err != nil || len(salt) != int(nsec3.SaltLength) {
			return nil, aggressiveNSEC3Parameters{}, aggressiveFallback("invalid NSEC3 salt")
		}
		if index == 0 {
			parameters = aggressiveNSEC3Parameters{
				hash:       nsec3.Hash,
				iterations: nsec3.Iterations,
				salt:       salt,
			}
		} else if nsec3.Hash != parameters.hash ||
			nsec3.Iterations != parameters.iterations ||
			!bytes.Equal(salt, parameters.salt) {
			return nil, aggressiveNSEC3Parameters{}, aggressiveFallback("mixed NSEC3 parameter tuples")
		}

		owner, err := newAggressiveCanonicalName(nsec3.Header().Name)
		if err != nil {
			return nil, aggressiveNSEC3Parameters{}, err
		}
		if len(owner.labels) != len(zone.labels)+1 ||
			!owner.isSubdomainOf(zone) {
			return nil, aggressiveNSEC3Parameters{}, aggressiveFallback("invalid NSEC3 owner zone")
		}
		ownerHash, err := decodeAggressiveNSEC3Hash(owner.labels[0])
		if err != nil {
			return nil, aggressiveNSEC3Parameters{}, err
		}
		if int(nsec3.HashLength) != len(ownerHash) {
			return nil, aggressiveNSEC3Parameters{},
				aggressiveFallback("invalid NSEC3 hash length")
		}
		nextHash, err := decodeAggressiveNSEC3Hash([]byte(nsec3.NextDomain))
		if err != nil {
			return nil, aggressiveNSEC3Parameters{}, err
		}

		candidate := aggressiveNSEC3Entry{
			rr:        nsec3,
			ownerHash: ownerHash,
			nextHash:  nextHash,
		}
		duplicate := false
		for i := range entries {
			if !bytes.Equal(entries[i].ownerHash, ownerHash) {
				continue
			}
			if !bytes.Equal(entries[i].nextHash, nextHash) ||
				entries[i].rr.Flags != nsec3.Flags ||
				!aggressiveTypeBitmapsEqual(entries[i].rr.TypeBitMap, nsec3.TypeBitMap) {
				return nil, aggressiveNSEC3Parameters{}, aggressiveFallback("conflicting NSEC3 owners")
			}
			duplicate = true
			break
		}
		if !duplicate {
			entries = append(entries, candidate)
		}
	}
	if len(entries) == 0 {
		return nil, aggressiveNSEC3Parameters{}, ErrNSECMissingCoverage
	}
	return entries, parameters, nil
}

var aggressiveNSEC3Base32 = base32.HexEncoding.WithPadding(base32.NoPadding)

func decodeAggressiveNSEC3Hash(encoded []byte) ([]byte, error) {
	if len(encoded) != 32 {
		return nil, aggressiveFallback("invalid NSEC3 hash length")
	}
	upper := make([]byte, len(encoded))
	for i, octet := range encoded {
		switch {
		case octet >= '0' && octet <= '9':
			upper[i] = octet
		case octet >= 'A' && octet <= 'V':
			upper[i] = octet
		case octet >= 'a' && octet <= 'v':
			upper[i] = octet - ('a' - 'A')
		default:
			return nil, aggressiveFallback("invalid NSEC3 base32hex hash")
		}
	}
	decoded, err := aggressiveNSEC3Base32.DecodeString(string(upper))
	if err != nil || len(decoded) != sha1.Size {
		return nil, aggressiveFallback("invalid NSEC3 base32hex hash")
	}
	return decoded, nil
}

type aggressiveNSEC3Hasher struct {
	parameters aggressiveNSEC3Parameters
	zone       aggressiveCanonicalName
	qclass     uint16
	work       NSEC3Work
	hashes     map[string][]byte
}

func (hasher *aggressiveNSEC3Hasher) hash(name aggressiveCanonicalName) ([]byte, error) {
	key := string(name.wire)
	if cached, ok := hasher.hashes[key]; ok {
		return cached, nil
	}

	compute := func() ([]byte, error) {
		if hasher.work != nil {
			release, err := hasher.work.BeginNSEC3Hash()
			if err != nil {
				return nil, wrapWorkError(err)
			}
			if release != nil {
				defer release()
			}
		}
		return calculateAggressiveNSEC3Hash(name, hasher.parameters), nil
	}

	value, err := nsec3HashWithMemo(
		hasher.work,
		aggressiveNSEC3HashMemoKey(
			name,
			hasher.zone,
			hasher.qclass,
			hasher.parameters,
		),
		compute,
	)
	if err != nil {
		return nil, err
	}
	hasher.hashes[key] = value
	return value, nil
}

func lookupAggressiveNSEC3(
	hash []byte,
	entries []aggressiveNSEC3Entry,
) (*aggressiveNSEC3Entry, *aggressiveNSEC3Entry, error) {
	var match *aggressiveNSEC3Entry
	var cover *aggressiveNSEC3Entry
	for i := range entries {
		entry := &entries[i]
		if bytes.Equal(hash, entry.ownerHash) {
			if match != nil {
				return nil, nil, aggressiveFallback("multiple matching NSEC3 records")
			}
			match = entry
			continue
		}
		if !aggressiveNSEC3Covers(entry, hash) {
			continue
		}
		if cover != nil {
			return nil, nil, aggressiveFallback("overlapping NSEC3 intervals")
		}
		cover = entry
	}
	if match != nil && cover != nil {
		return nil, nil, aggressiveFallback("NSEC3 match is also covered")
	}
	return match, cover, nil
}

func aggressiveNSEC3Covers(entry *aggressiveNSEC3Entry, hash []byte) bool {
	ownerNext := bytes.Compare(entry.ownerHash, entry.nextHash)
	hashOwner := bytes.Compare(hash, entry.ownerHash)
	hashNext := bytes.Compare(hash, entry.nextHash)
	switch {
	case ownerNext == 0:
		return hashOwner != 0
	case ownerNext < 0:
		return hashOwner > 0 && hashNext < 0
	default:
		return hashOwner > 0 || hashNext < 0
	}
}

type aggressiveNSEC3ClosestEncloser struct {
	name aggressiveCanonicalName
	rr   *dns.NSEC3
}

func findAggressiveNSEC3ClosestEncloser(
	qname aggressiveCanonicalName,
	zone aggressiveCanonicalName,
	entries []aggressiveNSEC3Entry,
	hasher *aggressiveNSEC3Hasher,
) (aggressiveNSEC3ClosestEncloser, aggressiveCanonicalName, error) {
	for labelCount := len(qname.labels) - 1; labelCount >= len(zone.labels); labelCount-- {
		candidate := qname.suffix(labelCount)
		hash, err := hasher.hash(candidate)
		if err != nil {
			return aggressiveNSEC3ClosestEncloser{}, aggressiveCanonicalName{}, err
		}
		match, _, err := lookupAggressiveNSEC3(hash, entries)
		if err != nil {
			return aggressiveNSEC3ClosestEncloser{}, aggressiveCanonicalName{}, err
		}
		if match == nil {
			continue
		}
		nextCloser := qname.suffix(labelCount + 1)
		return aggressiveNSEC3ClosestEncloser{name: candidate, rr: match.rr}, nextCloser, nil
	}
	return aggressiveNSEC3ClosestEncloser{}, aggressiveCanonicalName{}, ErrNSECMissingCoverage
}

func aggressiveTypeBitmapsEqual(a, b []uint16) bool {
	aSet := make(map[uint16]struct{}, len(a))
	bSet := make(map[uint16]struct{}, len(b))
	for _, rrtype := range a {
		aSet[rrtype] = struct{}{}
	}
	for _, rrtype := range b {
		bSet[rrtype] = struct{}{}
	}
	if len(aSet) != len(bSet) {
		return false
	}
	for rrtype := range aSet {
		if _, ok := bSet[rrtype]; !ok {
			return false
		}
	}
	return true
}

func appendAggressiveProof(proof []dns.RR, record dns.RR) []dns.RR {
	for _, existing := range proof {
		if existing == record {
			return proof
		}
	}
	return append(proof, record)
}

func aggressiveFallback(reason string) error {
	return fmt.Errorf("%w: %s", ErrNSECMissingCoverage, reason)
}
