// Package dnssec implements pure DNSSEC verification primitives:
// RRSIG/DS validation, NSEC and NSEC3 denial-of-existence proofs, and
// the EDE-coded sentinel errors they return. None of the functions here
// hold resolver state; they take the records they need to validate as
// inputs and return a pass/fail result. The recursive resolver wraps
// them with the chain-of-trust orchestration (DS lookups, key fetches,
// trust-anchor management).
package dnssec

import (
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// IsSupportedDSDigest reports whether the given DS digest type is
// implemented locally. RFC 6840 §5.2 requires validators to ignore DS
// records that use unknown or unimplemented digest algorithms. Only the
// three digest types miekg/dns' DNSKEY.ToDS actually computes are
// treated as supported here — anything else (GOST94, future digest
// types, unknown values) is skipped.
func IsSupportedDSDigest(t uint8) bool {
	switch t {
	case dns.SHA1, dns.SHA256, dns.SHA384:
		return true
	}
	return false
}

// IsSupportedDNSKEYAlgorithm reports whether miekg/dns' RRSIG.Verify can
// process signatures of the given algorithm without returning ErrAlg.
// DS records advertising unsupported DNSKEY algorithms are unusable —
// DNSKEY.ToDS will still hash them, but later RRSIG verification would
// fail. Per RFC 6840 §5.2 such DS entries must be disregarded so an
// unsupported-only DS RRset is treated as insecure rather than bogus.
//
// The list intentionally matches miekg/dns' switch in RRSIG.Verify
// exactly. RSAMD5 (deprecated by RFC 8624) is *not* accepted there, so
// classifying it as supported would let an RSAMD5 DS RRset appear
// usable and then bogus out on verification instead of downgrading to
// insecure.
func IsSupportedDNSKEYAlgorithm(alg uint8) bool {
	switch alg {
	case dns.RSASHA1,
		dns.RSASHA1NSEC3SHA1,
		dns.RSASHA256,
		dns.RSASHA512,
		dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384,
		dns.ED25519:
		return true
	}
	return false
}

// IsSupportedDS reports whether a DS record is usable for validation:
// both its digest type and the DNSKEY algorithm it advertises must be
// something this validator can verify.
func IsSupportedDS(ds *dns.DS) bool {
	return IsSupportedDSDigest(ds.DigestType) && IsSupportedDNSKEYAlgorithm(ds.Algorithm)
}

// VerifyDS looks for a DS record in parentDSSet that authenticates one
// of the KSKs in keyMap. It returns (unsupportedOnly, err):
//
//   - (false, nil)  — at least one supported DS matched a KSK.
//   - (false, err)  — at least one supported DS was present but none
//     matched; the zone is bogus (not "insecure").
//   - (true, err)   — every DS in the RRset uses an unsupported digest
//     type. Per RFC 6840 §5.2 validators MUST ignore such records, and
//     if none remain the caller must treat the zone as insecure.
//
// keyMap groups DNSKEYs by key tag because RFC 4034 Appendix B.1 does
// not guarantee key-tag uniqueness: a colliding tag could otherwise
// mask the KSK that actually authenticates the DS.
func VerifyDS(keyMap map[uint16][]*dns.DNSKEY, parentDSSet []dns.RR) (bool, error) {
	return verifyDSWithWork(keyMap, parentDSSet, nil)
}

// VerifyDSWithWork is VerifyDS with request-tree digest work accounting.
// Cheap DS/DNSKEY compatibility checks and duplicate removal happen before a
// digest slot is consumed.
func VerifyDSWithWork(
	keyMap map[uint16][]*dns.DNSKEY,
	parentDSSet []dns.RR,
	work DSDigestWork,
) (bool, error) {
	return verifyDSWithWork(keyMap, parentDSSet, work)
}

func verifyDSWithWork(
	keyMap map[uint16][]*dns.DNSKEY,
	parentDSSet []dns.RR,
	work DSDigestWork,
) (bool, error) {
	dsRecords := uniqueSortedDSRecords(parentDSSet)
	total := len(dsRecords)
	supported := 0
	var lastErr error
	for _, parentDS := range dsRecords {
		if !IsSupportedDS(parentDS) {
			continue
		}
		supported++

		rawCandidates, present := keyMap[parentDS.KeyTag]
		if !present {
			lastErr = ErrMissingKSK
			continue
		}

		candidates := make([]*dns.DNSKEY, 0, len(rawCandidates))
		for _, ksk := range rawCandidates {
			if !usableDSCandidate(parentDS, ksk) {
				continue
			}
			candidates = append(candidates, ksk)
		}
		candidates = uniqueSortedDNSKEYs(candidates)
		if len(candidates) == 0 {
			lastErr = ErrMissingKSK
			continue
		}

		// Decoded once for the whole candidate set: the parent's digest is
		// what every candidate is measured against, and it does not change
		// between them.
		wantDigest, decodeErr := hex.DecodeString(parentDS.Digest)
		if decodeErr != nil || len(wantDigest) == 0 {
			lastErr = ErrMismatchingDS
			continue
		}

		matched := false
		var candidateUsed uint32
		for _, ksk := range candidates {
			if work != nil {
				if err := work.CheckDNSKEYCandidate(candidateUsed); err != nil {
					return false, wrapWorkError(err)
				}
			}

			ok, err := runDSDigestMatch(work, ksk, parentDS.DigestType, wantDigest)
			if err != nil {
				return false, err
			}
			candidateUsed++
			if ok {
				matched = true
				break
			}
			lastErr = ErrMismatchingDS
		}
		if matched {
			return false, nil
		}
	}

	if total == 0 {
		return false, ErrMissingKSK
	}
	if supported == 0 {
		return true, ErrFailedToConvertKSK
	}
	if lastErr == nil {
		lastErr = ErrMissingKSK
	}
	return false, lastErr
}

type dnskeyIdentity struct {
	name      string
	class     uint16
	flags     uint16
	protocol  uint8
	algorithm uint8
	publicKey string
}

func dnskeyID(key *dns.DNSKEY) dnskeyIdentity {
	return dnskeyIdentity{
		name:      strings.ToLower(dns.Fqdn(key.Header().Name)),
		class:     key.Header().Class,
		flags:     key.Flags,
		protocol:  key.Protocol,
		algorithm: key.Algorithm,
		publicKey: key.PublicKey,
	}
}

func uniqueSortedDNSKEYs(keys []*dns.DNSKEY) []*dns.DNSKEY {
	if len(keys) < 2 {
		return keys
	}

	seen := make(map[dnskeyIdentity]struct{}, len(keys))
	unique := make([]*dns.DNSKEY, 0, len(keys))
	for _, key := range keys {
		id := dnskeyID(key)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, key)
	}
	sort.Slice(unique, func(i, j int) bool {
		a, b := dnskeyID(unique[i]), dnskeyID(unique[j])
		switch {
		case a.name != b.name:
			return a.name < b.name
		case a.class != b.class:
			return a.class < b.class
		case a.flags != b.flags:
			return a.flags < b.flags
		case a.protocol != b.protocol:
			return a.protocol < b.protocol
		case a.algorithm != b.algorithm:
			return a.algorithm < b.algorithm
		default:
			return a.publicKey < b.publicKey
		}
	})
	return unique
}

type dsIdentity struct {
	name       string
	class      uint16
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     string
}

func dsID(ds *dns.DS) dsIdentity {
	return dsIdentity{
		name:       strings.ToLower(dns.Fqdn(ds.Header().Name)),
		class:      ds.Header().Class,
		keyTag:     ds.KeyTag,
		algorithm:  ds.Algorithm,
		digestType: ds.DigestType,
		digest:     strings.ToUpper(ds.Digest),
	}
}

func uniqueSortedDSRecords(records []dns.RR) []*dns.DS {
	seen := make(map[dsIdentity]struct{}, len(records))
	result := make([]*dns.DS, 0, len(records))
	for _, record := range records {
		ds, ok := record.(*dns.DS)
		if !ok || ds == nil {
			continue
		}
		id := dsID(ds)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, ds)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := dsID(result[i]), dsID(result[j])
		switch {
		case a.name != b.name:
			return a.name < b.name
		case a.class != b.class:
			return a.class < b.class
		case a.keyTag != b.keyTag:
			return a.keyTag < b.keyTag
		case a.algorithm != b.algorithm:
			return a.algorithm < b.algorithm
		case a.digestType != b.digestType:
			return a.digestType < b.digestType
		default:
			return a.digest < b.digest
		}
	})
	return result
}

func usableDSCandidate(parentDS *dns.DS, key *dns.DNSKEY) bool {
	if key == nil {
		return false
	}
	// Ahead of KeyTag, which packs the key into a buffer of its own and
	// decodes the material to fill it. A key too large to produce a DS can
	// never match one, and a DS set may name the same key repeatedly: the
	// cheap check has to come first or the expensive one runs per mention.
	if oversizedKeyMaterial(key.PublicKey) {
		return false
	}
	return KeyTag(key) == parentDS.KeyTag &&
		key.Algorithm == parentDS.Algorithm &&
		key.Header().Class == parentDS.Header().Class &&
		strings.EqualFold(key.Header().Name, parentDS.Header().Name) &&
		key.Protocol == 3 &&
		key.Flags&dns.ZONE != 0
}

func beginDSDigest(work DSDigestWork) (func(), error) {
	if work == nil {
		return nil, nil
	}
	release, err := work.BeginDSDigest()
	if err != nil {
		return nil, wrapWorkError(err)
	}
	return release, nil
}

// runDSDigestMatch charges the request tree for one DS digest and reports
// whether key hashes to want. The comparison happens on the digest bytes
// rather than through a dns.DS: the record, its hexadecimal digest and the
// two oversized buffers behind them exist only to be compared and dropped.
func runDSDigestMatch(
	work DSDigestWork,
	key *dns.DNSKEY,
	digestType uint8,
	want []byte,
) (bool, error) {
	release, err := beginDSDigest(work)
	if err != nil {
		return false, err
	}
	if release != nil {
		defer release()
	}
	return dsDigestMatches(key, digestType, want), nil
}

// VerifyRRSIG validates that every in-zone RRset in msg is covered by at
// least one RRSIG that successfully verifies against the supplied DNSKEYs.
//
// The signer zone is supplied by the caller (verifyDNSSEC / verifyRootKeys)
// and represents the zone whose keys should authenticate this response.
// RRsets whose owner name is not in that zone — for example, target
// records appended via DNAME synthesis — are validated by their own
// recursion and are skipped here. An unsigned RRset inside the zone is
// rejected; a signature that fails (missing key, bad exponent, verify
// error, expired) only causes the RRset to fail if no sibling signature
// succeeds.
func VerifyRRSIG(signer string, keys map[uint16][]*dns.DNSKEY, msg *dns.Msg) (bool, error) {
	return verifyRRSIGWithWork(signer, keys, msg, nil)
}

// VerifyRRSIGWithWork is VerifyRRSIG with request-tree signature work
// accounting. Structural rejection, duplicate removal, and deterministic
// candidate ordering all happen before a public-key operation consumes work.
func VerifyRRSIGWithWork(
	signer string,
	keys map[uint16][]*dns.DNSKEY,
	msg *dns.Msg,
	work SignatureWork,
) (bool, error) {
	return verifyRRSIGWithWork(signer, keys, msg, work)
}

func verifyRRSIGWithWork(
	signer string,
	keys map[uint16][]*dns.DNSKEY,
	msg *dns.Msg,
	work SignatureWork,
) (bool, error) {
	if len(keys) == 0 {
		return false, ErrMissingDNSKEY
	}

	// Do NOT derive the zone from the keys map: after the key-tag
	// collision fix, that map can contain same-tag clones from a
	// different owner, and picking the first one would make the whole
	// zone filter misclassify in-zone records as foreign.
	signerZone := strings.ToLower(dns.Fqdn(signer))
	if signerZone == "" {
		return false, ErrMissingDNSKEY
	}

	type rrsetKey struct {
		name  string
		rtype uint16
		class uint16
	}

	// Collect DNAMEs in the signer zone first so we can recognise the
	// synthesised CNAMEs a DNAME answer is allowed to ship unsigned.
	var dnames []*dns.DNAME
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, r := range section {
			if d, ok := r.(*dns.DNAME); ok {
				if dnsutil.NameInZone(strings.ToLower(d.Header().Name), signerZone) {
					dnames = append(dnames, d)
				}
			}
		}
	}

	rrsets := make(map[rrsetKey][]dns.RR)
	// Every record in the validation pass must belong to the signer
	// zone (apart from the narrow synthesised-CNAME exception RFC
	// 6672 §5.3.1 allows when an in-zone DNAME signs the synthesis).
	// Callers that splice records from a separately-validated zone
	// (DNAME target answers) are expected to merge them only *after*
	// this function has returned, and to AND the other zone's AD
	// into the combined response themselves. Without this guard, a
	// signed response could carry attacker-injected foreign RRsets
	// alongside legitimately authenticated in-zone data and still
	// end up marked AuthenticatedData=true, violating RFC 4035
	// §3.2.3.
	var collectErr error
	collect := func(records []dns.RR, fromAuthority bool) {
		for _, r := range records {
			rtype := r.Header().Rrtype
			if rtype == dns.TypeRRSIG {
				continue
			}
			if rtype == dns.TypeNS && fromAuthority {
				continue
			}
			if rtype == dns.TypeCNAME {
				if cname, ok := r.(*dns.CNAME); ok && isSynthesizedCNAME(cname, dnames) {
					// RFC 6672 §5.3.1: the synthesised CNAME carries
					// no RRSIG of its own; the DNAME signature plus
					// correct synthesis is the proof.
					continue
				}
			}
			name := strings.ToLower(r.Header().Name)
			if !dnsutil.NameInZone(name, signerZone) {
				if fromAuthority {
					// Referral remnant: an upstream that also hosts
					// ancestors of a CNAME target may append the
					// target's zone-cut NS and DS-denial records —
					// owned outside the signer zone — to a positive
					// answer (issue #506). They are advisory (RFC
					// 2181 §5.4.1 ranks authority data below answer
					// data) and the caller re-resolves the target
					// through its own validated recursion, so they
					// are excluded from this signer's validation
					// rather than failing it. Out-of-zone records in
					// the ANSWER section stay fatal below.
					continue
				}
				if collectErr == nil {
					collectErr = ErrMissingSigned
				}
				continue
			}
			k := rrsetKey{name: name, rtype: rtype, class: r.Header().Class}
			rrsets[k] = append(rrsets[k], r)
		}
	}
	collect(msg.Answer, false)
	collect(msg.Ns, true)
	if collectErr != nil {
		return false, collectErr
	}

	if len(rrsets) == 0 {
		// Nothing authoritative for this signer (e.g., an NS-only
		// delegation referral, or a DNAME answer whose outer zone
		// was validated under a different signer). The caller is
		// responsible for ensuring a separate cryptographic proof
		// (DS, NSEC/NSEC3) exists.
		return true, nil
	}

	sigs := append(
		dnsutil.ExtractRRSet(msg.Answer, "", dns.TypeRRSIG),
		dnsutil.ExtractRRSet(msg.Ns, "", dns.TypeRRSIG)...,
	)
	if len(sigs) == 0 {
		return false, ErrNoSignatures
	}

	sigIndex := make(map[rrsetKey][]*dns.RRSIG)
	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		name := strings.ToLower(sig.Header().Name)
		if !dnsutil.NameInZone(name, signerZone) {
			continue
		}
		k := rrsetKey{name: name, rtype: sig.TypeCovered, class: sig.Header().Class}
		sigIndex[k] = append(sigIndex[k], sig)
	}

	keysInOrder := make([]rrsetKey, 0, len(rrsets))
	for key := range rrsets {
		keysInOrder = append(keysInOrder, key)
	}
	sort.Slice(keysInOrder, func(i, j int) bool {
		switch {
		case keysInOrder[i].name != keysInOrder[j].name:
			return keysInOrder[i].name < keysInOrder[j].name
		case keysInOrder[i].rtype != keysInOrder[j].rtype:
			return keysInOrder[i].rtype < keysInOrder[j].rtype
		default:
			return keysInOrder[i].class < keysInOrder[j].class
		}
	})

	for _, key := range keysInOrder {
		set := rrsets[key]
		sigList, ok := sigIndex[key]
		if !ok {
			return false, ErrMissingSigned
		}
		if !dns.IsRRset(set) {
			return false, ErrMissingSigned
		}
		sigList = uniqueSortedRRSIGs(sigList)

		var lastErr error
		verified := false
		var rrsetUsed uint32
		for _, sig := range sigList {
			if err := verifyOneSigWithWork(keys, set, sig, work, &rrsetUsed); err != nil {
				if IsWorkError(err) {
					return false, err
				}
				lastErr = err
				continue
			}
			verified = true
			break
		}
		if !verified {
			if lastErr == nil {
				lastErr = ErrMissingSigned
			}
			return false, lastErr
		}
	}

	return true, nil
}

type rrsigIdentity struct {
	name        string
	class       uint16
	typeCovered uint16
	algorithm   uint8
	labels      uint8
	origTTL     uint32
	expiration  uint32
	inception   uint32
	keyTag      uint16
	signer      string
	signature   string
}

func rrsigID(sig *dns.RRSIG) rrsigIdentity {
	return rrsigIdentity{
		name:        strings.ToLower(dns.Fqdn(sig.Header().Name)),
		class:       sig.Header().Class,
		typeCovered: sig.TypeCovered,
		algorithm:   sig.Algorithm,
		labels:      sig.Labels,
		origTTL:     sig.OrigTtl,
		expiration:  sig.Expiration,
		inception:   sig.Inception,
		keyTag:      sig.KeyTag,
		signer:      strings.ToLower(dns.Fqdn(sig.SignerName)),
		signature:   sig.Signature,
	}
}

func uniqueSortedRRSIGs(signatures []*dns.RRSIG) []*dns.RRSIG {
	if len(signatures) == 0 {
		return signatures
	}

	seen := make(map[rrsigIdentity]struct{}, len(signatures))
	unique := make([]*dns.RRSIG, 0, len(signatures))
	for _, sig := range signatures {
		if sig == nil {
			continue
		}
		id := rrsigID(sig)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, sig)
	}
	sort.Slice(unique, func(i, j int) bool {
		a, b := rrsigID(unique[i]), rrsigID(unique[j])
		switch {
		case a.name != b.name:
			return a.name < b.name
		case a.class != b.class:
			return a.class < b.class
		case a.typeCovered != b.typeCovered:
			return a.typeCovered < b.typeCovered
		case a.algorithm != b.algorithm:
			return a.algorithm < b.algorithm
		case a.keyTag != b.keyTag:
			return a.keyTag < b.keyTag
		case a.signer != b.signer:
			return a.signer < b.signer
		case a.labels != b.labels:
			return a.labels < b.labels
		case a.origTTL != b.origTTL:
			return a.origTTL < b.origTTL
		case a.inception != b.inception:
			return a.inception < b.inception
		case a.expiration != b.expiration:
			return a.expiration < b.expiration
		default:
			return a.signature < b.signature
		}
	})
	return unique
}

// verifyOneSig returns nil when sig verifies set with any DNSKEY in
// keys that matches sig.KeyTag. RFC 4034 Appendix B.1 says key tags are
// not unique, so every candidate key with the same tag must be tried
// before giving up. Returns a descriptive error for every other
// outcome so the caller can surface the most informative failure when
// every candidate signature fails for an RRset.
func verifyOneSig(
	keys map[uint16][]*dns.DNSKEY,
	set []dns.RR,
	sig *dns.RRSIG,
) error {
	var rrsetUsed uint32
	return verifyOneSigWithWork(keys, set, sig, nil, &rrsetUsed)
}

func verifyOneSigWithWork(
	keys map[uint16][]*dns.DNSKEY,
	set []dns.RR,
	sig *dns.RRSIG,
	work SignatureWork,
	rrsetUsed *uint32,
) error {
	candidates, ok := keys[sig.KeyTag]
	if !ok || len(candidates) == 0 {
		return ErrMissingDNSKEY
	}

	// Keep ErrMissingDNSKEY when no same-tag candidate belongs to the
	// signature's claimed signer. This error is surfaced as EDE 9, so changing
	// it to EDE 7 merely because the unrelated signature is also expired would
	// be an unnecessary wire-visible compatibility change.
	hasSigner := false
	for _, k := range candidates {
		if k == nil {
			continue
		}
		if strings.EqualFold(sig.SignerName, k.Header().Name) {
			hasSigner = true
			break
		}
	}
	if !hasSigner {
		return ErrMissingDNSKEY
	}

	// Signature validity is candidate-independent, so reject it before the
	// first public-key operation.
	if !sig.ValidityPeriod(time.Time{}) {
		return ErrInvalidSignaturePeriod
	}

	if !IsSupportedDNSKEYAlgorithm(sig.Algorithm) {
		return dns.ErrAlg
	}
	if !signatureMatchesRRset(sig, set) {
		return ErrMissingSigned
	}

	eligible := make([]*dns.DNSKEY, 0, len(candidates))
	for _, key := range candidates {
		if usableSignatureCandidate(sig, key) {
			eligible = append(eligible, key)
		}
	}
	eligible = uniqueSortedDNSKEYs(eligible)
	if len(eligible) == 0 {
		return ErrMissingDNSKEY
	}

	var lastErr error = ErrMissingDNSKEY
	var candidateUsed uint32
	for _, k := range eligible {
		if work != nil {
			if err := work.CheckDNSKEYCandidate(candidateUsed); err != nil {
				return wrapWorkError(err)
			}
			if err := work.CheckRRsetSignature(*rrsetUsed); err != nil {
				return wrapWorkError(err)
			}
		}

		err := runSignatureVerification(work, k, sig, set)
		if err != nil {
			if IsWorkError(err) {
				return err
			}
			candidateUsed++
			*rrsetUsed++
			lastErr = err
			continue
		}
		*rrsetUsed++
		// Preserve the validator's original acceptance-time check as well as
		// the new preflight. A large same-tag candidate set can spend enough
		// time in crypto to cross the signature's one-second expiry boundary.
		if !sig.ValidityPeriod(time.Time{}) {
			return ErrInvalidSignaturePeriod
		}
		return nil
	}
	return lastErr
}

func usableSignatureCandidate(sig *dns.RRSIG, key *dns.DNSKEY) bool {
	if key == nil {
		return false
	}
	return KeyTag(key) == sig.KeyTag &&
		key.Algorithm == sig.Algorithm &&
		key.Header().Class == sig.Header().Class &&
		strings.EqualFold(key.Header().Name, sig.SignerName) &&
		key.Protocol == 3 &&
		key.Flags&dns.ZONE != 0
}

func signatureMatchesRRset(sig *dns.RRSIG, set []dns.RR) bool {
	if len(set) == 0 || !dns.IsRRset(set) {
		return false
	}
	signer := dns.CanonicalName(sig.SignerName)
	header := set[0].Header()
	return header.Class == sig.Header().Class &&
		header.Rrtype == sig.TypeCovered &&
		dns.CountLabel(header.Name) >= int(sig.Labels) &&
		strings.EqualFold(header.Name, sig.Header().Name) &&
		dnsutil.NameInZone(strings.ToLower(dns.Fqdn(header.Name)), signer)
}

func beginSignature(work SignatureWork) (func(), error) {
	if work == nil {
		return nil, nil
	}
	release, err := work.BeginSignature()
	if err != nil {
		return nil, wrapWorkError(err)
	}
	return release, nil
}

func runSignatureVerification(
	work SignatureWork,
	key *dns.DNSKEY,
	sig *dns.RRSIG,
	set []dns.RR,
) error {
	release, err := beginSignature(work)
	if err != nil {
		return err
	}
	if release != nil {
		defer release()
	}
	return cryptoVerify(key, sig, set)
}

// cryptoVerify runs the cryptographic RRSIG check for a single candidate key,
// through this package's own verifier for the algorithms it implements and
// the library's for anything else. The two agree by construction: the
// canonical signed data is the same, and the cryptography is the standard
// library's on both sides.
//
// Keys whose public exponent exceeds crypto/rsa's ceiling — mailbox.org's
// alg-7/alg-10 ZSKs, exponent 2^32+1 — keep the raw modexp path inside that
// verifier, so they validate instead of bogusing out.
func cryptoVerify(k *dns.DNSKEY, sig *dns.RRSIG, set []dns.RR) error {
	if verifySignatureSupported(k.Algorithm) {
		return verifySignature(k, sig, set)
	}
	return sig.Verify(k, set)
}

// isSynthesizedCNAME reports whether cname is the CNAME a resolver
// should have synthesised from one of the given DNAMEs (RFC 6672 §3.3).
// The match is: some dname is a *proper* ancestor of the CNAME owner,
// and applying the DNAME substitution (owner's labels above the DNAME
// owner, concatenated with the DNAME target) reproduces the CNAME
// target. Only then is it safe to skip the CNAME's own RRSIG check and
// rely on the DNAME signature plus correct synthesis.
func isSynthesizedCNAME(cname *dns.CNAME, dnames []*dns.DNAME) bool {
	owner := cname.Header().Name
	ownerLabels := dns.CountLabel(owner)
	for _, d := range dnames {
		dnameLabels := dns.CountLabel(d.Header().Name)
		if dnameLabels == 0 || ownerLabels <= dnameLabels {
			continue
		}
		n := dns.CompareDomainName(d.Header().Name, owner)
		if n != dnameLabels {
			continue
		}
		prev, _ := dns.PrevLabel(owner, n)
		expected := dns.Fqdn(owner[:prev] + d.Target)
		if strings.EqualFold(expected, dns.Fqdn(cname.Target)) {
			return true
		}
	}
	return false
}

// ValidateSigner checks that the signer claimed by an RRSIG is a
// plausible zone apex for qname — either qname itself or a proper
// ancestor. The check must run before the DS-chain lookup because
// RRSIG.SignerName is unauthenticated RDATA until a key verifies the
// signature: without it, an on-path attacker can rewrite SignerName to
// an unsigned sibling or descendant, then rely on findDS() returning an
// empty set to silently skip verifyDNSSEC() and downgrade a signed
// response to "insecure" instead of bogus.
func ValidateSigner(signer, qname string) error {
	if signer == "" {
		return ErrDSRecords
	}
	if !dnsutil.NameInZone(strings.ToLower(dns.Fqdn(qname)), strings.ToLower(dns.Fqdn(signer))) {
		return ErrDSRecords
	}
	return nil
}

// VerifyNSEC reports whether any NSEC in nsecSet has q.Qtype set in its
// type bitmap. This is a cheap structural check used as a pre-filter
// before the full denial-of-existence proofs in VerifyNODATANSEC /
// VerifyNameErrorNSEC. A true result alone does not authenticate
// anything.
func VerifyNSEC(q dns.Question, nsecSet []dns.RR) (typeMatch bool) {
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		for _, t := range nsec.TypeBitMap {
			if t == q.Qtype {
				typeMatch = true
				break
			}
		}
	}
	return
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}
