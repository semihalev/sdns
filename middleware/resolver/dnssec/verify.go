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
	total := 0
	supported := 0
	var lastErr error
	for _, r := range parentDSSet {
		parentDS, ok := r.(*dns.DS)
		if !ok {
			continue
		}
		total++
		if !IsSupportedDS(parentDS) {
			continue
		}
		supported++

		candidates, present := keyMap[parentDS.KeyTag]
		if !present {
			lastErr = ErrMissingKSK
			continue
		}
		matched := false
		for _, ksk := range candidates {
			ds := ksk.ToDS(parentDS.DigestType)
			if ds == nil {
				continue
			}
			if ds.Digest == parentDS.Digest {
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
				if collectErr == nil {
					collectErr = ErrMissingSigned
				}
				continue
			}
			k := rrsetKey{name: name, rtype: rtype}
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
		k := rrsetKey{name: name, rtype: sig.TypeCovered}
		sigIndex[k] = append(sigIndex[k], sig)
	}

	for key, set := range rrsets {
		sigList, ok := sigIndex[key]
		if !ok {
			return false, ErrMissingSigned
		}
		var lastErr error
		verified := false
		for _, sig := range sigList {
			if err := verifyOneSig(keys, set, sig); err != nil {
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

// verifyOneSig returns nil when sig verifies set with any DNSKEY in
// keys that matches sig.KeyTag. RFC 4034 Appendix B.1 says key tags are
// not unique, so every candidate key with the same tag must be tried
// before giving up. Returns a descriptive error for every other
// outcome so the caller can surface the most informative failure when
// every candidate signature fails for an RRset.
func verifyOneSig(keys map[uint16][]*dns.DNSKEY, set []dns.RR, sig *dns.RRSIG) error {
	candidates, ok := keys[sig.KeyTag]
	if !ok || len(candidates) == 0 {
		return ErrMissingDNSKEY
	}
	var lastErr error = ErrMissingDNSKEY
	for _, k := range candidates {
		if !strings.EqualFold(sig.SignerName, k.Header().Name) {
			lastErr = ErrMissingDNSKEY
			continue
		}
		switch k.Algorithm {
		case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.RSAMD5:
			if !checkExponent(k.PublicKey) {
				// RSA exponent unsupported by Go crypto; treat as
				// no-valid-key rather than a silent pass.
				lastErr = ErrMissingDNSKEY
				continue
			}
		}
		if err := sig.Verify(k, set); err != nil {
			lastErr = err
			continue
		}
		if !sig.ValidityPeriod(time.Time{}) {
			lastErr = ErrInvalidSignaturePeriod
			continue
		}
		return nil
	}
	return lastErr
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

func checkExponent(key string) bool {
	keybuf, err := fromBase64([]byte(key))
	if err != nil {
		return true
	}

	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return true
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 || explen == 0 || keybuf[keyoff] == 0 {
		// Exponent larger than supported by the crypto package,
		// empty, or contains prohibited leading zero.
		return false
	}

	return true
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}
