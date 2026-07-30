package dnssec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const workFactorZone = "work-factor.example."

type workFactorKeyMaterial struct {
	key  *dns.DNSKEY
	priv ed25519.PrivateKey
}

type workFactorRRSIGFixture struct {
	keys              map[uint16][]*dns.DNSKEY
	msg               *dns.Msg
	rrset             []dns.RR
	signatures        []*dns.RRSIG
	goodKey           *dns.DNSKEY
	wrongSameTagKeys  []*dns.DNSKEY
	expectedCryptoOps int
}

type workFactorDSFixture struct {
	keys              map[uint16][]*dns.DNSKEY
	parentDSSet       []dns.RR
	expectedDigestOps int
}

// newWorkFactorKey uses a fixed Ed25519 seed so the fixtures and benchmark
// inputs are reproducible and do not spend benchmark time generating keys.
func newWorkFactorKey(tb testing.TB) workFactorKeyMaterial {
	tb.Helper()

	seed := sha256.Sum256([]byte("sdns DNSSEC work-factor fixture"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		tb.Fatal("Ed25519 private key did not return an Ed25519 public key")
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   workFactorZone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     dns.ZONE | 1, // Zone key plus SEP bit.
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	if key.KeyTag() == 0 {
		tb.Fatal("deterministic fixture unexpectedly produced key tag zero")
	}
	return workFactorKeyMaterial{key: key, priv: priv}
}

// newWrongSameTagKeys changes two equally weighted bytes in the DNSKEY RDATA:
// one is incremented and the other decremented by a unique delta. The public
// key changes while the RFC 4034 Appendix B checksum, and therefore the key
// tag, stays constant.
func newWrongSameTagKeys(tb testing.TB, good *dns.DNSKEY, count int) []*dns.DNSKEY {
	tb.Helper()
	if count <= 0 {
		return nil
	}

	publicKey, err := base64.StdEncoding.DecodeString(good.PublicKey)
	if err != nil {
		tb.Fatalf("decode fixture DNSKEY: %v", err)
	}

	incIndex, decIndex := -1, -1
	for parity := 0; parity < 2 && incIndex < 0; parity++ {
		for inc := parity; inc < len(publicKey) && incIndex < 0; inc += 2 {
			if int(publicKey[inc])+count > 0xff {
				continue
			}
			for dec := parity; dec < len(publicKey); dec += 2 {
				if dec == inc || int(publicKey[dec])-count < 0 {
					continue
				}
				incIndex, decIndex = inc, dec
				break
			}
		}
	}
	if incIndex < 0 {
		tb.Fatalf("could not construct %d deterministic same-tag DNSKEY candidates", count)
	}

	keys := make([]*dns.DNSKEY, 0, count)
	seen := map[string]struct{}{good.PublicKey: {}}
	for delta := 1; delta <= count; delta++ {
		changed := append([]byte(nil), publicKey...)
		changed[incIndex] += byte(delta)
		changed[decIndex] -= byte(delta)

		wrong := *good
		wrong.PublicKey = base64.StdEncoding.EncodeToString(changed)
		if _, duplicate := seen[wrong.PublicKey]; duplicate {
			tb.Fatalf("same-tag candidate %d duplicated public key material", delta)
		}
		seen[wrong.PublicKey] = struct{}{}
		if wrong.KeyTag() != good.KeyTag() {
			tb.Fatalf("same-tag fixture %d changed key tag: got %d, want %d", delta, wrong.KeyTag(), good.KeyTag())
		}
		keys = append(keys, &wrong)
	}
	return keys
}

func signWorkFactorRRSet(
	tb testing.TB,
	material workFactorKeyMaterial,
	rrset []dns.RR,
	inception, expiration time.Time,
) *dns.RRSIG {
	tb.Helper()

	hdr := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  hdr.Class,
			Ttl:    hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   material.key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)), //nolint:gosec // Test name has a fixed, small label count.
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(expiration.Unix()), //nolint:gosec // DNSSEC timestamps are unsigned 32-bit serial values.
		Inception:   uint32(inception.Unix()),  //nolint:gosec // DNSSEC timestamps are unsigned 32-bit serial values.
		KeyTag:      material.key.KeyTag(),
		SignerName:  material.key.Header().Name,
	}
	if err := sig.Sign(material.priv, rrset); err != nil {
		tb.Fatalf("sign work-factor RRset: %v", err)
	}
	return sig
}

func newWorkFactorRRSIGFixture(tb testing.TB, signatureCount, candidateKeyCount int) workFactorRRSIGFixture {
	tb.Helper()
	if signatureCount < 1 || candidateKeyCount < 1 {
		tb.Fatalf("fixture sizes must be positive, got signatures=%d candidates=%d", signatureCount, candidateKeyCount)
	}

	material := newWorkFactorKey(tb)
	wrongKeys := newWrongSameTagKeys(tb, material.key, candidateKeyCount-1)
	rrset := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "www." + workFactorZone,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	now := time.Now()
	signatures := make([]*dns.RRSIG, 0, signatureCount)
	seenSignatures := make(map[string]struct{}, signatureCount)
	for i := 0; i < signatureCount-1; i++ {
		// These signatures have the expected owner, algorithm, signer, and
		// key tag, but each covers different RDATA. Every candidate reaches
		// the cryptographic verifier and fails.
		otherRRSet := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "www." + workFactorZone,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: []byte{192, 0, 2, byte(i + 2)},
			},
		}
		sig := signWorkFactorRRSet(
			tb,
			material,
			otherRRSet,
			now.Add(-time.Hour),
			now.Add(time.Hour),
		)
		if _, duplicate := seenSignatures[sig.Signature]; duplicate {
			tb.Fatalf("leading RRSIG %d duplicated signature material", i)
		}
		seenSignatures[sig.Signature] = struct{}{}
		signatures = append(signatures, sig)
	}
	// The only usable signature is last.
	goodSignature := signWorkFactorRRSet(
		tb,
		material,
		rrset,
		now.Add(-time.Hour),
		now.Add(time.Hour),
	)
	if _, duplicate := seenSignatures[goodSignature.Signature]; duplicate {
		tb.Fatal("final valid RRSIG duplicated a leading signature")
	}
	signatures = append(signatures, goodSignature)

	candidates := make([]*dns.DNSKEY, 0, candidateKeyCount)
	candidates = append(candidates, wrongKeys...)
	// The only usable candidate is last.
	candidates = append(candidates, material.key)

	msg := new(dns.Msg)
	msg.SetQuestion(rrset[0].Header().Name, dns.TypeA)
	msg.Answer = append(msg.Answer, rrset...)
	for _, sig := range signatures {
		msg.Answer = append(msg.Answer, sig)
	}

	return workFactorRRSIGFixture{
		keys: map[uint16][]*dns.DNSKEY{
			material.key.KeyTag(): candidates,
		},
		msg:               msg,
		rrset:             rrset,
		signatures:        signatures,
		goodKey:           material.key,
		wrongSameTagKeys:  wrongKeys,
		expectedCryptoOps: signatureCount * candidateKeyCount,
	}
}

func newWorkFactorDSFixture(tb testing.TB, dsCount, candidateKeyCount int) workFactorDSFixture {
	tb.Helper()
	if dsCount < 1 || candidateKeyCount < 1 {
		tb.Fatalf("fixture sizes must be positive, got DS=%d candidates=%d", dsCount, candidateKeyCount)
	}

	material := newWorkFactorKey(tb)
	wrongKeys := newWrongSameTagKeys(tb, material.key, candidateKeyCount-1)
	goodDS := material.key.ToDS(dns.SHA256)
	if goodDS == nil {
		tb.Fatal("could not derive fixture DS")
		return workFactorDSFixture{}
	}

	parentDSSet := make([]dns.RR, 0, dsCount)
	forbiddenDigests := map[string]struct{}{goodDS.Digest: {}}
	for i, wrongKey := range wrongKeys {
		wrongDS := wrongKey.ToDS(dns.SHA256)
		if wrongDS == nil {
			tb.Fatalf("could not derive same-tag candidate DS %d", i)
			return workFactorDSFixture{}
		}
		forbiddenDigests[wrongDS.Digest] = struct{}{}
	}
	seenBadDigests := make(map[string]struct{}, dsCount-1)
	for i := 0; i < dsCount-1; i++ {
		badDS := *goodDS
		for candidate := i + 1; ; candidate++ {
			badDS.Digest = fmt.Sprintf("%0*X", len(goodDS.Digest), candidate)
			_, forbidden := forbiddenDigests[badDS.Digest]
			_, duplicate := seenBadDigests[badDS.Digest]
			if !forbidden && !duplicate {
				break
			}
		}
		seenBadDigests[badDS.Digest] = struct{}{}
		parentDSSet = append(parentDSSet, &badDS)
	}
	// The only matching DS is last.
	parentDSSet = append(parentDSSet, goodDS)

	candidates := make([]*dns.DNSKEY, 0, candidateKeyCount)
	candidates = append(candidates, wrongKeys...)
	// The only key matching the last DS is last.
	candidates = append(candidates, material.key)

	return workFactorDSFixture{
		keys: map[uint16][]*dns.DNSKEY{
			material.key.KeyTag(): candidates,
		},
		parentDSSet:       parentDSSet,
		expectedDigestOps: dsCount * candidateKeyCount,
	}
}

func TestVerifyRRSIGWorkFactorLastSignatureAndCandidate(t *testing.T) {
	const (
		signatureCount = 4
		candidateCount = 4
	)
	fixture := newWorkFactorRRSIGFixture(t, signatureCount, candidateCount)

	for i, wrongKey := range fixture.wrongSameTagKeys {
		if wrongKey.KeyTag() != fixture.goodKey.KeyTag() {
			t.Fatalf("fixture key %d does not collide on key tag", i)
		}
	}
	if err := fixture.signatures[0].Verify(fixture.goodKey, fixture.rrset); err == nil {
		t.Fatal("leading signature unexpectedly verifies the answer RRset")
	}
	if err := fixture.signatures[0].Verify(fixture.wrongSameTagKeys[0], fixture.rrset); err == nil {
		t.Fatal("leading signature unexpectedly verifies with the wrong same-tag key")
	}
	lastSignature := fixture.signatures[len(fixture.signatures)-1]
	if err := lastSignature.Verify(fixture.wrongSameTagKeys[0], fixture.rrset); err == nil {
		t.Fatal("last signature unexpectedly verifies with the wrong same-tag key")
	}
	if err := lastSignature.Verify(fixture.goodKey, fixture.rrset); err != nil {
		t.Fatalf("last signature must verify with the last candidate: %v", err)
	}

	cryptoOps := 0
	ok, err := verifyRRSIGWith(
		workFactorZone,
		fixture.keys,
		fixture.msg,
		func(key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) error {
			cryptoOps++
			return cryptoVerify(key, sig, rrset)
		},
	)
	if err != nil {
		t.Fatalf("VerifyRRSIG rejected last-signature/last-candidate fixture: %v", err)
	}
	if !ok {
		t.Fatal("VerifyRRSIG returned false for a valid final signature and candidate")
	}
	if cryptoOps < 1 || cryptoOps > fixture.expectedCryptoOps {
		t.Fatalf("crypto operations = %d, want within [1,%d]", cryptoOps, fixture.expectedCryptoOps)
	}
}

func TestVerifyDSWorkFactorLastRecordAndCandidate(t *testing.T) {
	const (
		dsCount        = 4
		candidateCount = 4
	)
	fixture := newWorkFactorDSFixture(t, dsCount, candidateCount)

	digestOps := 0
	unsupportedOnly, err := verifyDSWith(
		fixture.keys,
		fixture.parentDSSet,
		func(key *dns.DNSKEY, digestType uint8) *dns.DS {
			digestOps++
			return key.ToDS(digestType)
		},
	)
	if err != nil {
		t.Fatalf("VerifyDS rejected last-record/last-candidate fixture: %v", err)
	}
	if unsupportedOnly {
		t.Fatal("supported SHA-256 DS fixture reported unsupported-only")
	}
	if digestOps < 1 || digestOps > fixture.expectedDigestOps {
		t.Fatalf("digest operations = %d, want within [1,%d]", digestOps, fixture.expectedDigestOps)
	}
}

func TestVerifyRRSIGExpiredWorkFactor(t *testing.T) {
	material := newWorkFactorKey(t)
	rrset := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "expired." + workFactorZone,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 3},
		},
	}
	now := time.Now()
	expired := signWorkFactorRRSet(
		t,
		material,
		rrset,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
	)

	// Establish that only the period is invalid; the expensive
	// cryptographic operation itself succeeds on this fixture.
	if err := expired.Verify(material.key, rrset); err != nil {
		t.Fatalf("expired fixture must remain cryptographically valid: %v", err)
	}
	cryptoOps := 0
	if err := verifyOneSig(
		map[uint16][]*dns.DNSKEY{material.key.KeyTag(): {material.key}},
		rrset,
		expired,
		func(key *dns.DNSKEY, sig *dns.RRSIG, set []dns.RR) error {
			cryptoOps++
			return cryptoVerify(key, sig, set)
		},
	); err != ErrInvalidSignaturePeriod {
		t.Fatalf("verifyOneSig error = %v, want %v", err, ErrInvalidSignaturePeriod)
	}
	if cryptoOps != 0 {
		t.Fatalf("expired signature reached %d crypto operations, want 0", cryptoOps)
	}
}

func TestNSEC3WorkFactorIterationBoundary(t *testing.T) {
	const qname = "name.work-factor.example."

	makeMatching := func(iterations uint16) *dns.NSEC3 {
		hash := dns.HashName(qname, dns.SHA1, iterations, "A1B2")
		return &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   hash + "." + workFactorZone,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Hash:       dns.SHA1,
			Iterations: iterations,
			Salt:       "A1B2",
			NextDomain: hash,
		}
	}

	atLimit := makeMatching(maxNSEC3Iterations)
	if _, err := findMatching(qname, []dns.RR{atLimit}); err != nil {
		t.Fatalf("NSEC3 at iteration limit must be usable: %v", err)
	}

	overLimit := makeMatching(maxNSEC3Iterations + 1)
	if _, err := findMatching(qname, []dns.RR{overLimit}); err != ErrNSECMissingCoverage {
		t.Fatalf("NSEC3 over iteration limit error = %v, want %v", err, ErrNSECMissingCoverage)
	}
}

func TestVerifyNameErrorNSEC3WorkFactorCountsHashCalls(t *testing.T) {
	const (
		qname       = "a.b.c.work-factor.example."
		recordCount = 2
	)

	for _, iterations := range []uint16{maxNSEC3Iterations, maxNSEC3Iterations + 1} {
		t.Run(fmt.Sprintf("iterations=%d", iterations), func(t *testing.T) {
			msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
			records := newWorkFactorNSEC3ProofRecords(iterations, recordCount)
			hashCalls := 0
			match := func(n *dns.NSEC3, name string) bool {
				hashCalls++
				return n.Match(name)
			}
			cover := func(n *dns.NSEC3, name string) bool {
				hashCalls++
				return n.Cover(name)
			}

			err := verifyNameErrorWith(msg, records, match, cover)
			if iterations <= maxNSEC3Iterations && err != nil {
				t.Fatalf("VerifyNameError error = %v, want nil", err)
			}
			if iterations > maxNSEC3Iterations && err != ErrNSECMissingCoverage {
				t.Fatalf("VerifyNameError error = %v, want %v", err, ErrNSECMissingCoverage)
			}

			expected := 0
			if iterations <= maxNSEC3Iterations {
				expected = (nsec3ClosestEncloserChecks(qname) + 4) * recordCount
			}
			if hashCalls != expected {
				t.Fatalf("NSEC3 hash calls = %d, want %d", hashCalls, expected)
			}
		})
	}
}

func BenchmarkVerifyRRSIGWorkFactor(b *testing.B) {
	cases := []struct {
		signatures int
		candidates int
	}{
		{signatures: 2, candidates: 2},
		{signatures: 8, candidates: 2},
		{signatures: 2, candidates: 8},
		{signatures: 8, candidates: 8},
	}

	for _, tc := range cases {
		name := fmt.Sprintf("signatures=%d/candidates=%d", tc.signatures, tc.candidates)
		b.Run(name, func(b *testing.B) {
			fixture := newWorkFactorRRSIGFixture(b, tc.signatures, tc.candidates)
			cryptoOps := 0
			b.ReportAllocs()

			for b.Loop() {
				before := cryptoOps
				ok, err := verifyRRSIGWith(
					workFactorZone,
					fixture.keys,
					fixture.msg,
					func(key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) error {
						cryptoOps++
						return cryptoVerify(key, sig, rrset)
					},
				)
				if err != nil || !ok {
					b.Fatalf("VerifyRRSIG() = (%v, %v), want (true, nil)", ok, err)
				}
				if got := cryptoOps - before; got < 1 || got > fixture.expectedCryptoOps {
					b.Fatalf("crypto operations = %d, want within [1,%d]", got, fixture.expectedCryptoOps)
				}
			}
			b.ReportMetric(float64(cryptoOps)/float64(b.N), "crypto-ops/op")
		})
	}
}

func BenchmarkVerifyDSWorkFactor(b *testing.B) {
	cases := []struct {
		ds         int
		candidates int
	}{
		{ds: 2, candidates: 2},
		{ds: 8, candidates: 2},
		{ds: 2, candidates: 8},
		{ds: 8, candidates: 8},
	}

	for _, tc := range cases {
		name := fmt.Sprintf("DS=%d/candidates=%d", tc.ds, tc.candidates)
		b.Run(name, func(b *testing.B) {
			fixture := newWorkFactorDSFixture(b, tc.ds, tc.candidates)
			digestOps := 0
			b.ReportAllocs()

			for b.Loop() {
				before := digestOps
				unsupportedOnly, err := verifyDSWith(
					fixture.keys,
					fixture.parentDSSet,
					func(key *dns.DNSKEY, digestType uint8) *dns.DS {
						digestOps++
						return key.ToDS(digestType)
					},
				)
				if err != nil || unsupportedOnly {
					b.Fatalf("VerifyDS() = (%v, %v), want (false, nil)", unsupportedOnly, err)
				}
				if got := digestOps - before; got < 1 || got > fixture.expectedDigestOps {
					b.Fatalf("digest operations = %d, want within [1,%d]", got, fixture.expectedDigestOps)
				}
			}
			b.ReportMetric(float64(digestOps)/float64(b.N), "digest-ops/op")
		})
	}
}

func BenchmarkVerifyRRSIGExpiredWorkFactor(b *testing.B) {
	for _, signatureCount := range []int{2, 8} {
		b.Run(fmt.Sprintf("signatures=%d", signatureCount), func(b *testing.B) {
			material := newWorkFactorKey(b)
			rrset := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "expired." + workFactorZone,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{192, 0, 2, 3},
				},
			}
			now := time.Now()
			msg := new(dns.Msg)
			msg.SetQuestion(rrset[0].Header().Name, dns.TypeA)
			msg.Answer = append(msg.Answer, rrset...)
			for range signatureCount {
				msg.Answer = append(msg.Answer, signWorkFactorRRSet(
					b,
					material,
					rrset,
					now.Add(-2*time.Hour),
					now.Add(-time.Hour),
				))
			}
			keys := map[uint16][]*dns.DNSKEY{
				material.key.KeyTag(): {material.key},
			}

			cryptoOps := 0
			b.ReportAllocs()
			for b.Loop() {
				if _, err := verifyRRSIGWith(
					workFactorZone,
					keys,
					msg,
					func(key *dns.DNSKEY, sig *dns.RRSIG, set []dns.RR) error {
						cryptoOps++
						return cryptoVerify(key, sig, set)
					},
				); err != ErrInvalidSignaturePeriod {
					b.Fatalf("VerifyRRSIG error = %v, want %v", err, ErrInvalidSignaturePeriod)
				}
			}
			if cryptoOps != 0 {
				b.Fatalf("expired signatures reached %d crypto operations, want 0", cryptoOps)
			}
			b.ReportMetric(float64(cryptoOps)/float64(b.N), "crypto-ops/op")
		})
	}
}

func newWorkFactorNSEC3ProofRecords(iterations uint16, count int) []dns.RR {
	records := make([]dns.RR, 0, count)
	for i := 0; i < count-1; i++ {
		// Tiny intervals near zero neither match nor cover any name in the
		// fixed fixture. They force every search to reach the final record.
		ownerHash := fmt.Sprintf("%032X", i*2)
		records = append(records, &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   ownerHash + "." + workFactorZone,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Hash:       dns.SHA1,
			Iterations: iterations,
			Salt:       "A1B2",
			NextDomain: fmt.Sprintf("%032X", i*2+1),
		})
	}

	// The final record proves the zone apex as the closest encloser. Its empty
	// interval covers both the next-closer and wildcard hashes, so a valid full
	// NXDOMAIN proof exercises Match and Cover all the way through the slice.
	apexHash := dns.HashName(workFactorZone, dns.SHA1, iterations, "A1B2")
	records = append(records, &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   apexHash + "." + workFactorZone,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: iterations,
		Salt:       "A1B2",
		NextDomain: apexHash,
	})
	return records
}

func nsec3ClosestEncloserChecks(qname string) int {
	checks := 0
	for _, labelIndex := range dns.Split(qname) {
		checks++
		if strings.EqualFold(qname[labelIndex:], workFactorZone) {
			return checks
		}
	}
	return checks
}

func BenchmarkVerifyNameErrorNSEC3WorkFactor(b *testing.B) {
	const qname = "a.b.c.d.e.f.work-factor.example."
	cases := []struct {
		name       string
		iterations uint16
		records    int
	}{
		{name: "iterations=0/records=2", iterations: 0, records: 2},
		{name: "iterations=150/records=2", iterations: maxNSEC3Iterations, records: 2},
		{name: "iterations=150/records=8", iterations: maxNSEC3Iterations, records: 8},
		{name: "iterations=151/records=8-skipped", iterations: maxNSEC3Iterations + 1, records: 8},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
			records := newWorkFactorNSEC3ProofRecords(tc.iterations, tc.records)
			expectedHashCalls := 0
			expectedSHA1Rounds := 0
			if tc.iterations <= maxNSEC3Iterations {
				if err := VerifyNameError(msg, records); err != nil {
					b.Fatalf("fixture must provide a complete NSEC3 name-error proof: %v", err)
				}
				expectedHashCalls = (nsec3ClosestEncloserChecks(qname) + 4) * tc.records
				expectedSHA1Rounds = expectedHashCalls * (int(tc.iterations) + 1)
			}

			hashCalls := 0
			sha1Rounds := 0
			match := func(n *dns.NSEC3, name string) bool {
				hashCalls++
				sha1Rounds += int(n.Iterations) + 1
				return n.Match(name)
			}
			cover := func(n *dns.NSEC3, name string) bool {
				hashCalls++
				sha1Rounds += int(n.Iterations) + 1
				return n.Cover(name)
			}

			b.ReportAllocs()
			for b.Loop() {
				beforeCalls, beforeRounds := hashCalls, sha1Rounds
				err := verifyNameErrorWith(msg, records, match, cover)
				if tc.iterations <= maxNSEC3Iterations && err != nil {
					b.Fatalf("VerifyNameError error = %v, want nil", err)
				}
				if tc.iterations > maxNSEC3Iterations && err != ErrNSECMissingCoverage {
					b.Fatalf("VerifyNameError error = %v, want %v", err, ErrNSECMissingCoverage)
				}
				if got := hashCalls - beforeCalls; got != expectedHashCalls {
					b.Fatalf("NSEC3 hash calls = %d, want %d", got, expectedHashCalls)
				}
				if got := sha1Rounds - beforeRounds; got != expectedSHA1Rounds {
					b.Fatalf("NSEC3 SHA-1 rounds = %d, want %d", got, expectedSHA1Rounds)
				}
			}
			b.ReportMetric(float64(hashCalls)/float64(b.N), "hash-calls/op")
			b.ReportMetric(float64(sha1Rounds)/float64(b.N), "sha1-rounds/op")
		})
	}
}
