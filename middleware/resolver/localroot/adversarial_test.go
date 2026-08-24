package localroot

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// TestVerifyZoneRefusesForeignSignerWithRealKSKPresent reproduces the
// verification bypass a review caught. The real root KSK is public
// knowledge, so an attacker builds a zone whose DNSKEY RRset CONTAINS the
// anchor-matching key while every signature — DNSKEY, SOA, ZONEMD — is made
// by a second key of their own, also in the set. Matching an anchor and
// signing the zone are different claims: the first alone proved nothing,
// and verifying signatures against the whole transferred set accepted the
// attacker's. The DNSKEY RRset must verify under anchor-matched keys only;
// nothing else promotes the rest of the set.
func TestVerifyZoneRefusesForeignSignerWithRealKSKPresent(t *testing.T) {
	victim := buildTestRoot(t) // its key plays the real KSK; its DS is the anchor

	var victimKey *dns.DNSKEY
	for _, rr := range victim.rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			victimKey = k
		}
	}
	if victimKey == nil {
		t.Fatal("victim zone has no DNSKEY")
	}

	// The attacker's own zone, rebuilt with the victim's key spliced into
	// the DNSKEY RRset. The set changed, so its RRSIG and the ZONEMD seal
	// are remade — with the ATTACKER's key, exactly as the attack would.
	az, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("attacker zone: %v", err)
	}
	var forged []dns.RR
	for _, rr := range az.RRs {
		if rr.Header().Rrtype == dns.TypeZONEMD {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok &&
			(sig.TypeCovered == dns.TypeZONEMD || sig.TypeCovered == dns.TypeDNSKEY) {
			continue
		}
		forged = append(forged, rr)
	}
	forged = append(forged, victimKey)

	sign := func(rrset []dns.RR) dns.RR {
		t.Helper()
		now := time.Now()
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name: ".", Rrtype: dns.TypeRRSIG,
				Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl,
			},
			TypeCovered: rrset[0].Header().Rrtype,
			Algorithm:   dns.ECDSAP256SHA256,
			OrigTtl:     rrset[0].Header().Ttl,
			Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			KeyTag:      az.Key.KeyTag(),
			SignerName:  ".",
		}
		if err := sig.Sign(az.Priv.(*ecdsa.PrivateKey), rrset); err != nil {
			t.Fatalf("attacker sign: %v", err)
		}
		return sig
	}

	var dnskeySet []dns.RR
	for _, rr := range forged {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			dnskeySet = append(dnskeySet, rr)
		}
	}
	forged = append(forged, sign(dnskeySet))

	digest, err := ComputeDigest(forged, ".")
	if err != nil {
		t.Fatalf("forged digest: %v", err)
	}
	zonemd := &dns.ZONEMD{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: 86400},
		Serial: roottest.Serial,
		Scheme: zonemdSchemeSimple,
		Hash:   zonemdHashSHA384,
		Digest: hex.EncodeToString(digest),
	}
	forged = append(forged, zonemd, sign([]dns.RR{zonemd}))

	// The anchor is the victim's DS, and the forged zone carries the key
	// that matches it — the zone must still be refused, because that key
	// signed nothing here.
	if err := verifyZone(forged, victim.anchors); err == nil {
		t.Fatal("a zone signed by a foreign key was accepted because the anchor-matching key rode along unsigned")
	}
}

// TestManagerRefusesSerialRollback pins RFC 1982 acceptance: an older,
// validly signed zone replayed at the manager cannot displace a newer copy
// — neither through Load nor by a probe steering a transfer. Without it a
// captured older root, still correctly signed for its day, could be fed
// back to reinstate withdrawn delegations and restart the expire horizon.
func TestManagerRefusesSerialRollback(t *testing.T) {
	newer, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("newer zone: %v", err)
	}
	// The same key signs both, so the replay is a genuine rollback within
	// one trust world rather than a chain failure.
	older, err := roottest.BuildZoneWithKey(
		ComputeDigest,
		roottest.DefaultLines(roottest.Serial-10),
		roottest.Serial-10,
		newer.Key,
		newer.Priv,
	)
	if err != nil {
		t.Fatalf("older zone: %v", err)
	}

	m := New(nil, func() []dns.RR { return newer.Anchors })
	if err := m.Load(newer.RRs); err != nil {
		t.Fatalf("load newer: %v", err)
	}
	// Sanity: the older zone is itself perfectly valid — it is refused for
	// being older, not for being unverifiable.
	if err := verifyZone(older.RRs, newer.Anchors); err != nil {
		t.Fatalf("the older zone must verify on its own merits: %v", err)
	}
	if err := m.Load(older.RRs); err == nil {
		t.Fatal("an older serial displaced the live copy")
	}
	if got := m.Active().Serial(); got != roottest.Serial {
		t.Fatalf("active serial = %d, want the newer %d", got, roottest.Serial)
	}

	// A source advertising the older serial must be skipped whole: nothing
	// it could transfer is acceptable, so it is not transferred from.
	transfers := 0
	m.probeFn = func(context.Context, string, time.Duration) (uint32, error) {
		return roottest.Serial - 10, nil
	}
	m.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) {
		transfers++
		return older.RRs, nil
	}
	if err := m.refreshOnce(context.Background()); err == nil {
		t.Fatal("a rollback-advertising source reported success")
	}
	if transfers != 0 {
		t.Fatalf("a rollback-advertising source was transferred from (%d times)", transfers)
	}
	if got := m.Active().Serial(); got != roottest.Serial {
		t.Fatalf("active serial = %d after the rollback attempt, want %d", got, roottest.Serial)
	}
}

// TestSerialNewer pins the RFC 1982 comparison itself, wrap included.
func TestSerialNewer(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{1, 2, true},
		{2, 1, false},
		{1, 1, false},
		{0xFFFFFFFF, 0, true},           // wrap forward
		{0, 0xFFFFFFFF, false},          // wrap backward
		{2026082401, 2026082400, false}, // a real rollback by one
	}
	for _, c := range cases {
		if got := serialNewer(c.a, c.b); got != c.want {
			t.Fatalf("serialNewer(%d, %d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestVerifyZoneRefusesDuplicateZONEMDTuple pins RFC 8976 §4 step 4: "When
// multiple ZONEMD RRs are present, each MUST specify a unique Scheme and
// Hash Algorithm tuple." The duplicate here is validly signed as part of
// the ZONEMD RRset and does not disturb the digest (apex ZONEMD records are
// excluded from it), so nothing else in the chain can catch it — only the
// uniqueness rule stands between a malformed RRset and a verifier that
// takes whichever digest it happens to read first.
func TestVerifyZoneRefusesDuplicateZONEMDTuple(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	var (
		base  []dns.RR
		first *dns.ZONEMD
	)
	for _, rr := range z.RRs {
		if md, ok := rr.(*dns.ZONEMD); ok {
			first = md
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			continue
		}
		base = append(base, rr)
	}
	if first == nil {
		t.Fatal("built zone has no apex ZONEMD")
	}

	// A second record with the same scheme/hash tuple, carrying a digest an
	// attacker (or a broken signer) chose.
	second := dns.Copy(first).(*dns.ZONEMD)
	second.Digest = strings.Repeat("ab", sha512.Size384)

	set := []dns.RR{first, second}
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: ".", Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: first.Hdr.Ttl,
		},
		TypeCovered: dns.TypeZONEMD,
		Algorithm:   dns.ECDSAP256SHA256,
		OrigTtl:     first.Hdr.Ttl,
		Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		KeyTag:      z.Key.KeyTag(),
		SignerName:  ".",
	}
	if err := sig.Sign(z.Priv.(*ecdsa.PrivateKey), set); err != nil {
		t.Fatalf("sign the two-record ZONEMD RRset: %v", err)
	}

	dup := make([]dns.RR, 0, len(base)+3)
	dup = append(dup, base...)
	dup = append(dup, first, second, sig)
	if err := verifyZone(dup, z.Anchors); err == nil {
		t.Fatal("a repeated ZONEMD scheme/hash tuple verified")
	}

	// Sanity: the same zone with the single original ZONEMD still verifies,
	// so the refusal above is the duplicate rule and nothing else.
	if err := verifyZone(z.RRs, z.Anchors); err != nil {
		t.Fatalf("the unmodified zone must still verify: %v", err)
	}
}

// TestDSAnswerRequiresProvableNODATA pins the unsigned-delegation proof: an
// exact-owner NSEC denies DS only when its type bitmap says so. A bitmap
// asserting DS contradicts the missing record — a truncated index, or a
// zone the copy did not fully hold — and must not be dressed as an
// authenticated NODATA.
func TestDSAnswerRequiresProvableNODATA(t *testing.T) {
	// org. has no DS record, but its NSEC claims the type exists.
	lines := []string{
		". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
		". 518400 IN NS a.root-servers.test.",
		". 86400 IN NSEC org. NS SOA RRSIG NSEC DNSKEY ZONEMD",
		"org. 172800 IN NS ns.org.",
		"org. 86400 IN NSEC . NS DS RRSIG NSEC",
		"ns.org. 172800 IN A 198.51.100.2",
	}
	z, err := roottest.BuildZone(ComputeDigest, lines, roottest.Serial)
	if err != nil {
		t.Fatalf("build zone: %v", err)
	}
	if err := verifyZone(z.RRs, z.Anchors); err != nil {
		t.Fatalf("the zone itself must verify — the defect is semantic: %v", err)
	}
	snap, err := buildSnapshot(z.RRs, time.Now())
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	if _, _, _, _, ok := snap.DSAnswer("org."); ok {
		t.Fatal("an NSEC whose bitmap asserts DS was served as a DS NODATA proof")
	}

	// The honest shape still answers: bitmap without DS proves the absence.
	honest, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}
	honestSnap, err := buildSnapshot(honest.RRs, time.Now())
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if _, _, nsec, _, ok := honestSnap.DSAnswer("org."); !ok || len(nsec) != 1 {
		t.Fatalf("the honest unsigned delegation must prove NODATA: ok=%v nsec=%d", ok, len(nsec))
	}
}

// TestVerifyZoneAcceptsUniqueTupleBesideDuplicates pins the scope of the
// duplicate rule. RFC 8976 §4 disqualifies "those ZONEMD RRs" that repeat a
// tuple — not the zone — and §4 step 5 adds that "a match using any one of
// the recipient's supported Schemes and Hash Algorithms is sufficient to
// verify the zone". So a zone carrying a repeated *unsupported* tuple
// alongside a sound unique SIMPLE/SHA-384 record still verifies through the
// latter; rejecting it outright would let a malformed record nobody uses
// deny an otherwise valid zone.
func TestVerifyZoneAcceptsUniqueTupleBesideDuplicates(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	var (
		base   []dns.RR
		simple *dns.ZONEMD
	)
	for _, rr := range z.RRs {
		if md, ok := rr.(*dns.ZONEMD); ok {
			simple = md
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			continue
		}
		base = append(base, rr)
	}
	if simple == nil {
		t.Fatal("built zone has no apex ZONEMD")
	}

	// Two records sharing an unsupported tuple, beside the sound one.
	unsupportedA := dns.Copy(simple).(*dns.ZONEMD)
	unsupportedA.Scheme = 240 // private-use scheme this build does not implement
	unsupportedA.Hash = 240
	unsupportedA.Digest = strings.Repeat("11", sha512.Size384)
	unsupportedB := dns.Copy(unsupportedA).(*dns.ZONEMD)
	unsupportedB.Digest = strings.Repeat("22", sha512.Size384)

	set := []dns.RR{simple, unsupportedA, unsupportedB}
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: ".", Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: simple.Hdr.Ttl,
		},
		TypeCovered: dns.TypeZONEMD,
		Algorithm:   dns.ECDSAP256SHA256,
		OrigTtl:     simple.Hdr.Ttl,
		Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		KeyTag:      z.Key.KeyTag(),
		SignerName:  ".",
	}
	if err := sig.Sign(z.Priv.(*ecdsa.PrivateKey), set); err != nil {
		t.Fatalf("sign the ZONEMD RRset: %v", err)
	}

	mixed := make([]dns.RR, 0, len(base)+4)
	mixed = append(mixed, base...)
	mixed = append(mixed, simple, unsupportedA, unsupportedB, sig)

	if err := verifyZone(mixed, z.Anchors); err != nil {
		t.Fatalf("a sound unique tuple beside duplicated unsupported ones must verify: %v", err)
	}
}
