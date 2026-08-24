package localroot

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
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
	if _, err := verifyZone(forged, victim.anchors); err == nil {
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
	if _, err := verifyZone(older.RRs, newer.Anchors); err != nil {
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
	if _, err := verifyZone(dup, z.Anchors); err == nil {
		t.Fatal("a repeated ZONEMD scheme/hash tuple verified")
	}

	// Sanity: the same zone with the single original ZONEMD still verifies,
	// so the refusal above is the duplicate rule and nothing else.
	if _, err := verifyZone(z.RRs, z.Anchors); err != nil {
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
	if _, err := verifyZone(z.RRs, z.Anchors); err != nil {
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

	if _, err := verifyZone(mixed, z.Anchors); err != nil {
		t.Fatalf("a sound unique tuple beside duplicated unsupported ones must verify: %v", err)
	}
}

// TestLoadPublishIsExclusive pins the publish decision. The serial check and
// the swap are one decision, not two: two loads that both observe the same
// older copy can each pass the check and then store in the opposite order,
// leaving the newer copy displaced by the older one. Every operation
// involved is individually legal, so the race detector reports nothing, and
// the window is a few instructions wide, so volume testing does not find it
// either — the section has to be held open to prove it is exclusive.
//
// Held open: the first load pauses between its check and its swap while a
// second load runs to completion with a newer serial. Under an exclusive
// section the second load waits, sees the first one's copy, and its newer
// serial wins. Without one, the paused load wakes and overwrites it.
func TestLoadPublishIsExclusive(t *testing.T) {
	base, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("base zone: %v", err)
	}
	// One key throughout, so all three copies chain to the same anchor and
	// the only thing separating them is the serial.
	zoneAt := func(serial uint32) []dns.RR {
		t.Helper()
		z, err := roottest.BuildZoneWithKey(
			ComputeDigest, roottest.DefaultLines(serial), serial, base.Key, base.Priv,
		)
		if err != nil {
			t.Fatalf("zone %d: %v", serial, err)
		}
		return z.RRs
	}
	const (
		oldest = roottest.Serial
		middle = roottest.Serial + 1
		newest = roottest.Serial + 2
	)

	m := New(nil, func() []dns.RR { return base.Anchors })
	if err := m.Load(zoneAt(oldest)); err != nil {
		t.Fatalf("seed load: %v", err)
	}

	paused := make(chan struct{})
	release := make(chan struct{})
	// Only the first load pauses, and later ones must pass straight
	// through: sync.Once would block them inside the hook instead, which
	// serializes the very overlap this test exists to create.
	var first atomic.Bool
	m.afterSerialCheck = func() {
		if first.CompareAndSwap(false, true) {
			close(paused)
			<-release
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = m.Load(zoneAt(middle)) // pauses inside the section
	}()

	<-paused
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = m.Load(zoneAt(newest))
	}()
	// Give the newer load every chance to slip past an unguarded section.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	active := m.Active()
	if active == nil {
		t.Fatal("no copy active after the loads")
	}
	if active.Serial() != newest {
		t.Fatalf("active serial = %d, want the newest %d — a paused load rolled the copy backwards",
			active.Serial(), newest)
	}
}

// TestSnapshotHorizonIgnoresUnverifiedZONEMDSignature pins which signatures
// may shorten a copy's life. RFC 8976 excludes the apex RRSIG(ZONEMD) from
// the digest — it is written after the digest is computed — and apex
// verification accepts an RRset when one covering signature validates. So
// an appended, already-expired RRSIG(ZONEMD) is the one record in a
// transfer that is neither authenticated by the digest nor rejected by
// verification, and trusting its expiration would let anyone who can add a
// record to a transfer expire a sound copy the moment it arrives.
func TestSnapshotHorizonIgnoresUnverifiedZONEMDSignature(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	// An RRSIG(ZONEMD) that expired a year ago, signed by nobody in
	// particular: the digest does not cover it and the sound sibling
	// signature still carries the RRset through verification.
	long, err := dns.NewRR(". 86400 IN RRSIG ZONEMD 13 0 86400 " +
		"20250824000000 20250810000000 12345 . AAAA")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	poisoned := make([]dns.RR, 0, len(z.RRs)+1)
	poisoned = append(poisoned, z.RRs...)
	poisoned = append(poisoned, long)

	if _, err := verifyZone(poisoned, z.Anchors); err != nil {
		t.Fatalf("the zone must still verify — the appended signature is not "+
			"part of the digest and a sound one covers the RRset: %v", err)
	}

	now := time.Now()
	snap, err := buildSnapshot(poisoned, now)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if snap.Expired(now) {
		t.Fatal("an appended expired RRSIG(ZONEMD) expired a sound copy on arrival")
	}
	// The horizon still follows the signatures that are authenticated: the
	// test zone signs with a one-hour window.
	if snap.ValidUntil().After(now.Add(2 * time.Hour)) {
		t.Fatalf("horizon %v ignores the authenticated signatures", snap.ValidUntil())
	}
}

// TestRefreshRejectsTransferBehindProbe pins the source's own claim as part
// of acceptance. A source that advertises N+1 and then hands back the
// current N has not delivered the update; taking it would mark the refresh
// successful and sleep a full refresh interval on a zone the source itself
// called stale. The transfer must carry at least what the probe announced,
// and a source that fails that is failed over rather than believed.
func TestRefreshRejectsTransferBehindProbe(t *testing.T) {
	root := buildTestRoot(t)

	m := New([]string{"stale.test:53", "honest.test:53"}, func() []dns.RR { return root.anchors })
	if err := m.Load(root.rrs); err != nil {
		t.Fatalf("seed load: %v", err)
	}

	bumped, err := roottest.BuildZoneWithKey(
		ComputeDigest,
		roottest.DefaultLines(roottest.Serial+1),
		roottest.Serial+1,
		root.key, root.priv,
	)
	if err != nil {
		t.Fatalf("bumped zone: %v", err)
	}

	// Both sources announce the bump; the first serves the old zone anyway.
	var served []string
	m.probeFn = func(_ context.Context, addr string, _ time.Duration) (uint32, error) {
		return roottest.Serial + 1, nil
	}
	m.transferFn = func(_ context.Context, addr string, _ time.Duration) ([]dns.RR, error) {
		served = append(served, addr)
		if addr == "stale.test:53" {
			return root.rrs, nil // the zone it just said was superseded
		}
		return bumped.RRs, nil
	}

	if err := m.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(served) != 2 {
		t.Fatalf("sources transferred from = %v, want the stale one to fail over", served)
	}
	if got := m.Active().Serial(); got != roottest.Serial+1 {
		t.Fatalf("active serial = %d, want the announced %d", got, roottest.Serial+1)
	}

	// And with only the stale source, the refresh must fail rather than
	// report success and sleep out the full interval.
	m2 := New([]string{"stale.test:53"}, func() []dns.RR { return root.anchors })
	if err := m2.Load(root.rrs); err != nil {
		t.Fatalf("seed load: %v", err)
	}
	m2.probeFn = m.probeFn
	m2.transferFn = func(context.Context, string, time.Duration) ([]dns.RR, error) {
		return root.rrs, nil
	}
	if err := m2.refreshOnce(context.Background()); err == nil {
		t.Fatal("a source that did not deliver what it announced reported success")
	}
}

// TestHorizonFollowsTheVerifyingZONEMDSignature is the other half of the
// poisoning fix. Skipping every apex RRSIG(ZONEMD) keeps an appended
// expired signature from expiring a sound copy, but the signature that
// actually carried the ZONEMD RRset through verification is what makes the
// digest evidence at all: authenticated data may not outlive the signature
// that authenticated it (RFC 4035 §5.3.3, RFC 8976 §6.4). So a zone whose
// real ZONEMD signature lapses in a minute must not be served for an hour
// on the strength of its longer-lived record signatures.
func TestHorizonFollowsTheVerifyingZONEMDSignature(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	// Re-sign the ZONEMD RRset with a one-minute validity, leaving every
	// other signature in the zone at its original hour.
	var (
		base   []dns.RR
		zonemd *dns.ZONEMD
	)
	for _, rr := range z.RRs {
		if md, ok := rr.(*dns.ZONEMD); ok {
			zonemd = md
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			continue
		}
		base = append(base, rr)
	}
	if zonemd == nil {
		t.Fatal("built zone has no apex ZONEMD")
	}

	now := time.Now()
	short := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: ".", Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: zonemd.Hdr.Ttl,
		},
		TypeCovered: dns.TypeZONEMD,
		Algorithm:   dns.ECDSAP256SHA256,
		OrigTtl:     zonemd.Hdr.Ttl,
		Expiration:  uint32(now.Add(time.Minute).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		Inception:   uint32(now.Add(-time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		KeyTag:      z.Key.KeyTag(),
		SignerName:  ".",
	}
	if err := short.Sign(z.Priv.(*ecdsa.PrivateKey), []dns.RR{zonemd}); err != nil {
		t.Fatalf("sign ZONEMD: %v", err)
	}

	shortLived := make([]dns.RR, 0, len(base)+2)
	shortLived = append(shortLived, base...)
	shortLived = append(shortLived, zonemd, short)

	m := New(nil, func() []dns.RR { return z.Anchors })
	if err := m.Load(shortLived); err != nil {
		t.Fatalf("the zone must verify — only its authentication is short: %v", err)
	}
	snap := m.Active()
	if snap == nil {
		t.Fatal("no copy active")
	}
	if got := snap.ValidUntil(); got.After(now.Add(2 * time.Minute)) {
		t.Fatalf("horizon %v outlives the signature that authenticated the digest (%v)",
			got, time.Unix(int64(short.Expiration), 0))
	}
	if !snap.Expired(now.Add(2 * time.Minute)) {
		t.Fatal("the copy is still active past the ZONEMD signature's expiration")
	}
}

// TestApexSignatureWorkIsBounded pins the cost of verifying an apex RRset.
// Apex RRSIG(ZONEMD) records sit outside the digest, so a transfer can
// carry any number of them, and verifying each in turn turns the generous
// transfer limits into cryptographic work — the refresh worker stalls for
// as long as an attacker cares to make it. Deduplication, descending
// expiration order and a small attempt cap bound it, and a sound zone
// still verifies on its first attempt.
func TestApexSignatureWorkIsBounded(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	var (
		base  []dns.RR
		sound *dns.RRSIG
	)
	for _, rr := range z.RRs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			sound = sig
			continue
		}
		base = append(base, rr)
	}
	if sound == nil {
		t.Fatal("built zone has no RRSIG(ZONEMD)")
	}

	// Thousands of forgeries, each claiming to outlive the sound signature
	// so ordering cannot skip them, each distinct so deduplication cannot
	// collapse them, and each the exact width RFC 6605 §4 gives a P-256
	// signature — a wrong length is refused before any public-key
	// operation, which would make this measure nothing at all.
	const forgeries = 4096
	flooded := make([]dns.RR, 0, len(base)+forgeries+1)
	flooded = append(flooded, base...)
	for i := range forgeries {
		raw := make([]byte, 64)
		binary.BigEndian.PutUint32(raw, uint32(i)+1) //nolint:gosec // bounded test index
		raw[40] = 0x7f                               // keep both halves non-trivial
		fake := dns.Copy(sound).(*dns.RRSIG)
		fake.Expiration = sound.Expiration + uint32(i) + 1 //nolint:gosec // bounded test index
		fake.Signature = base64.StdEncoding.EncodeToString(raw)
		flooded = append(flooded, fake)
	}
	flooded = append(flooded, sound)

	// The cap is in force: the sound signature sits below thousands of
	// higher-expiring forgeries, so it never gets an attempt and the zone
	// is refused. Denial is not a capability this hands anyone — whoever
	// can append these records can already break a digested one — but it
	// is the observable proof that the attempt window is bounded.
	start := time.Now()
	if _, err := verifyZone(flooded, z.Anchors); err == nil {
		t.Fatal("every attempt went to a forgery, yet the zone verified — the window is not bounded")
	}
	// And the refusal is cheap. Bounded, this is a handful of public-key
	// operations; unbounded it is one per forgery, which on this input
	// takes hundreds of milliseconds and scales with whatever a transfer
	// carries. The threshold is loose on purpose — it is a guard against
	// the work scaling, not a benchmark.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("verification of %d appended signatures took %v — the work is not bounded",
			forgeries, elapsed)
	}
}

// TestApexSignatureOrderPicksTheLatestVerifying pins what the ordering buys
// besides speed: stopping at the first signature that verifies is only
// correct because everything longer-lived was tried before it, so the one
// that stops the loop carries the latest expiration among those that would
// have verified at all.
func TestApexSignatureOrderPicksTheLatestVerifying(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	var (
		base   []dns.RR
		zonemd *dns.ZONEMD
		sound  *dns.RRSIG
	)
	for _, rr := range z.RRs {
		if md, ok := rr.(*dns.ZONEMD); ok {
			zonemd = md
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			sound = sig
			continue
		}
		base = append(base, rr)
	}
	if zonemd == nil || sound == nil {
		t.Fatal("built zone is missing its ZONEMD or its signature")
	}

	// A second sound signature over the same RRset, valid for a day rather
	// than the hour the first one carries. The copy must live to the later
	// of the two, since either one authenticates it.
	now := time.Now()
	longer := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: ".", Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: zonemd.Hdr.Ttl,
		},
		TypeCovered: dns.TypeZONEMD,
		Algorithm:   dns.ECDSAP256SHA256,
		OrigTtl:     zonemd.Hdr.Ttl,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		Inception:   uint32(now.Add(-time.Hour).Unix()),     //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		KeyTag:      z.Key.KeyTag(),
		SignerName:  ".",
	}
	if err := longer.Sign(z.Priv.(*ecdsa.PrivateKey), []dns.RR{zonemd}); err != nil {
		t.Fatalf("sign the longer-lived signature: %v", err)
	}

	// The shorter one first in the slice, so only the ordering can find the
	// longer — and a forgery claiming to outlive both, which must not.
	forged := dns.Copy(longer).(*dns.RRSIG)
	forged.Expiration = uint32(now.Add(72 * time.Hour).Unix()) //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
	forged.Signature = "AAAAAAAA"

	both := make([]dns.RR, 0, len(base)+4)
	both = append(both, base...)
	both = append(both, zonemd, sound, forged, longer)

	authUntil, err := verifyZone(both, z.Anchors)
	if err != nil {
		t.Fatalf("verifyZone: %v", err)
	}
	if want := time.Unix(int64(longer.Expiration), 0); !authUntil.Equal(want) {
		t.Fatalf("authenticated until %v, want the longer sound signature's %v", authUntil, want)
	}
}

// TestApexSignatureDedupeKeepsDistinctSignatures pins what "the same
// signature" means. Deduplication exists to keep a flood of identical
// copies from spending the attempt budget, but every field an RRSIG signs
// over is part of its identity: two records differing in one of them sign
// different data, so one may verify where the other cannot. Dedupe on less
// and a sound signature is discarded as a copy of the unsound sibling that
// happened to arrive first — the flood then succeeds by resemblance where
// it could not succeed by volume.
func TestApexSignatureDedupeKeepsDistinctSignatures(t *testing.T) {
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	var (
		base  []dns.RR
		sound *dns.RRSIG
	)
	for _, rr := range z.RRs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			sound = sig
			continue
		}
		base = append(base, rr)
	}
	if sound == nil {
		t.Fatal("built zone has no RRSIG(ZONEMD)")
	}

	// One decoy per field that the previous, narrower identity ignored and
	// that a decoy can actually vary here. Each carries the sound
	// signature's bytes and window, so a dedupe key missing that field
	// sees a duplicate and drops the sound record.
	//
	// The owner name is deliberately absent. Moving it off the apex takes
	// the record out of the set this function is handed, and — because
	// only apex RRSIG(ZONEMD) records are excluded from the digest — puts
	// it into the digest instead, where the mismatch refuses the zone
	// outright. That field is guarded by a different mechanism, not this
	// one, and asserting it here would be asserting the wrong defense.
	for _, tc := range []struct {
		field  string
		mangle func(*dns.RRSIG)
	}{
		{"OrigTtl", func(s *dns.RRSIG) { s.OrigTtl++ }},
		{"Labels", func(s *dns.RRSIG) { s.Labels++ }},
		{"SignerName", func(s *dns.RRSIG) { s.SignerName = "example." }},
		{"class", func(s *dns.RRSIG) { s.Hdr.Class = dns.ClassCHAOS }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			decoy := dns.Copy(sound).(*dns.RRSIG)
			tc.mangle(decoy)

			// The decoy first, so a collision would discard the sound one.
			withDecoy := make([]dns.RR, 0, len(base)+2)
			withDecoy = append(withDecoy, base...)
			withDecoy = append(withDecoy, decoy, sound)

			if _, err := verifyZone(withDecoy, z.Anchors); err != nil {
				t.Fatalf("a sound zone was refused because a sibling differing only "+
					"in %s was treated as the same signature: %v", tc.field, err)
			}
		})
	}
}
