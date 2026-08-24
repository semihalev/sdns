package localroot

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
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
