// Package roottest builds a miniature signed root zone for tests: an apex
// with SOA/NS/DNSKEY/NSEC sealed by a ZONEMD, a signed delegation (com.,
// with DS), an unsigned delegation (org., NSEC without the DS bit), and
// in-zone glue. Everything chains from one generated CSK whose DS is the
// returned trust anchor. Nothing here runs outside test binaries.
package roottest

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// errZeroKeyTag reports that key generation kept producing the one tag value
// a signer refuses. Reaching it means the generator is not random.
var errZeroKeyTag = errors.New("roottest: could not generate a key with a non-zero tag")

// Serial is the zone serial every default-built zone carries.
const Serial = 2026082401

// Zone is one built test root.
type Zone struct {
	RRs     []dns.RR
	Anchors []dns.RR // the CSK's DS — the trust anchor the zone chains to
	Key     *dns.DNSKEY
	Priv    crypto.PrivateKey
}

// DefaultLines is the default zone body: a signed com. delegation, an
// unsigned org. delegation, and in-zone glue. serial lands in the SOA.
func DefaultLines(serial uint32) []string {
	return []string{
		fmt.Sprintf(". 86400 IN SOA a.root-servers.test. nstld.test. %d 1800 900 604800 86400", serial),
		". 518400 IN NS a.root-servers.test.",
		". 86400 IN NSEC com. NS SOA RRSIG NSEC DNSKEY ZONEMD",
		"com. 172800 IN NS ns.com.",
		"com. 86400 IN DS 12345 13 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE58AB7A66C82AABE7A9E10F53",
		"com. 86400 IN NSEC org. NS DS RRSIG NSEC",
		"org. 172800 IN NS ns.org.",
		"org. 86400 IN NSEC . NS RRSIG NSEC",
		// Glue for the root's own NS target, as the real root zone carries
		// it: unsigned, and the additional section of a priming answer.
		"a.root-servers.test. 172800 IN A 198.51.100.53",
		"a.root-servers.test. 172800 IN AAAA 2001:db8::53",
		"ns.com. 172800 IN A 198.51.100.1",
		"ns.com. 172800 IN AAAA 2001:db8::1",
		"ns.org. 172800 IN A 198.51.100.2",
	}
}

// Build generates a fresh key and assembles the sealed default zone. digest
// is the RFC 8976 computation to seal with — localroot.ComputeDigest in
// every real caller; a parameter so this package does not import the one it
// exists to test.
func Build(digest func(rrs []dns.RR, apex string) ([]byte, error)) (*Zone, error) {
	return BuildZone(digest, DefaultLines(Serial), Serial)
}

// BuildZone assembles and seals a zone from the given body lines, whose SOA
// must carry serial, under a freshly generated key.
func BuildZone(digest func(rrs []dns.RR, apex string) ([]byte, error), lines []string, serial uint32) (*Zone, error) {
	// A key tag is a checksum over the key's own bytes, so roughly one
	// generated key in 65536 lands on zero — and miekg's signer rejects a
	// zero tag outright ("dns: bad key"), which surfaced as a rare, entirely
	// unrelated-looking test failure. Draw again rather than sign with it.
	// The loop is bounded: it can only repeat if the generator keeps landing
	// on that one value out of 65536.
	for range 8 {
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
			Flags:     257,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv, err := key.Generate(256)
		if err != nil {
			return nil, err
		}
		if key.KeyTag() == 0 {
			continue
		}
		return BuildZoneWithKey(digest, lines, serial, key, priv)
	}
	return nil, errZeroKeyTag
}

// BuildZoneWithKey is BuildZone under an existing key, so a test can produce
// two zones — different serials, different contents — that chain to the same
// trust anchor.
func BuildZoneWithKey(
	digest func(rrs []dns.RR, apex string) ([]byte, error),
	lines []string,
	serial uint32,
	key *dns.DNSKEY,
	priv crypto.PrivateKey,
) (*Zone, error) {
	zone := make([]dns.RR, 0, len(lines)+8)
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			return nil, fmt.Errorf("test zone RR %q: %w", l, err)
		}
		zone = append(zone, rr)
	}
	zone = append(zone, key)

	sign := func(rrset []dns.RR) (dns.RR, error) {
		now := time.Now()
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG,
				Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl,
			},
			TypeCovered: rrset[0].Header().Rrtype,
			Algorithm:   dns.ECDSAP256SHA256,
			Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)), //nolint:gosec // test names are tiny
			OrigTtl:     rrset[0].Header().Ttl,
			Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			KeyTag:      key.KeyTag(),
			SignerName:  ".",
		}
		if err := sig.Sign(priv.(*ecdsa.PrivateKey), rrset); err != nil {
			return nil, err
		}
		return sig, nil
	}

	// Sign what the real root signs: every authoritative RRset. Delegation
	// NS sets at the TLDs stay unsigned; glue stays unsigned.
	group := make(map[string]map[uint16][]dns.RR)
	for _, rr := range zone {
		owner := dns.CanonicalName(rr.Header().Name)
		if group[owner] == nil {
			group[owner] = make(map[uint16][]dns.RR)
		}
		group[owner][rr.Header().Rrtype] = append(group[owner][rr.Header().Rrtype], rr)
	}
	for owner, sets := range group {
		for rtype, set := range sets {
			if owner == "." || rtype == dns.TypeDS || rtype == dns.TypeNSEC {
				sig, err := sign(set)
				if err != nil {
					return nil, err
				}
				zone = append(zone, sig)
			}
		}
	}

	// Seal with ZONEMD last: the digest excludes the apex ZONEMD and its
	// RRSIG by rule, so sealing after signing digests exactly the zone.
	sum, err := digest(zone, ".")
	if err != nil {
		return nil, err
	}
	zonemd := &dns.ZONEMD{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: 86400},
		Serial: serial,
		Scheme: 1,
		Hash:   1,
		Digest: hex.EncodeToString(sum),
	}
	zonemdSig, err := sign([]dns.RR{zonemd})
	if err != nil {
		return nil, err
	}
	zone = append(zone, zonemd, zonemdSig)

	ds := key.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 172800

	return &Zone{RRs: zone, Anchors: []dns.RR{ds}, Key: key, Priv: priv}, nil
}
