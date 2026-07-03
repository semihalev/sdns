package dnssec

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signRRSet signs rrset with key/priv and returns the RRSIG. The
// validity window is now±6h so verifyOneSig's period check passes.
func signRRSet(t *testing.T, key *dns.DNSKEY, priv crypto.PrivateKey, rrset []dns.RR) *dns.RRSIG {
	t.Helper()

	hdr := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdr.Ttl},
		TypeCovered: hdr.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)), //nolint:gosec // G115 - test names have few labels
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(time.Now().Add(6 * time.Hour).Unix()),  //nolint:gosec // G115 - RFC 4034 serial-arithmetic timestamp
		Inception:   uint32(time.Now().Add(-6 * time.Hour).Unix()), //nolint:gosec // G115 - RFC 4034 serial-arithmetic timestamp
		KeyTag:      key.KeyTag(),
		SignerName:  key.Header().Name,
	}
	if err := sig.Sign(priv.(crypto.Signer), rrset); err != nil {
		t.Fatalf("failed to sign %s %s: %s", hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}
	return sig
}

func makeZoneKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.PrivateKey) {
	t.Helper()

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("failed to generate zone key for %s: %s", zone, err)
	}
	return key, priv
}

// Test_VerifyRRSIG_ForeignReferralInAuthority reproduces issue #506
// (variant 2, www.edpb.europa.eu): an authoritative server that hosts
// both the signer zone and ancestors of the CNAME target answers with
// a validly signed CNAME in ANSWER plus a referral for the target in
// AUTHORITY — NS records for the target's zone cut and an NSEC proving
// its insecure delegation, both owned by names OUTSIDE the signer zone
// (on the wire the NSEC is signed by the parent zone, and that RRSIG's
// owner is equally out-of-zone).
//
// Wire shape captured live from ans1.cw.net for
// "www.edpb.europa.eu. IN AAAA":
//
//	;; ANSWER:    www.edpb.europa.eu. CNAME 51da….alb.prd.dhs.tech.ec.europa.eu.
//	;;            www.edpb.europa.eu. RRSIG CNAME … edpb.europa.eu. …
//	;; AUTHORITY: dhs.tech.ec.europa.eu. NS ns-520.awsdns-01.net.
//	;;            dhs.tech.ec.europa.eu. NSEC dke.tech.ec.europa.eu. NS RRSIG NSEC
//	;;            dhs.tech.ec.europa.eu. RRSIG NSEC … europa.eu. …
//
// The referral remnant is advisory (RFC 2181 §5.4.1 ranks it below
// answer data; the resolver re-resolves the CNAME target through its
// own validated recursion), so it must not bogus the answer: the
// in-zone CNAME validates and VerifyRRSIG must succeed. The buggy
// collect() guard instead hard-fails with ErrMissingSigned.
func Test_VerifyRRSIG_ForeignReferralInAuthority(t *testing.T) {
	signerZone := "edpb.example."
	key, priv := makeZoneKey(t, signerZone)
	keys := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.edpb.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "51da7994.alb.prd.dhs.tech.ec.example.",
	}
	cnameSig := signRRSet(t, key, priv, []dns.RR{cname})

	// Referral remnant for the CNAME target's zone cut — owner names
	// live under ec.example., outside the signer zone.
	foreignNS := &dns.NS{
		Hdr: dns.RR_Header{Name: "dhs.tech.ec.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 7200},
		Ns:  "ns-520.awsdns-01.example.",
	}
	foreignNSEC := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "dhs.tech.ec.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 1800},
		NextDomain: "dke.tech.ec.example.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}

	msg := new(dns.Msg)
	msg.SetQuestion("www.edpb.example.", dns.TypeAAAA)
	msg.Answer = []dns.RR{cname, cnameSig}
	msg.Ns = []dns.RR{foreignNS, foreignNSEC}

	ok, err := VerifyRRSIG(signerZone, keys, msg)
	if err != nil {
		t.Fatalf("BUG REPRODUCED (issue #506 variant 2): a validly signed CNAME answer "+
			"was rejected because the authority section carries the upstream's referral "+
			"remnant for the CNAME target (out-of-zone NS+NSEC): %s", err)
	}
	if !ok {
		t.Fatal("expected the in-zone CNAME RRset to validate")
	}
}

// Test_VerifyRRSIG_ForeignRecordInAnswerStaysBogus pins the guard the
// referral fix must NOT relax: an unsigned out-of-zone RRset inside the
// ANSWER section is attacker-piggybacked data riding on a signed
// response (RFC 4035 §3.2.3) and must keep failing validation.
func Test_VerifyRRSIG_ForeignRecordInAnswerStaysBogus(t *testing.T) {
	signerZone := "edpb.example."
	key, priv := makeZoneKey(t, signerZone)
	keys := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.edpb.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "51da7994.alb.prd.dhs.tech.ec.example.",
	}
	cnameSig := signRRSet(t, key, priv, []dns.RR{cname})

	// Unsigned foreign A record spliced into the ANSWER section.
	foreignA := &dns.A{
		Hdr: dns.RR_Header{Name: "51da7994.alb.prd.dhs.tech.ec.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 66},
	}

	msg := new(dns.Msg)
	msg.SetQuestion("www.edpb.example.", dns.TypeAAAA)
	msg.Answer = []dns.RR{cname, cnameSig, foreignA}

	if _, err := VerifyRRSIG(signerZone, keys, msg); err == nil {
		t.Fatal("an unsigned out-of-zone RRset in the ANSWER section must stay bogus")
	}
}
