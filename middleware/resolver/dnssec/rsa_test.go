package dnssec

import (
	"crypto"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Live mailbox.org records (issue #495). Both ZSKs that sign the answer
// RRsets carry the RSA exponent 2^32+1, which crypto/rsa and miekg/dns
// refuse to load. The captured (key, RRSIG, RRset) triples stay
// cryptographically valid regardless of the signature's validity period,
// so this is a stable regression fixture.
const (
	mboxA = "mailbox.org.\t103\tIN\tA\t185.97.174.35"

	mboxZSK7 = "mailbox.org.\t900\tIN\tDNSKEY\t256 3 7 BQEAAAABwcvTaaZokGcz2HFSgv+ixKiuypnYzA3z/pu9MlZ1XFD2qeN7KgVB/mmlvFKDUgKdraUV2m2KglZLzc4d8GoXTnpLDhcWVJx9et9tDYVUzzrXyW6SL/mEYUIoK9KvVP5gTUxU9eRr0qohT36SL7QdPR16Lig7jANGeCQKLsJNQ08="
	mboxSig7 = "mailbox.org.\t103\tIN\tRRSIG\tA 7 2 300 20260718040026 20260618032642 5719 mailbox.org. FgIdLjsHQLDsW9fpes/6EDksB2oI3VxuB/6Qvh1o/253/rlZzD75RpKkUWDWbbTe404nJY/IohlwyRoreekI0OsvRCLLleFwHKlTEH68lKOLk3wrnTDNI9dclfJwSZR27hXUro5E7Oghv0huMcd0Tbwv+yRa01bBVIJEkjVdkqU="

	mboxZSK10 = "mailbox.org.\t900\tIN\tDNSKEY\t256 3 10 BQEAAAAB1LEf+LUCBcflBj5sFAJiZnhv9WBP8lVkaau+VW9vVV4soJ/Q7UJz+pbhMPDFicgzArADejYML+zl8Lkn9vRRd+pu2iQ/vZnfpKQkuNCcd7eba4JSG24cO7TVLCdfsGJqvNgoN15mMUXKnTbhP+nFq9mfGIjKBTELekqkkYLl3zs="
	mboxSig10 = "mailbox.org.\t103\tIN\tRRSIG\tA 10 2 300 20260718040026 20260618032642 48028 mailbox.org. cyHbFb33mr/jHoVF1QAbpjaJR47byFwJnC+rgn2u18YRXRM+aekUl0T2ZcILL8nsGwnlrd7FDAU4/mP+lVZ25/bZZ8CMQpVKdvL4R1JbQ7JRapB7sAZCbc5Br7qLSjud7/BYY5HNuQNllaWEVr0yJNVvU6kakhRj76YtMddaLeM="
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return rr
}

func TestVerifyRSAWideExponent_LiveMailbox(t *testing.T) {
	a := mustRR(t, mboxA)

	cases := []struct {
		name, key, sig string
	}{
		{"alg7 ZSK 5719", mboxZSK7, mboxSig7},
		{"alg10 ZSK 48028", mboxZSK10, mboxSig10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustRR(t, tc.key).(*dns.DNSKEY)
			sig := mustRR(t, tc.sig).(*dns.RRSIG)

			if !rsaExponentExceedsStdlib(key.PublicKey) {
				t.Fatal("expected exponent to exceed stdlib ceiling")
			}
			if err := verifyRSAWideExponent(key, sig, []dns.RR{a}); err != nil {
				t.Fatalf("verifyRSAWideExponent: %v", err)
			}
		})
	}
}

func TestVerifyRSAWideExponent_TamperedSignature(t *testing.T) {
	key := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	sig := mustRR(t, mboxSig7).(*dns.RRSIG)

	// Flip the answer so the signature no longer covers it.
	bad := mustRR(t, "mailbox.org.\t103\tIN\tA\t185.97.174.36")
	if err := verifyRSAWideExponent(key, sig, []dns.RR{bad}); err == nil {
		t.Fatal("expected verification failure for tampered RRset")
	}
}

// TestVerifyRSAWideExponent_MatchesMiekg proves the hand-rolled canonical
// signed-data construction is byte-identical to miekg/dns': a signature
// miekg produces and accepts must also pass our raw path.
func TestVerifyRSAWideExponent_MatchesMiekg(t *testing.T) {
	for _, alg := range []uint8{dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512} {
		t.Run(dns.AlgorithmToString[alg], func(t *testing.T) {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "Example.ORG.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     256,
				Protocol:  3,
				Algorithm: alg,
			}
			priv, err := key.Generate(1024)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			// A multi-record RRset with mixed case and embedded names to
			// exercise canonical sorting and RDATA name lowercasing.
			rrset := []dns.RR{
				mustRR(t, "MX.Example.org.\t300\tIN\tMX\t20 Backup.Example.Org."),
				mustRR(t, "MX.Example.org.\t300\tIN\tMX\t10 Mail.Example.Org."),
			}
			sig := &dns.RRSIG{
				Hdr:        dns.RR_Header{Name: "mx.example.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				Algorithm:  alg,
				Expiration: 1<<32 - 1,
				Inception:  0,
				KeyTag:     key.KeyTag(),
				SignerName: key.Hdr.Name,
			}
			if err := sig.Sign(priv.(crypto.Signer), rrset); err != nil {
				t.Fatalf("sign: %v", err)
			}

			// Sanity: miekg accepts its own signature.
			if err := sig.Verify(key, rrset); err != nil {
				t.Fatalf("miekg Verify rejected its own signature: %v", err)
			}
			// Cross-check: our raw path agrees byte-for-byte.
			if err := verifyRSAWideExponent(key, sig, rrset); err != nil {
				t.Fatalf("verifyRSAWideExponent disagreed with miekg: %v", err)
			}

			// Altered RDATA must fail.
			tampered := append([]dns.RR(nil), rrset...)
			tampered[0] = mustRR(t, "MX.Example.org.\t300\tIN\tMX\t20 Evil.Example.Org.")
			if err := verifyRSAWideExponent(key, sig, tampered); err == nil {
				t.Fatal("expected failure for tampered RRset")
			}
		})
	}
}

func TestRSAExponentExceedsStdlib(t *testing.T) {
	// Normal exponent 65537 -> within stdlib range.
	ksk := mustRR(t, "mailbox.org.\t900\tIN\tDNSKEY\t257 3 7 AwEAAdAx4Z+YqK6hogFjzM7TddRVDK9lE5WY9qTmWRwxAHDWYOOVV4b/N6FksRFWXV3rXfMIiyXRfdzt1Lnwt3rS2v9nYRCNlg1FDLHGwyDwV/I0D6CwgeZbTX7PSOL4oR0nFE1BYCbE2bHckgVE33tDF5fasDU0jXF00T9DPAhO0rxj").(*dns.DNSKEY)
	if rsaExponentExceedsStdlib(ksk.PublicKey) {
		t.Error("KSK exponent 65537 should be within stdlib range")
	}
	zsk := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	if !rsaExponentExceedsStdlib(zsk.PublicKey) {
		t.Error("ZSK exponent 2^32+1 should exceed stdlib range")
	}
	if rsaExponentExceedsStdlib("@@not base64@@") {
		t.Error("unparsable key should not be reported as wide-exponent")
	}
}

func TestUsableRSAKey(t *testing.T) {
	big1024 := new(big.Int).Lsh(big.NewInt(1), 1023)                 // exactly 1024 bits
	tooBig := new(big.Int).Lsh(big.NewInt(1), maxRSAModulusBits)     // maxRSAModulusBits+1 bits
	wideExp := new(big.Int).Lsh(big.NewInt(1), maxRSAExponentBits+1) // exponent over the cap
	wideExp.SetBit(wideExp, 0, 1)                                    // make it odd

	cases := []struct {
		name string
		n, e *big.Int
		want bool
	}{
		{"valid wide exponent", big1024, big.NewInt(4294967297), true},
		{"valid 65537", big1024, big.NewInt(65537), true},
		{"modulus too small", big.NewInt(7), big.NewInt(3), false},
		{"modulus too large", tooBig, big.NewInt(65537), false},
		{"even exponent", big1024, big.NewInt(4), false},
		{"exponent too small", big1024, big.NewInt(1), false},
		{"exponent >= modulus", big.NewInt(5), big.NewInt(5), false},
		{"exponent too wide", big1024, wideExp, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := usableRSAKey(tc.n, tc.e); got != tc.want {
				t.Errorf("usableRSAKey = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseRSAPublicKey_NonCanonical confirms a prohibited leading-zero
// exponent byte is rejected (matches miekg/dns), since such an encoding
// changes the key tag and is never emitted by a conformant signer.
func TestParseRSAPublicKey_NonCanonical(t *testing.T) {
	modulus := make([]byte, 128) // 1024-bit modulus placeholder
	modulus[0] = 0x80
	// explen=2, exponent bytes 0x00 0x01 -> non-canonical leading zero.
	keybuf := append([]byte{0x02, 0x00, 0x01}, modulus...)
	if _, _, ok := parseRSAPublicKey(base64.StdEncoding.EncodeToString(keybuf)); ok {
		t.Fatal("expected non-canonical leading-zero exponent to be rejected")
	}
	// Canonical counterpart (explen=1, 0x03) must parse.
	keybuf = append([]byte{0x01, 0x03}, modulus...)
	if _, _, ok := parseRSAPublicKey(base64.StdEncoding.EncodeToString(keybuf)); !ok {
		t.Fatal("canonical key should parse")
	}

	// Leading-zero modulus byte -> rejected.
	zeroMod := make([]byte, 129)
	zeroMod[1] = 0x80
	keybuf = append([]byte{0x01, 0x03}, zeroMod...)
	if _, _, ok := parseRSAPublicKey(base64.StdEncoding.EncodeToString(keybuf)); ok {
		t.Fatal("expected non-canonical leading-zero modulus to be rejected")
	}
}

// TestVerifyRSAWideExponent_NonCanonicalModulus reproduces the Codex finding:
// padding two leading zero bytes into the modulus leaves the value and the
// key tag unchanged (an even byte count preserves the checksum), so it
// survives candidate lookup — but the canonical-encoding check must reject it.
func TestVerifyRSAWideExponent_NonCanonicalModulus(t *testing.T) {
	key := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	sig := mustRR(t, mboxSig7).(*dns.RRSIG)
	a := mustRR(t, mboxA)

	kb, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	modoff := 1 + int(kb[0]) // single-byte exponent length for this key
	padded := append([]byte{}, kb[:modoff]...)
	padded = append(padded, 0x00, 0x00)
	padded = append(padded, kb[modoff:]...)
	key.PublicKey = base64.StdEncoding.EncodeToString(padded)

	if key.KeyTag() != sig.KeyTag {
		t.Fatalf("zero padding changed key tag to %d; test premise invalid", key.KeyTag())
	}
	if err := verifyRSAWideExponent(key, sig, []dns.RR{a}); err == nil {
		t.Fatal("expected non-canonical modulus to be rejected")
	}
}

// TestVerifyRSAWideExponent_Preflight confirms the raw path rejects a key
// whose algorithm/tag no longer binds to the signature, mirroring miekg's
// RRSIG.Verify preflight (Codex review finding).
func TestVerifyRSAWideExponent_Preflight(t *testing.T) {
	a := mustRR(t, mboxA)
	sig := mustRR(t, mboxSig7).(*dns.RRSIG) // alg 7

	mismatched := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	mismatched.Algorithm = dns.RSASHA1 // alg 5: same hash family, but != sig alg 7
	if err := verifyRSAWideExponent(mismatched, sig, []dns.RR{a}); err == nil {
		t.Fatal("expected rejection on algorithm/key-tag mismatch")
	}
}

// Guard against accidentally widening the normal-key path: a routine
// 65537 key must still route through miekg, not the raw verifier.
func TestCryptoVerify_NormalKeyUsesMiekg(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	priv, err := key.Generate(1024)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rrset := []dns.RR{mustRR(t, "example.org.\t300\tIN\tA\t192.0.2.1")}
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		Algorithm:  dns.RSASHA256,
		Expiration: 1<<32 - 1,
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	if err := sig.Sign(priv.(crypto.Signer), rrset); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(key.PublicKey, " ") {
		t.Fatal("unexpected space in public key")
	}
	if err := cryptoVerify(key, sig, rrset); err != nil {
		t.Fatalf("cryptoVerify: %v", err)
	}
}

// Live .lv records (Latvia ccTLD). Its apex KSK (keytag 42018, alg 8
// RSASHA256) -- the key the root DS pins -- uses exponent 2^32+1, so SDNS
// v1.7.0 cannot validate the .lv DNSKEY RRset and downgrades the entire TLD
// to insecure (no AD), confirmed against the live resolver at 195.244.44.44.
// The KSK self-signature over the DNSKEY RRset is a durable crypto fixture
// (verifyRSAWideExponent performs no validity-period check).
const (
	lvZSK    = "lv.\t1656\tIN\tDNSKEY\t256 3 8 AwEAAcDygkF9GrWafQuFEgldV8cU2zKs//pQvWGt6Mr12kw+IH3ILlzGQodUem6BhD0/zEsbfy/KiHiQ7QbcXBn7etz70bmHzb/ovH3//uNfjFfUgBdcFbtTRoYA1Hk67ibAI/1phRsOkdycOnk85monJ8fakMVG+7IMoeAcp2S+XBKMfK7aaMTCjG8nRmVyw4m2PnHiiGrwPfEJQBy80SuSbECn5CMMYhmpLn9EzvW33itnM3lCy2rBZj2spPiCzlZEnTeLNgp/Tao45kselo6zN+WhmDLzi2Om86wnO5YYCtadCKVZAWNAc4gMC5OKKPIV8WMuIrcyMp5NI89nioHf+zM="
	lvKSK    = "lv.\t1656\tIN\tDNSKEY\t257 3 8 BQEAAAAByLU9dUcHHcl1eLgjLidTJKlwxsU9a580xierZ+WyfRBI47L3LLXAZZ0ub6Sea3qKP2mhP5ZBG/reXvyh3OSlHa39WoMiUUZFcuouCajBg7XeLGVPL4U1Ja1UW9wq/Oc8WU1dq4e+2Q8Dt8tipFvbL0AD0BhJAsfQuT3wperedwQAUKId0/JQOFNTWhEJaYN2P5IIhyRKWQp8OhtKmdNYQ5jfqqpXVO4zyqV+4ZxWurXJS8c7bKrE3OAewWEGAtTjeElfQ2CFAKWVjMOLeZ86+mgw7p3UHhGB+KuRaKg6fAtTcQYBF78Xe40wuj9EgGL19mp9v6tDwFe+Epow4SFSPQ=="
	lvSigKSK = "lv.\t1656\tIN\tRRSIG\tDNSKEY 8 1 1800 20260703000353 20260622230632 42018 lv. S5DSStcFkgmR3lYS1Woyv0SU3esPn3RLlqGhKGShVo6dgUPA2of1ZNz00JYs5+/da204qVqRHrnzoWK4Dszpc/5wnu9P2gDCdWrjk8cSc7yla/3tiDc9tC6WKNzUwHQp3DMa711CFInDIN73cpZ//whWjt4FYnExn8O2UQtaSUebx56CUKzh1hSnt9A3Gc+PIKXVH5lzaMxoDiZ4zdYR9mv5BtYZ/gxNBlPF6a0kI7ZnZEwi3z2Qh2X+v8SP767C57R0HIb98o+qxAq4f8XJ9DfgR5nCULY8u+ypDALOi3SkZCoqBapKhWYh+ASzQ8ytWsxmL83tI5mgGLrcqXn56g=="
)

func TestVerifyRSAWideExponent_LiveLatviaTLD(t *testing.T) {
	zsk := mustRR(t, lvZSK)
	ksk := mustRR(t, lvKSK).(*dns.DNSKEY)
	sig := mustRR(t, lvSigKSK).(*dns.RRSIG)

	if ksk.KeyTag() != 42018 || !rsaExponentExceedsStdlib(ksk.PublicKey) {
		t.Fatalf("unexpected .lv KSK: tag=%d wide=%v", ksk.KeyTag(), rsaExponentExceedsStdlib(ksk.PublicKey))
	}
	// The DS-pinned KSK must validate the apex DNSKEY RRset (alg 8).
	if err := verifyRSAWideExponent(ksk, sig, []dns.RR{zsk, ksk}); err != nil {
		t.Fatalf(".lv DNSKEY RRset failed to validate via wide-exponent KSK: %v", err)
	}
}
