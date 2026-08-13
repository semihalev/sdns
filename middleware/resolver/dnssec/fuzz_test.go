package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// FuzzNsecCovers fuzzes the NSEC coverage check function
// This is security-critical for DNSSEC validation.
func FuzzNsecCovers(f *testing.F) {
	f.Add("a.example.com.", "z.example.com.", "m.example.com.")
	f.Add("example.com.", "example.com.", "test.example.com.")
	f.Add("a.example.com.", "c.example.com.", "b.example.com.")
	f.Add("z.example.com.", "a.example.com.", "m.example.com.") // wrap case
	f.Add(".", ".", "example.com.")
	f.Add("EXAMPLE.COM.", "test.example.com.", "foo.example.com.")
	f.Add("", "", "")
	f.Add("a.", "b.", "a.")

	f.Fuzz(func(t *testing.T, owner, next, name string) {
		_ = nsecCovers(owner, next, name)
	})
}

// FuzzRSAPublicKey fuzzes the RFC 3110 RSA public key parsing that feeds
// the wide-exponent verification path.
func FuzzRSAPublicKey(f *testing.F) {
	f.Add("AQAB") // Common RSA exponent 65537
	f.Add("Aw==") // Exponent 3
	f.Add("")
	f.Add("!!!invalid-base64!!!")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
	f.Add("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3")
	f.Add("BQEAAAABwcvTaaZokGcz2HFSgv+ixKiuypnYzA3z") // 5-byte exponent

	f.Fuzz(func(t *testing.T, key string) {
		_ = rsaExponentExceedsStdlib(key)
		if n, e, ok := parseRSAPublicKey(key); ok {
			_ = usableRSAKey(n, e)
		}
	})
}

// FuzzFromBase64 fuzzes the base64 decoder.
func FuzzFromBase64(f *testing.F) {
	f.Add([]byte("AQAB"))
	f.Add([]byte(""))
	f.Add([]byte("!!!"))
	f.Add([]byte("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = fromBase64(data)
	})
}

// FuzzVerifyNSEC fuzzes NSEC type bitmap verification.
func FuzzVerifyNSEC(f *testing.F) {
	f.Add("example.com.", dns.TypeA, "example.com.", "z.example.com.")
	f.Add("test.com.", dns.TypeAAAA, "a.com.", "zzzz.com.")

	f.Fuzz(func(t *testing.T, qname string, qtype uint16, nsecOwner, nsecNext string) {
		q := dns.Question{
			Name:   qname,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}

		nsecSet := []dns.RR{
			&dns.NSEC{
				Hdr:        dns.RR_Header{Name: nsecOwner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: nsecNext,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA},
			},
		}

		_ = VerifyNSEC(q, nsecSet)
		_ = VerifyNSEC(q, nil)
	})
}

// FuzzTypesSet fuzzes the type set checking helper.
func FuzzTypesSet(f *testing.F) {
	f.Add(dns.TypeA, dns.TypeAAAA, dns.TypeNS)
	f.Add(uint16(0), uint16(0), uint16(0))
	f.Add(uint16(65535), uint16(1), uint16(2))

	f.Fuzz(func(t *testing.T, setType, checkType1, checkType2 uint16) {
		set := []uint16{setType, dns.TypeSOA, dns.TypeMX}
		_ = typesSet(set, checkType1, checkType2)
		_ = typesSet(set, checkType1)
		_ = typesSet(nil, checkType1)
		_ = typesSet(set)
	})
}

// FuzzKeyTag drives the key tag against the library's for arbitrary key
// material. The tag decides which key a DS or an RRSIG is matched against, so
// a disagreement does not fail loudly — it quietly stops the right key from
// being tried. A checksum read in chunks is exactly the kind of thing that
// agrees on the inputs someone thought to write down, so this looks for the
// ones nobody did.
func FuzzKeyTag(f *testing.F) {
	f.Add(uint16(257), uint8(3), dns.RSASHA256, "AwEAAcQ8")
	f.Add(uint16(256), uint8(3), dns.ECDSAP256SHA256, "")
	f.Add(uint16(0), uint8(0), dns.ED25519, "not base64!!")
	f.Add(uint16(0xFFFF), uint8(255), dns.RSASHA512, "AAAA=AAA")
	f.Add(uint16(385), uint8(3), dns.RSAMD5, "AQAB")
	f.Add(uint16(257), uint8(3), dns.RSASHA256, "AAAA\r\nAAAA")

	f.Fuzz(func(t *testing.T, flags uint16, protocol, algorithm uint8, publicKey string) {
		key := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: dns.TypeDNSKEY,
				Class: dns.ClassINET, Ttl: 3600,
			},
			Flags: flags, Protocol: protocol, Algorithm: algorithm,
			PublicKey: publicKey,
		}
		if algorithm == dns.RSAMD5 {
			// Not compared: the library panics on part of this input
			// space, which is why RSAMD5 has no tag here. See KeyTag.
			if got := KeyTag(key); got != 0 {
				t.Fatalf("RSAMD5 key=%q: tag %d, want 0", publicKey, got)
			}
			return
		}
		if got, want := KeyTag(key), key.KeyTag(); got != want {
			t.Fatalf("flags=%d protocol=%d algorithm=%d key=%q: tag %d, "+
				"library says %d", flags, protocol, algorithm, publicKey,
				got, want)
		}
	})
}

// FuzzFindClosestEncloser fuzzes the NSEC3 closest encloser algorithm.
func FuzzFindClosestEncloser(f *testing.F) {
	f.Add("sub.example.com.")
	f.Add("a.b.c.d.example.com.")
	f.Add("example.com.")
	f.Add(".")
	f.Add("")

	f.Fuzz(func(t *testing.T, name string) {
		nsec := []dns.RR{
			&dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
				Hash:       1,
				Flags:      0,
				Iterations: 1,
				Salt:       "aabb",
				NextDomain: "ABCD1234",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
			},
		}

		_, _ = findClosestEncloser(name, nsec)
		_, _ = findClosestEncloser(name, nil)
	})
}
