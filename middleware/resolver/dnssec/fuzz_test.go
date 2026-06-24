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
