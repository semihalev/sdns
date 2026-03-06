package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// FuzzNsecCovers fuzzes the NSEC coverage check function
// This is security-critical for DNSSEC validation
func FuzzNsecCovers(f *testing.F) {
	// Add seed corpus with various domain name orderings
	f.Add("a.example.com.", "z.example.com.", "m.example.com.")
	f.Add("example.com.", "example.com.", "test.example.com.")
	f.Add("a.example.com.", "c.example.com.", "b.example.com.")
	f.Add("z.example.com.", "a.example.com.", "m.example.com.") // wrap case
	f.Add(".", ".", "example.com.")
	f.Add("EXAMPLE.COM.", "test.example.com.", "foo.example.com.")
	f.Add("", "", "")
	f.Add("a.", "b.", "a.")

	f.Fuzz(func(t *testing.T, owner, next, name string) {
		// This should not panic regardless of input
		_ = nsecCovers(owner, next, name)
	})
}

// FuzzCheckExponent fuzzes the RSA public key exponent validation
// This is security-critical for DNSSEC key validation
func FuzzCheckExponent(f *testing.F) {
	// Add seed corpus with various base64-encoded keys
	f.Add("AQAB") // Common RSA exponent 65537
	f.Add("Aw==") // Exponent 3
	f.Add("")
	f.Add("!!!invalid-base64!!!")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
	// Realistic DNSKEY public key (truncated)
	f.Add("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3")

	f.Fuzz(func(t *testing.T, key string) {
		// This should not panic regardless of input
		_ = checkExponent(key)
	})
}

// FuzzFromBase64 fuzzes the base64 decoder
func FuzzFromBase64(f *testing.F) {
	f.Add([]byte("AQAB"))
	f.Add([]byte(""))
	f.Add([]byte("!!!"))
	f.Add([]byte("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="))

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should not panic regardless of input
		_, _ = fromBase64(data)
	})
}

// FuzzExtractRRSet fuzzes the RR extraction function
func FuzzExtractRRSet(f *testing.F) {
	f.Add("example.com.", dns.TypeA, dns.TypeAAAA)
	f.Add("", dns.TypeNS, dns.TypeSOA)
	f.Add("TEST.EXAMPLE.COM.", dns.TypeMX, dns.TypeTXT)

	f.Fuzz(func(t *testing.T, name string, type1, type2 uint16) {
		// Create some test RRs
		rrs := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.1"),
			},
			&dns.AAAA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::1"),
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.com.",
			},
		}

		// This should not panic regardless of input
		_ = extractRRSet(rrs, name, type1, type2)
		_ = extractRRSet(rrs, name, type1)
		_ = extractRRSet(rrs, name)
		_ = extractRRSet(nil, name, type1)
	})
}

// FuzzFormatQuestion fuzzes the question formatting function
func FuzzFormatQuestion(f *testing.F) {
	f.Add("example.com.", dns.TypeA, uint16(dns.ClassINET))
	f.Add("", uint16(0), uint16(0))
	f.Add("EXAMPLE.COM.", dns.TypeAAAA, uint16(dns.ClassINET))
	f.Add("test.example.com.", uint16(65535), uint16(65535))

	f.Fuzz(func(t *testing.T, name string, qtype, qclass uint16) {
		q := dns.Question{
			Name:   name,
			Qtype:  qtype,
			Qclass: qclass,
		}
		// This should not panic regardless of input
		_ = formatQuestion(q)
	})
}

// FuzzTypesSet fuzzes the type set checking function
func FuzzTypesSet(f *testing.F) {
	f.Add(dns.TypeA, dns.TypeAAAA, dns.TypeNS)
	f.Add(uint16(0), uint16(0), uint16(0))
	f.Add(uint16(65535), uint16(1), uint16(2))

	f.Fuzz(func(t *testing.T, setType, checkType1, checkType2 uint16) {
		set := []uint16{setType, dns.TypeSOA, dns.TypeMX}
		// This should not panic regardless of input
		_ = typesSet(set, checkType1, checkType2)
		_ = typesSet(set, checkType1)
		_ = typesSet(nil, checkType1)
		_ = typesSet(set)
	})
}

// FuzzGetDnameTarget fuzzes DNAME target extraction
func FuzzGetDnameTarget(f *testing.F) {
	f.Add("sub.example.com.", "example.com.", "target.com.")
	f.Add("a.b.c.example.com.", "example.com.", "new.domain.")
	f.Add("example.com.", "example.com.", "target.")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, qname, dnameName, dnameTarget string) {
		msg := &dns.Msg{
			Question: []dns.Question{{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		}

		// Only add DNAME if we have valid-ish names
		if dnameName != "" && dnameTarget != "" {
			msg.Answer = []dns.RR{
				&dns.DNAME{
					Hdr:    dns.RR_Header{Name: dnameName, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dnameTarget,
				},
			}
		}

		// This should not panic regardless of input
		_ = getDnameTarget(msg)
	})
}

// FuzzVerifyNSEC fuzzes NSEC type bitmap verification
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

		// This should not panic regardless of input
		_ = verifyNSEC(q, nsecSet)
		_ = verifyNSEC(q, nil)
	})
}

// FuzzSearchAddrs fuzzes address extraction from DNS messages
func FuzzSearchAddrs(f *testing.F) {
	f.Add("192.0.2.1", "2001:db8::1")
	f.Add("127.0.0.1", "::1")
	f.Add("0.0.0.0", "::")
	f.Add("255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

	f.Fuzz(func(t *testing.T, ipv4Str, ipv6Str string) {
		ipv4 := net.ParseIP(ipv4Str)
		ipv6 := net.ParseIP(ipv6Str)

		msg := &dns.Msg{
			Answer: []dns.RR{},
		}

		if ipv4 != nil {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ipv4,
			})
		}

		if ipv6 != nil {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: ipv6,
			})
		}

		// This should not panic regardless of input
		_, _ = searchAddrs(msg)
	})
}

// FuzzIsDO fuzzes EDNS0 DO bit checking
func FuzzIsDO(f *testing.F) {
	f.Add(uint16(4096), true)
	f.Add(uint16(512), false)
	f.Add(uint16(0), true)
	f.Add(uint16(65535), false)

	f.Fuzz(func(t *testing.T, bufSize uint16, do bool) {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeA)

		// Test with EDNS0
		msg.SetEdns0(bufSize, do)
		_ = isDO(msg)

		// Test without EDNS0
		msg2 := &dns.Msg{}
		msg2.SetQuestion("example.com.", dns.TypeA)
		_ = isDO(msg2)
	})
}

// FuzzFindClosestEncloser fuzzes the NSEC3 closest encloser algorithm
func FuzzFindClosestEncloser(f *testing.F) {
	f.Add("sub.example.com.")
	f.Add("a.b.c.d.example.com.")
	f.Add("example.com.")
	f.Add(".")
	f.Add("")

	f.Fuzz(func(t *testing.T, name string) {
		// Create minimal NSEC3 records for testing
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

		// This should not panic regardless of input
		_, _ = findClosestEncloser(name, nsec)
		_, _ = findClosestEncloser(name, nil)
	})
}

// FuzzSortnss fuzzes nameserver sorting
func FuzzSortnss(f *testing.F) {
	f.Add("example.com.")
	f.Add("sub.example.com.")
	f.Add("")
	f.Add(".")

	f.Fuzz(func(t *testing.T, qname string) {
		nss := nameservers{
			"ns1.example.com.": struct{}{},
			"ns2.example.com.": struct{}{},
			"ns1.test.com.":    struct{}{},
		}

		// This should not panic regardless of input
		_ = sortnss(nss, qname)
		_ = sortnss(nil, qname)
		_ = sortnss(nameservers{}, qname)
	})
}
