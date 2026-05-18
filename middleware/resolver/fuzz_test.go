package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// FuzzExtractRRSet fuzzes the RR extraction function.
func FuzzExtractRRSet(f *testing.F) {
	f.Add("example.com.", dns.TypeA, dns.TypeAAAA)
	f.Add("", dns.TypeNS, dns.TypeSOA)
	f.Add("TEST.EXAMPLE.COM.", dns.TypeMX, dns.TypeTXT)

	f.Fuzz(func(t *testing.T, name string, type1, type2 uint16) {
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

		_ = dnsutil.ExtractRRSet(rrs, name, type1, type2)
		_ = dnsutil.ExtractRRSet(rrs, name, type1)
		_ = dnsutil.ExtractRRSet(rrs, name)
		_ = dnsutil.ExtractRRSet(nil, name, type1)
	})
}

// FuzzFormatQuestion fuzzes the question formatting function.
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
		_ = formatQuestion(q)
	})
}

// FuzzGetDnameTarget fuzzes DNAME target extraction.
func FuzzGetDnameTarget(f *testing.F) {
	f.Add("sub.example.com.", "example.com.", "target.com.")
	f.Add("a.b.c.example.com.", "example.com.", "new.domain.")
	f.Add("example.com.", "example.com.", "target.")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, qname, dnameName, dnameTarget string) {
		msg := &dns.Msg{
			Question: []dns.Question{{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		}

		if dnameName != "" && dnameTarget != "" {
			msg.Answer = []dns.RR{
				&dns.DNAME{
					Hdr:    dns.RR_Header{Name: dnameName, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
					Target: dnameTarget,
				},
			}
		}

		_ = dnsutil.DnameTarget(msg)
	})
}

// FuzzSearchAddrs fuzzes address extraction from DNS messages.
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

		_, _ = searchAddrs(msg)
	})
}

// FuzzIsDO fuzzes EDNS0 DO bit checking.
func FuzzIsDO(f *testing.F) {
	f.Add(uint16(4096), true)
	f.Add(uint16(512), false)
	f.Add(uint16(0), true)
	f.Add(uint16(65535), false)

	f.Fuzz(func(t *testing.T, bufSize uint16, do bool) {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeA)

		msg.SetEdns0(bufSize, do)
		_ = isDO(msg)

		msg2 := &dns.Msg{}
		msg2.SetQuestion("example.com.", dns.TypeA)
		_ = isDO(msg2)
	})
}

// FuzzSortnss fuzzes nameserver sorting.
func FuzzSortnss(f *testing.F) {
	f.Add("example.com.")
	f.Add("sub.example.com.")
	f.Add("")
	f.Add(".")

	f.Fuzz(func(t *testing.T, qname string) {
		hosts := hostSet{
			"ns1.example.com.": struct{}{},
			"ns2.example.com.": struct{}{},
			"ns1.test.com.":    struct{}{},
		}

		_ = sortHosts(hosts, qname)
		_ = sortHosts(nil, qname)
		_ = sortHosts(hostSet{}, qname)
	})
}
