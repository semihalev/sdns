package util

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// FuzzIPFromReverseName fuzzes PTR record name parsing
func FuzzIPFromReverseName(f *testing.F) {
	// IPv4 PTR names
	f.Add("1.0.0.127.in-addr.arpa.")
	f.Add("54.119.58.176.in-addr.arpa.")
	f.Add("1.168.192.in-addr.arpa.")
	f.Add("0.0.0.0.in-addr.arpa.")
	f.Add("255.255.255.255.in-addr.arpa.")

	// IPv6 PTR names
	f.Add("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	f.Add("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")

	// Invalid inputs
	f.Add("")
	f.Add("invalid")
	f.Add("not.a.ptr.name")
	f.Add("1.2.3.in-addr.arpa.")     // Too few octets
	f.Add("1.2.3.4.5.in-addr.arpa.") // Too many octets
	f.Add("abc.in-addr.arpa.")
	f.Add(".in-addr.arpa.")
	f.Add("in-addr.arpa.")
	f.Add(".ip6.arpa.")

	f.Fuzz(func(t *testing.T, name string) {
		// This should not panic regardless of input
		_ = IPFromReverseName(name)
	})
}

// FuzzCheckReverseName fuzzes reverse DNS zone checking
func FuzzCheckReverseName(f *testing.F) {
	f.Add("1.0.0.127.in-addr.arpa.")
	f.Add("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	f.Add("example.com.")
	f.Add("")
	f.Add(".")
	f.Add("in-addr.arpa.")
	f.Add("ip6.arpa.")

	f.Fuzz(func(t *testing.T, name string) {
		// This should not panic regardless of input
		_ = CheckReverseName(name)
	})
}

// FuzzClassifyResponse fuzzes DNS response classification
func FuzzClassifyResponse(f *testing.F) {
	// Create seed corpus with packed DNS messages
	// Success response
	successMsg := new(dns.Msg)
	successMsg.SetQuestion("example.com.", dns.TypeA)
	successMsg.Answer = append(successMsg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})
	if packed, err := successMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// NXDOMAIN response
	nxMsg := new(dns.Msg)
	nxMsg.SetQuestion("nonexistent.example.com.", dns.TypeA)
	nxMsg.Rcode = dns.RcodeNameError
	if packed, err := nxMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// NODATA response (with SOA)
	nodataMsg := new(dns.Msg)
	nodataMsg.SetQuestion("example.com.", dns.TypeAAAA)
	nodataMsg.Ns = append(nodataMsg.Ns, &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:     "ns1.example.com.",
		Mbox:   "admin.example.com.",
		Serial: 2024010101,
	})
	if packed, err := nodataMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// Referral response
	referralMsg := new(dns.Msg)
	referralMsg.SetQuestion("sub.example.com.", dns.TypeA)
	referralMsg.Ns = append(referralMsg.Ns, &dns.NS{
		Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns1.sub.example.com.",
	})
	if packed, err := referralMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// Empty/minimal
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := new(dns.Msg)
		if err := msg.Unpack(data); err != nil {
			return
		}

		// This should not panic regardless of input
		_, _ = ClassifyResponse(msg, time.Now())
	})
}

// FuzzParseIPv4PTR fuzzes IPv4 PTR name parsing
func FuzzParseIPv4PTR(f *testing.F) {
	f.Add("1.0.0.127.in-addr.arpa.")
	f.Add("0.0.0.0.in-addr.arpa.")
	f.Add("255.255.255.255.in-addr.arpa.")
	f.Add("1.2.3.4.in-addr.arpa.")
	f.Add("")
	f.Add("invalid.in-addr.arpa.")
	f.Add("1.2.3.in-addr.arpa.")
	f.Add("1.2.3.4.5.in-addr.arpa.")

	f.Fuzz(func(t *testing.T, name string) {
		// This should not panic regardless of input
		_ = parseIPv4PTR(name)
	})
}

// FuzzParseIPv6PTR fuzzes IPv6 PTR name parsing
func FuzzParseIPv6PTR(f *testing.F) {
	f.Add("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	f.Add("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")
	f.Add("")
	f.Add("invalid.ip6.arpa.")
	f.Add("g.0.0.0.ip6.arpa.") // Invalid hex

	f.Fuzz(func(t *testing.T, name string) {
		// This should not panic regardless of input
		_ = parseIPv6PTR(name)
	})
}
