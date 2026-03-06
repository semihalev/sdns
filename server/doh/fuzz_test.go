package doh

import (
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
)

// FuzzDNSMessageUnpack fuzzes DNS wire format message unpacking
// This tests the security-critical DNS message parsing code path
func FuzzDNSMessageUnpack(f *testing.F) {
	// Add seed corpus with valid DNS messages
	validMsg := new(dns.Msg)
	validMsg.SetQuestion("example.com.", dns.TypeA)
	if packed, err := validMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// Add EDNS0 message
	ednsMsg := new(dns.Msg)
	ednsMsg.SetQuestion("test.example.com.", dns.TypeAAAA)
	ednsMsg.SetEdns0(4096, true)
	if packed, err := ednsMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// Add message with answer
	answerMsg := new(dns.Msg)
	answerMsg.SetQuestion("example.com.", dns.TypeA)
	answerMsg.Answer = append(answerMsg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{93, 184, 216, 34},
	})
	if packed, err := answerMsg.Pack(); err == nil {
		f.Add(packed)
	}

	// Add minimal header
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Simulate the same validation as HandleWireFormat
		if len(data) < minMsgHeaderSize {
			return
		}

		msg := new(dns.Msg)
		// This should not panic regardless of input
		_ = msg.Unpack(data)
	})
}

// FuzzBase64DNSMessage fuzzes base64-encoded DNS messages (DoH GET format)
func FuzzBase64DNSMessage(f *testing.F) {
	// Add seed corpus
	validMsg := new(dns.Msg)
	validMsg.SetQuestion("example.com.", dns.TypeA)
	if packed, err := validMsg.Pack(); err == nil {
		f.Add(base64.RawURLEncoding.EncodeToString(packed))
	}

	f.Add("AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE")
	f.Add("")
	f.Add("!!!invalid-base64!!!")

	f.Fuzz(func(t *testing.T, encoded string) {
		buf, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(buf) < minMsgHeaderSize {
			return
		}

		msg := new(dns.Msg)
		// This should not panic regardless of input
		_ = msg.Unpack(buf)
	})
}

// FuzzParseQTYPE fuzzes the QTYPE parser
func FuzzParseQTYPE(f *testing.F) {
	// Add seed corpus
	f.Add("A")
	f.Add("AAAA")
	f.Add("MX")
	f.Add("TXT")
	f.Add("CNAME")
	f.Add("NS")
	f.Add("SOA")
	f.Add("PTR")
	f.Add("SRV")
	f.Add("1")
	f.Add("28")
	f.Add("255")
	f.Add("")
	f.Add("INVALID")
	f.Add("99999999999999999")

	f.Fuzz(func(t *testing.T, input string) {
		// This should not panic regardless of input
		_ = ParseQTYPE(input)
	})
}

// FuzzNewMsg fuzzes the Msg constructor with various dns.Msg inputs
func FuzzNewMsg(f *testing.F) {
	// Add seed corpus as packed messages
	validMsg := new(dns.Msg)
	validMsg.SetQuestion("example.com.", dns.TypeA)
	if packed, err := validMsg.Pack(); err == nil {
		f.Add(packed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < minMsgHeaderSize {
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(data); err != nil {
			return
		}

		// This should not panic regardless of input
		_ = NewMsg(msg)
	})
}
