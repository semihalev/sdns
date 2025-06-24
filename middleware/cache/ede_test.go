package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestEDEPreservationInCache(t *testing.T) {
	// Create a message with EDE
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetRcode(msg, dns.RcodeServerFailure)

	// Add EDNS0 with EDE
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
		},
	}
	ede := &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeDNSBogus,
		ExtraText: "DNSSEC validation failed",
	}
	opt.Option = append(opt.Option, ede)
	msg.Extra = append(msg.Extra, opt)

	// Create cache entry
	entry := NewCacheEntry(msg, 30*time.Second, 0)

	// Verify EDE was preserved
	assert.NotNil(t, entry.ede)
	assert.Equal(t, dns.ExtendedErrorCodeDNSBogus, entry.ede.InfoCode)
	assert.Equal(t, "DNSSEC validation failed", entry.ede.ExtraText)

	// Create a request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	// Get response from cache
	resp := entry.ToMsg(req)
	assert.NotNil(t, resp)

	// Verify EDE is present in response
	opt2 := resp.IsEdns0()
	assert.NotNil(t, opt2)

	var foundEDE *dns.EDNS0_EDE
	for _, option := range opt2.Option {
		if e, ok := option.(*dns.EDNS0_EDE); ok {
			foundEDE = e
			break
		}
	}

	assert.NotNil(t, foundEDE)
	assert.Equal(t, dns.ExtendedErrorCodeDNSBogus, foundEDE.InfoCode)
	assert.Equal(t, "DNSSEC validation failed", foundEDE.ExtraText)
}

func TestEDENotAddedForSuccessResponses(t *testing.T) {
	// Create a successful response
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetRcode(msg, dns.RcodeSuccess)

	// Add an answer
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.1"),
	}
	msg.Answer = append(msg.Answer, rr)

	// Create cache entry
	entry := NewCacheEntry(msg, 30*time.Second, 0)

	// Verify no EDE was preserved (success responses don't have EDE)
	assert.Nil(t, entry.ede)

	// Create a request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	// Get response from cache
	resp := entry.ToMsg(req)
	assert.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// Verify no EDE is added
	opt := resp.IsEdns0()
	if opt != nil {
		for _, option := range opt.Option {
			_, isEDE := option.(*dns.EDNS0_EDE)
			assert.False(t, isEDE, "EDE should not be present in success responses")
		}
	}
}
