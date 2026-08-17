package cache

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
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
	if entry.ede == nil {
		t.Fatalf("entry.ede is nil")
	}
	if !reflect.DeepEqual(dns.ExtendedErrorCodeDNSBogus, entry.ede.InfoCode) {
		t.Errorf("entry.ede.InfoCode = %v, want %v", entry.ede.InfoCode, dns.ExtendedErrorCodeDNSBogus)
	}
	if !reflect.DeepEqual("DNSSEC validation failed", entry.ede.ExtraText) {
		t.Errorf("entry.ede.ExtraText = %v, want %v", entry.ede.ExtraText, "DNSSEC validation failed")
	}

	// Create a request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	// Get response from cache
	resp := entry.ToMsg(req)
	if resp == nil {
		t.Fatalf("resp is nil")
	}

	// Verify EDE is present in response
	opt2 := resp.IsEdns0()
	if opt2 == nil {
		t.Fatalf("opt2 is nil")
	}

	var foundEDE *dns.EDNS0_EDE
	for _, option := range opt2.Option {
		if e, ok := option.(*dns.EDNS0_EDE); ok {
			foundEDE = e
			break
		}
	}

	if foundEDE == nil {
		t.Fatalf("foundEDE is nil")
	}
	if !reflect.DeepEqual(dns.ExtendedErrorCodeDNSBogus, foundEDE.InfoCode) {
		t.Errorf("foundEDE.InfoCode = %v, want %v", foundEDE.InfoCode, dns.ExtendedErrorCodeDNSBogus)
	}
	if !reflect.DeepEqual("DNSSEC validation failed", foundEDE.ExtraText) {
		t.Errorf("foundEDE.ExtraText = %v, want %v", foundEDE.ExtraText, "DNSSEC validation failed")
	}
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
	if entry.ede != nil {
		t.Errorf("entry.ede = %v, want nil", entry.ede)
	}

	// Create a request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	// Get response from cache
	resp := entry.ToMsg(req)
	if resp == nil {
		t.Fatalf("resp is nil")
	}
	if !reflect.DeepEqual(dns.RcodeSuccess, resp.Rcode) {
		t.Errorf("resp.Rcode = %v, want %v", resp.Rcode, dns.RcodeSuccess)
	}

	// Verify no EDE is added
	opt := resp.IsEdns0()
	if opt != nil {
		for _, option := range opt.Option {
			_, isEDE := option.(*dns.EDNS0_EDE)
			if isEDE {
				t.Errorf("%s: isEDE is true", "EDE should not be present in success responses")
			}
		}
	}
}
