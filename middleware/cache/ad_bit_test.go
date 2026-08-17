package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheADBitHandling(t *testing.T) {
	// Create a cache entry with AD=1
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.AuthenticatedData = true
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	entry := NewCacheEntry(msg, 5*time.Minute, 0)

	// Test 1: Request with CD=0 should preserve AD=1
	req1 := new(dns.Msg)
	req1.SetQuestion("example.com.", dns.TypeA)
	req1.CheckingDisabled = false

	resp1 := entry.ToMsg(req1)
	if resp1 == nil {
		t.Fatalf("resp1 is nil")
	}
	if !(resp1.AuthenticatedData) {
		t.Errorf("%s: resp1.AuthenticatedData is false", "AD bit should be preserved when CD=0")
	}

	// Test 2: Request with CD=1 should clear AD bit
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeA)
	req2.CheckingDisabled = true

	resp2 := entry.ToMsg(req2)
	if resp2 == nil {
		t.Fatalf("resp2 is nil")
	}
	if resp2.AuthenticatedData {
		t.Errorf("%s: resp2.AuthenticatedData is true", "AD bit should be cleared when CD=1")
	}

	// Verify original entry is not modified
	if !(msg.AuthenticatedData) {
		t.Errorf("%s: msg.AuthenticatedData is false", "Original message should not be modified")
	}
}

func TestCacheEntryWithoutAD(t *testing.T) {
	// Create a cache entry without AD bit
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.AuthenticatedData = false
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	entry := NewCacheEntry(msg, 5*time.Minute, 0)

	// Both CD=0 and CD=1 requests should have AD=0
	for _, cd := range []bool{false, true} {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		req.CheckingDisabled = cd

		resp := entry.ToMsg(req)
		if resp == nil {
			t.Fatalf("resp is nil")
		}
		if resp.AuthenticatedData {
			t.Errorf("%s: resp.AuthenticatedData is true", "AD bit should remain false when original had AD=0")
		}
	}
}
