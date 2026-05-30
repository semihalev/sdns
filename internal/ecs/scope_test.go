package ecs

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func msgWithECS(opt *dns.EDNS0_SUBNET) *dns.Msg {
	m := new(dns.Msg)
	if opt == nil {
		return m
	}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = []dns.EDNS0{opt}
	m.Extra = []dns.RR{o}
	return m
}

func TestReadResponseScope_NilOrNoOpt(t *testing.T) {
	if _, ok := ReadResponseScope(nil); ok {
		t.Errorf("nil response should not yield a scope")
	}
	if _, ok := ReadResponseScope(new(dns.Msg)); ok {
		t.Errorf("response with no OPT should not yield a scope")
	}
}

func TestReadResponseScope_NoSubnetOption(t *testing.T) {
	m := msgWithECS(nil)
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	// OPT without an EDNS0_SUBNET option.
	o.Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: ""}}
	m.Extra = []dns.RR{o}

	if _, ok := ReadResponseScope(m); ok {
		t.Errorf("OPT without ECS option should not yield a scope")
	}
}

func TestReadResponseScope_GlobalAnswerSkipped(t *testing.T) {
	// RFC 7871 §6: SCOPE = 0 means "valid for entire address space",
	// i.e. cache shared-key, not scoped. ReadResponseScope must NOT
	// return a prefix for that case.
	m := msgWithECS(&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1,
		SourceNetmask: 24, SourceScope: 0,
		Address: net.ParseIP("203.0.113.0").To4(),
	})
	if _, ok := ReadResponseScope(m); ok {
		t.Errorf("SCOPE=0 should be reported as 'no scope'")
	}
}

func TestReadResponseScope_ValidV4Scope(t *testing.T) {
	m := msgWithECS(&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1,
		SourceNetmask: 24, SourceScope: 24,
		Address: net.ParseIP("203.0.113.0").To4(),
	})
	got, ok := ReadResponseScope(m)
	if !ok {
		t.Fatal("expected valid scope")
	}
	if want := "203.0.113.0/24"; got.String() != want {
		t.Errorf("scope = %s, want %s", got, want)
	}
}

func TestReadResponseScope_ValidV6Scope(t *testing.T) {
	m := msgWithECS(&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 2,
		SourceNetmask: 56, SourceScope: 56,
		Address: net.ParseIP("2001:db8::"),
	})
	got, ok := ReadResponseScope(m)
	if !ok {
		t.Fatal("expected valid scope")
	}
	if want := "2001:db8::/56"; got.String() != want {
		t.Errorf("scope = %s, want %s", got, want)
	}
}

func TestReadResponseScope_FamilyMismatchRejected(t *testing.T) {
	// Family=1 (IPv4) but a 16-byte non-mapped v6 address. Malformed.
	m := msgWithECS(&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1,
		SourceNetmask: 24, SourceScope: 24,
		Address: net.ParseIP("2001:db8::1"),
	})
	if _, ok := ReadResponseScope(m); ok {
		t.Errorf("family/address mismatch should be rejected")
	}
}
