package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestHasNSEC3OptOutUsesDNSASCIICaseFolding(t *testing.T) {
	optOut := func(owner string, flags uint8) dns.RR {
		return &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
			},
			Flags: flags,
		}
	}

	if !HasNSEC3OptOut([]dns.RR{optOut("HASH.k.example.", 1)}, "K.Example.") {
		t.Fatal("in-zone NSEC3 Opt-Out record was not detected")
	}
	if HasNSEC3OptOut([]dns.RR{optOut("HASH.k.example.", 0)}, "k.example.") {
		t.Fatal("ordinary NSEC3 record was classified as Opt-Out")
	}
	if HasNSEC3OptOut([]dns.RR{optOut("HASH.\u212A.example.", 1)}, "k.example.") {
		t.Fatal("Unicode folding aliased Kelvin-sign and ASCII-k signer zones")
	}
}

func TestFilterRRsToZoneUsesDNSASCIICaseFolding(t *testing.T) {
	nsec := func(owner, next string) dns.RR {
		return &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
			},
			NextDomain: next,
		}
	}

	inZone := nsec("A.K.Example.", "Z.k.example.")
	kelvinOwner := nsec("a.\u212A.example.", "z.k.example.")
	kelvinNext := nsec("a.k.example.", "z.\u212A.example.")
	got := FilterRRsToZone(
		[]dns.RR{inZone, kelvinOwner, kelvinNext},
		"k.example.",
	)
	if len(got) != 1 || got[0] != inZone {
		t.Fatalf("filtered records = %v, want only ASCII-case-equivalent in-zone NSEC", got)
	}
}
