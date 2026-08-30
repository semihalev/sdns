package resolver

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
)

// unlimitedSignatureWork lets every verification attempt through: these tests
// are about the type of the records, not about the work budget.
type unlimitedSignatureWork struct{}

func (unlimitedSignatureWork) CheckDNSKEYCandidate(uint32) error { return nil }
func (unlimitedSignatureWork) CheckRRsetSignature(uint32) error  { return nil }
func (unlimitedSignatureWork) BeginSignature() (func(), error)   { return func() {}, nil }

// dnskeyImpostor answers TypeDNSKEY from its header without being a
// *dns.DNSKEY. dnsutil.ExtractRRSet selects on the header, so an impostor
// reaches every loop a real key reaches — and an unchecked type assertion
// there is a panic in the trust-anchor refresh, which takes the resolver with
// it. The records these loops walk come from a network response and from
// configuration, so neither source is ours to trust.
func dnskeyImpostor() dns.RR {
	return &dns.RFC3597{
		Hdr: dns.RR_Header{
			Name: ".", Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 172800,
		},
		Rdata: "00",
	}
}

func testRootKSK() *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: ".", Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 172800,
		},
		Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256,
		PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 260)),
	}
}

// TestVerifyFetchedKeysSkipsRecordsThatAreNotDNSKEYs pins both loops that walk
// records claiming to be DNSKEYs: the configured trust anchors, and the keys
// fetched from the root. Each must skip a record it cannot use rather than
// assert on its type.
func TestVerifyFetchedKeysSkipsRecordsThatAreNotDNSKEYs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rootKeys []dns.RR
		rrs      []dns.RR
	}{
		{
			// Reaches the trust-anchor loop: with nothing usable in it,
			// the answer is "no KSK", not a crash.
			name:     "impostor among the trust anchors",
			rootKeys: []dns.RR{dnskeyImpostor()},
			rrs:      []dns.RR{dnskeyImpostor()},
		},
		{
			// A usable anchor gets past the first loop, so the fetched-key
			// loop is the one that meets the impostor.
			name:     "impostor among the fetched keys",
			rootKeys: []dns.RR{testRootKSK()},
			rrs:      []dns.RR{dnskeyImpostor()},
		},
		{
			// Both loops see one of each: the impostor must be stepped over
			// without taking the real key with it.
			name:     "impostor beside a real key",
			rootKeys: []dns.RR{dnskeyImpostor(), testRootKSK()},
			rrs:      []dns.RR{dnskeyImpostor(), testRootKSK()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, err := verifyFetchedKeysWithWork(
				tc.rootKeys, tc.rrs, unlimitedSignatureWork{})
			if ok {
				t.Fatal("nothing here is signed, so nothing may verify")
			}
			if err == nil {
				t.Fatal("want an error naming what was missing")
			}
			t.Logf("err = %v", err)
		})
	}
}
