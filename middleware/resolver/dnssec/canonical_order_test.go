package dnssec

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestCanonicalRRsetOrdersByRdataOnly pins the ordering RFC 4034 §6.3
// defines: within an RRset the records are sorted by their RDATA, and by
// nothing that precedes it.
//
// Sorting the whole packed record instead puts RDLENGTH ahead of the data,
// so records of unequal length order by length first. Two TXT strings are
// enough to tell the two rules apart, and a signature made over one ordering
// does not verify under the other.
func TestCanonicalRRsetOrdersByRdataOnly(t *testing.T) {
	// A TXT record's RDATA begins with a length octet, so a single string
	// orders the same way under both rules. Two strings separate them: this
	// pair has the longer RDATA starting with the smaller octets, so RDATA
	// order and whole-record order are opposites.
	rrset := []dns.RR{
		mustSignatureRR(t, `txt.example.com. 300 IN TXT "a" "zzzz"`),
		mustSignatureRR(t, `txt.example.com. 300 IN TXT "b"`),
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
	}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatal("generated key does not sign")
	}

	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: "txt.example.com.", Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: 300,
		},
		TypeCovered: dns.TypeTXT, Algorithm: key.Algorithm, Labels: 3,
		OrigTtl:    300,
		Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test epoch fits
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test epoch fits
		KeyTag:     key.KeyTag(), SignerName: key.Hdr.Name,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := sig.Verify(key, rrset); err != nil {
		t.Fatalf("fixture is wrong: the library does not accept what it signed: %v", err)
	}
	if err := verifySignature(key, sig, rrset); err != nil {
		t.Fatalf("rejected a signature the library accepts, over records whose "+
			"RDATA and length order differently: %v", err)
	}
}

// TestCanonicalRRsetMatchesLibraryOrdering compares the signed data this
// package builds with the library's, over sets chosen so that length order
// and content order disagree.
func TestCanonicalRRsetMatchesLibraryOrdering(t *testing.T) {
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: "txt.example.com.", Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: 300,
		},
		TypeCovered: dns.TypeTXT, Algorithm: dns.ECDSAP256SHA256, Labels: 3,
		OrigTtl: 300, Expiration: 2000000000, Inception: 1000000000,
		KeyTag: 1234, SignerName: "example.com.",
	}

	for _, values := range [][]string{
		{`"a" "zzzz"`, `"b"`},
		{`"b"`, `"a" "zzzz"`},
		{`"zz"`, `"aaaa"`},
		{`"b"`, `"aa"`, `"ccc"`},
		{`"` + strings.Repeat("x", 200) + `"`, `"y"`},
		{`"same"`, `"same"`},
	} {
		var rrset []dns.RR
		for _, value := range values {
			rrset = append(rrset, mustSignatureRR(t,
				`txt.example.com. 300 IN TXT `+value))
		}

		ours, err := canonicalRRset(rrset, sig)
		if err != nil {
			t.Fatalf("%v: canonicalRRset: %v", values, err)
		}
		theirs := libraryCanonicalRRset(t, rrset, sig)
		if string(ours) != string(theirs) {
			t.Fatalf("%v: canonical form diverged from the library's\n"+
				" ours:  %x\n them:  %x", values, ours, theirs)
		}
	}
}

// libraryCanonicalRRset reproduces what dns.RRSIG.Verify hashes, by signing
// with a key and reading back what the library considered the signed data.
// The library does not export it, so this rebuilds the ordering rule it
// documents: sort on the RDATA, which begins ten octets past the owner name.
func libraryCanonicalRRset(tb testing.TB, rrset []dns.RR, sig *dns.RRSIG) []byte {
	tb.Helper()
	wires := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		clone := dns.Copy(rr)
		clone.Header().Ttl = sig.OrigTtl
		clone.Header().Name = dns.CanonicalName(clone.Header().Name)
		wire := make([]byte, dns.Len(clone)+1)
		n, err := dns.PackRR(clone, wire, 0, nil, false)
		if err != nil {
			tb.Fatalf("PackRR: %v", err)
		}
		wires = append(wires, wire[:n])
	}
	sortByRdata(tb, wires)

	var buf []byte
	for i, wire := range wires {
		if i > 0 && string(wire) == string(wires[i-1]) {
			continue
		}
		buf = append(buf, wire...)
	}
	return buf
}

// TestCanonicalRRsetLabelsZeroStaysRejected pins the acceptance boundary
// review caught this construction drifting across. For Labels=0 the RFC's
// wildcard arithmetic yields "*.", a name that would verify a root-wildcard
// signature — but the library's construction yields "*.." and the packer
// rejects it, so such signatures have always failed verification, there and
// here. Accepting them may well be the RFC's intent; it is also a wider
// acceptance than the library's, and this package promises never to be
// wider. Root-wildcard support, if ever wanted, is a deliberate change with
// its own cryptographic and denial-proof tests — not a side effect of an
// allocation rewrite.
func TestCanonicalRRsetLabelsZeroStaysRejected(t *testing.T) {
	rrset := []dns.RR{mustSignatureRR(t, "foo. 300 IN A 192.0.2.1")}

	for _, labels := range []uint8{0, 1} {
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name: "foo.", Rrtype: dns.TypeRRSIG,
				Class: dns.ClassINET, Ttl: 300,
			},
			TypeCovered: dns.TypeA, Algorithm: dns.RSASHA256, Labels: labels,
			OrigTtl: 300, Expiration: 2000000000, Inception: 1000000000,
			KeyTag: 1234, SignerName: ".",
		}
		_, err := canonicalRRset(rrset, sig)
		if labels == 0 && err == nil {
			t.Fatal("a Labels=0 reconstruction was accepted; the library " +
				"rejects the *.. spelling it produces")
		}
		if labels == 1 && err != nil {
			t.Fatalf("an exact-owner signature was rejected: %v", err)
		}
	}
}

func sortByRdata(tb testing.TB, wires [][]byte) {
	tb.Helper()
	rdata := func(wire []byte) []byte {
		_, off, err := dns.UnpackDomainName(wire, 0)
		if err != nil {
			tb.Fatalf("UnpackDomainName: %v", err)
		}
		return wire[off+10:]
	}
	for i := 1; i < len(wires); i++ {
		for j := i; j > 0 && string(rdata(wires[j])) < string(rdata(wires[j-1])); j-- {
			wires[j], wires[j-1] = wires[j-1], wires[j]
		}
	}
}
