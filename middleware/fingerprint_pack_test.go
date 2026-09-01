package middleware

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestNegativeProofFingerprintUnchanged pins that hashing the proof in the
// packer's pooled buffer produces the same seal the library-packed form did,
// the fingerprint is persisted identity, and a changed formula would orphan
// every seal taken before it.
func TestNegativeProofFingerprintUnchanged(t *testing.T) {
	soa, err := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. " +
		"hostmaster.example.com. 2026081401 7200 3600 1209600 3600")
	if err != nil {
		t.Fatal(err)
	}
	nsec, err := dns.NewRR("a.example.com. 3600 IN NSEC c.example.com. A RRSIG")
	if err != nil {
		t.Fatal(err)
	}

	proofs := []*dns.Msg{}
	small := new(dns.Msg)
	small.SetQuestion("b.example.com.", dns.TypeA)
	small.Rcode = dns.RcodeNameError
	small.Ns = []dns.RR{soa, nsec}
	proofs = append(proofs, small)

	// Past the pooled buffer: the fallback half of the formula.
	big := new(dns.Msg)
	big.SetQuestion("b.example.com.", dns.TypeA)
	big.Rcode = dns.RcodeNameError
	for i := range 120 {
		rr, err := dns.NewRR(fmt.Sprintf(
			`n%03d.example.com. 300 IN TXT "%s"`, i, strings.Repeat("x", 60)))
		if err != nil {
			t.Fatal(err)
		}
		big.Ns = append(big.Ns, rr)
	}
	proofs = append(proofs, big)

	for i, proof := range proofs {
		got, ok := validatedNegativeProofFingerprint(proof)
		if !ok {
			t.Fatalf("proof %d: no fingerprint", i)
		}

		// The original formula, verbatim.
		sealed := new(dns.Msg)
		sealed.Rcode = proof.Rcode
		sealed.Ns = proof.Ns
		packed, err := sealed.Pack()
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if want := sha256.Sum256(packed); got != want {
			t.Fatalf("proof %d: the fingerprint formula changed", i)
		}
	}

	if _, ok := validatedNegativeProofFingerprint(nil); ok {
		t.Fatal("a nil proof produced a fingerprint")
	}
}

// BenchmarkNegativeProofFingerprint compiles unchanged against the
// pre-packer tree, for the before/after comparison.
func BenchmarkNegativeProofFingerprint(b *testing.B) {
	soa, err := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. " +
		"hostmaster.example.com. 2026081401 7200 3600 1209600 3600")
	if err != nil {
		b.Fatal(err)
	}
	nsec, err := dns.NewRR("a.example.com. 3600 IN NSEC c.example.com. A RRSIG")
	if err != nil {
		b.Fatal(err)
	}
	proof := new(dns.Msg)
	proof.SetQuestion("b.example.com.", dns.TypeA)
	proof.Rcode = dns.RcodeNameError
	proof.Ns = []dns.RR{soa, nsec}

	b.ReportAllocs()
	for b.Loop() {
		if _, ok := validatedNegativeProofFingerprint(proof); !ok {
			b.Fatal("no fingerprint")
		}
	}
}
