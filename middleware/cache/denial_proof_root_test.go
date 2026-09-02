package cache

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// rootNSEC3 builds a plausible root-zone NSEC3: a single hash label directly
// under the root, which is the shortest owner an NSEC3 can have.
func rootNSEC3(owner, next string) *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: owner + ".", Rrtype: dns.TypeNSEC3,
			Class: dns.ClassINET, Ttl: 300,
		},
		Hash:       dns.SHA1,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: next,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA},
	}
}

// TestDenialProofAdmitsRootZoneNSEC3 pins the regression review found: a
// root-zone NSEC3 owner is one label, <hash>., and NextLabel legitimately
// answers end=true for it. Treating that answer as invalid rejected every
// root-zone proof, which the split-based code this replaced accepted; the
// failure was fail-closed, but a root that serves NSEC3 lost aggressive
// denial caching entirely.
func TestDenialProofAdmitsRootZoneNSEC3(t *testing.T) {
	ownerHash := strings.Repeat("v", 32) // base32hex, SHA-1 width
	nextHash := strings.Repeat("0", 32)

	params, gotOwner, gotNext, ok := denialProofNSEC3Identity(
		rootNSEC3(ownerHash, nextHash), ".")
	if !ok {
		t.Fatal("a root-zone NSEC3 was refused admission")
	}
	if gotOwner != strings.ToUpper(ownerHash) && gotOwner != ownerHash {
		t.Fatalf("owner hash = %q, want the owner label's hash", gotOwner)
	}
	if gotNext == "" || params.hash != dns.SHA1 {
		t.Fatalf("identity = (%+v, %q, %q)", params, gotOwner, gotNext)
	}

	// The deeper shape stays admitted, and the shape checks stay real: an
	// owner two labels below its zone is still refused.
	if _, _, _, ok := denialProofNSEC3Identity(
		rootNSEC3(ownerHash, nextHash), "example.com."); ok {
		t.Fatal("an owner outside its zone was admitted")
	}
	deep := rootNSEC3(ownerHash, nextHash)
	deep.Hdr.Name = ownerHash + ".example.com."
	if _, _, _, ok := denialProofNSEC3Identity(deep, "example.com."); !ok {
		t.Fatal("an ordinary in-zone NSEC3 was refused")
	}
	deeper := rootNSEC3(ownerHash, nextHash)
	deeper.Hdr.Name = ownerHash + ".sub.example.com."
	if _, _, _, ok := denialProofNSEC3Identity(deeper, "example.com."); ok {
		t.Fatal("an owner two labels below the zone was admitted")
	}
}
