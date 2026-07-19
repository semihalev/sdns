package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// wildcardSig builds an RRSIG covering an RRset at owner whose Labels field
// reflects a wildcard with the given label count (e.g. labels=2 for
// *.example.com.).
func wildcardSig(owner string, labels uint8) *dns.RRSIG {
	sig := &dns.RRSIG{Labels: labels, TypeCovered: dns.TypeA}
	sig.Hdr = dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}
	return sig
}

func nsec(owner, next string) *dns.NSEC {
	n := &dns.NSEC{NextDomain: dns.Fqdn(next)}
	n.Hdr = dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET}
	return n
}

func aRR(owner string) *dns.A {
	a := &dns.A{}
	a.Hdr = dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeA, Class: dns.ClassINET}
	return a
}

// TestVerifyWildcardAnswer_ReplayForged locks in the fix for the wildcard
// positive-answer replay: a signed wildcard RRSIG (Labels=2, i.e.
// *.example.com.) presented over the concrete name secure.example.com. with
// NO NSEC proof of non-existence must be rejected as bogus.
func TestVerifyWildcardAnswer_ReplayForged(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		aRR("secure.example.com."),
		wildcardSig("secure.example.com.", 2),
	}
	// No NSEC/NSEC3 in the authority section.
	if err := VerifyWildcardAnswer(msg); err != ErrWildcardNoDenial {
		t.Fatalf("expected ErrWildcardNoDenial for a wildcard answer with no denial proof, got %v", err)
	}
}

// TestVerifyWildcardAnswer_ReplayWithNonCoveringNSEC ensures a replayed but
// non-covering NSEC (as an attacker can only supply for a name that exists)
// does not satisfy the proof.
func TestVerifyWildcardAnswer_ReplayWithNonCoveringNSEC(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		aRR("secure.example.com."),
		wildcardSig("secure.example.com.", 2),
	}
	// An NSEC that exists in the zone but does not cover secure.example.com.
	msg.Ns = []dns.RR{nsec("aaa.example.com.", "bbb.example.com.")}
	if err := VerifyWildcardAnswer(msg); err != ErrWildcardNoDenial {
		t.Fatalf("non-covering NSEC must not satisfy the wildcard denial, got %v", err)
	}
}

// TestVerifyWildcardAnswer_LegitimateWithNSEC verifies a genuine wildcard
// answer accompanied by an NSEC covering the next closer name is accepted.
func TestVerifyWildcardAnswer_LegitimateWithNSEC(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		aRR("secure.example.com."),
		wildcardSig("secure.example.com.", 2),
	}
	// next closer for wildcard *.example.com. over secure.example.com. is
	// secure.example.com. itself; an NSEC covering it proves non-existence.
	msg.Ns = []dns.RR{nsec("labrador.example.com.", "terrier.example.com.")}
	if err := VerifyWildcardAnswer(msg); err != nil {
		t.Fatalf("legitimate wildcard answer with covering NSEC should verify, got %v", err)
	}
}

// TestVerifyWildcardAnswer_DeepNextCloser verifies the next closer name is
// computed one label below the closest encloser, not the full owner name.
func TestVerifyWildcardAnswer_DeepNextCloser(t *testing.T) {
	msg := new(dns.Msg)
	// Owner a.b.example.com. expanded from *.example.com. (Labels=2).
	// Closest encloser = example.com.; next closer = b.example.com.
	msg.Answer = []dns.RR{
		aRR("a.b.example.com."),
		wildcardSig("a.b.example.com.", 2),
	}
	// NSEC covering b.example.com. proves nothing closer than the wildcard.
	msg.Ns = []dns.RR{nsec("aa.example.com.", "c.example.com.")}
	if err := VerifyWildcardAnswer(msg); err != nil {
		t.Fatalf("deep next-closer proof should verify, got %v", err)
	}

	// Same answer but the NSEC covers the owner a.b.example.com. while
	// leaving the next closer b.example.com. on the owner boundary
	// (not covered), so the closest-encloser proof is incomplete and
	// must be rejected.
	msg.Ns = []dns.RR{nsec("b.example.com.", "c.example.com.")}
	if err := VerifyWildcardAnswer(msg); err != ErrWildcardNoDenial {
		t.Fatalf("owner-only coverage must not satisfy the next-closer proof, got %v", err)
	}
}

// TestVerifyWildcardAnswer_NonWildcard confirms an exact-owner answer (no
// wildcard expansion) needs no denial proof.
func TestVerifyWildcardAnswer_NonWildcard(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		aRR("secure.example.com."),
		wildcardSig("secure.example.com.", 3), // Labels == owner label count
	}
	if err := VerifyWildcardAnswer(msg); err != nil {
		t.Fatalf("non-wildcard answer should not require a denial proof, got %v", err)
	}
}

// TestVerifyWildcardAnswer_NSEC3 verifies the NSEC3 next-closer proof path.
func TestVerifyWildcardAnswer_NSEC3(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		aRR("secure.example.com."),
		wildcardSig("secure.example.com.", 2),
	}
	// Build an NSEC3 whose hashed-owner interval covers the next closer
	// name (secure.example.com.). Compute the real hash so Cover matches.
	const salt = "aabbccdd"
	h := dns.HashName("secure.example.com.", dns.SHA1, 0, salt)
	// Owner just below the target hash, next just above, so it covers it.
	n3 := &dns.NSEC3{
		Hash:       dns.SHA1,
		Iterations: 0,
		Salt:       salt,
		NextDomain: bumpHash(h, +1),
	}
	n3.Hdr = dns.RR_Header{Name: bumpHash(h, -1) + ".example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET}
	msg.Ns = []dns.RR{n3}
	if err := VerifyWildcardAnswer(msg); err != nil {
		t.Fatalf("wildcard answer with covering NSEC3 should verify, got %v", err)
	}
}

func TestVerifyWildcardAnswer_NSEC3ExactOwnerRejected(t *testing.T) {
	const nextCloser = "secure.example.com."
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		aRR(nextCloser),
		wildcardSig(nextCloser, 2),
	}

	exact := makeNSEC3(nextCloser, "", false, nil)
	hash := dns.HashName(nextCloser, exact.Hash, exact.Iterations, exact.Salt)
	exact.NextDomain = adjacentNSEC3Hash(t, hash, 1)
	if !exact.Match(nextCloser) || !exact.Cover(nextCloser) {
		t.Fatal("test requires the DNS library to report both Match and Cover for the exact owner")
	}
	msg.Ns = []dns.RR{exact}

	if err := VerifyWildcardAnswer(msg); err != ErrWildcardNoDenial {
		t.Fatalf("exact NSEC3 owner must not deny the wildcard next closer, got %v", err)
	}
}

// bumpHash returns the base32hex-encoded label h shifted by delta in its
// last character, producing a neighbour hash for building covering NSEC3
// intervals in tests.
func bumpHash(h string, delta int) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	b := []byte(h)
	idx := len(alphabet) - 1
	for i := range len(alphabet) {
		if alphabet[i] == b[len(b)-1] {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(alphabet)) % len(alphabet)
	b[len(b)-1] = alphabet[idx]
	return string(b)
}
