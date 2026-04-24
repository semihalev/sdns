package resolver

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_shuffleStr(t *testing.T) {

	vals := make([]string, 1)

	rr := shuffleStr(vals)

	if len(rr) != 1 {
		t.Error("invalid array length")
	}
}

func Test_searchAddr(t *testing.T) {
	testDomain := "google.com."

	m := new(dns.Msg)
	m.SetQuestion(testDomain, dns.TypeA)

	m.SetEdns0(512, true)
	assert.Equal(t, isDO(m), true)

	m.Extra = []dns.RR{}
	assert.Equal(t, isDO(m), false)

	a1 := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		A: net.ParseIP("127.0.0.1")}

	m.Answer = append(m.Answer, a1)

	a2 := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		A: net.ParseIP("192.0.2.1")}

	m.Answer = append(m.Answer, a2)

	addrs, found := searchAddrs(m)
	assert.Equal(t, len(addrs), 1)
	assert.NotEqual(t, addrs[0], "127.0.0.1")
	assert.Equal(t, addrs[0], "192.0.2.1")
	assert.Equal(t, found, true)
}

func Test_extractRRSet(t *testing.T) {
	var rr []dns.RR
	for i := 0; i < 3; i++ {
		a, _ := dns.NewRR(fmt.Sprintf("test.com. 5 IN A 127.0.0.%d", i))
		rr = append(rr, a)
	}

	rre := extractRRSet(rr, "test.com.", dns.TypeA)
	assert.Len(t, rre, 3)
}

func Test_extractRRSetMultipleTypes(t *testing.T) {
	var rr []dns.RR
	a, _ := dns.NewRR("test.com. 5 IN A 127.0.0.1")
	aaaa, _ := dns.NewRR("test.com. 5 IN AAAA ::1")
	mx, _ := dns.NewRR("test.com. 5 IN MX 10 mail.test.com.")
	rr = append(rr, a, aaaa, mx)

	// Test with multiple types
	rre := extractRRSet(rr, "test.com.", dns.TypeA, dns.TypeAAAA)
	assert.Len(t, rre, 2)

	// Test with empty input
	rre = extractRRSet(nil, "", dns.TypeA)
	assert.Nil(t, rre)

	// Test with name filter mismatch
	rre = extractRRSet(rr, "other.com.", dns.TypeA)
	assert.Len(t, rre, 0)
}

func Test_verifyNSEC(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA}

	// Create NSEC record with A type
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "next.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS},
	}

	// Should find A type
	typeMatch := verifyNSEC(q, []dns.RR{nsec})
	assert.True(t, typeMatch)

	// Query for type not in bitmap
	q2 := dns.Question{Name: "example.com.", Qtype: dns.TypeMX}
	typeMatch = verifyNSEC(q2, []dns.RR{nsec})
	assert.False(t, typeMatch)
}

func Test_getDnameTarget(t *testing.T) {
	msg := &dns.Msg{}
	msg.Question = []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeA}}

	// No DNAME record
	target := getDnameTarget(msg)
	assert.Empty(t, target)

	// Exact-owner match: RFC 6672 §2.3 — the DNAME owner itself is
	// *not* redirected, so no target is returned.
	dname := &dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "sub.example.com.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: "target.com.",
	}
	msg.Answer = []dns.RR{dname}
	target = getDnameTarget(msg)
	assert.Empty(t, target, "DNAME owner must not be redirected")

	// Test with subdomain
	msg.Question = []dns.Question{{Name: "deep.sub.example.com.", Qtype: dns.TypeA}}
	dname2 := &dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "sub.example.com.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: "newtarget.com.",
	}
	msg.Answer = []dns.RR{dname2}
	target = getDnameTarget(msg)
	assert.Equal(t, "deep.newtarget.com.", target)

	// Cousin name: qname shares a suffix with the DNAME owner but is
	// not a descendant. dns.CompareDomainName reports the shared
	// trailing labels regardless of ancestry, so without the explicit
	// ancestor check the helper would rewrite unrelated names.
	msg.Question = []dns.Question{{Name: "other.example.com.", Qtype: dns.TypeA}}
	msg.Answer = []dns.RR{dname2} // DNAME owner is sub.example.com.
	target = getDnameTarget(msg)
	assert.Empty(t, target, "cousin of DNAME owner must not be redirected")
}

// Test_verifyRRSIG_RejectsForeignPiggyback pins the defense that
// foreign unsigned RRsets next to signed in-zone data fail the
// validator. Without this, an attacker could piggyback junk foreign
// records on an otherwise-valid response and still get AD=true, in
// violation of RFC 4035 §3.2.3. Signature content is irrelevant — the
// check fires during record collection, before any crypto work.
func Test_verifyRRSIG_RejectsForeignPiggyback(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "irrelevant-test-value",
	}
	keys := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("1.2.3.4"),
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		SignerName:  "example.com.",
		KeyTag:      key.KeyTag(),
	}
	evil := &dns.TXT{
		Hdr: dns.RR_Header{Name: "evil.net.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"gotcha"},
	}
	msg := &dns.Msg{Answer: []dns.RR{a, sig, evil}}

	ok, err := verifyRRSIG("example.com.", keys, msg)
	assert.False(t, ok)
	assert.Equal(t, errMissingSigned, err, "foreign RRset must make the whole response bogus")
}

func Test_checkExponent(t *testing.T) {
	// Test with invalid base64
	result := checkExponent("!!!invalid!!!")
	assert.True(t, result) // Returns true on error

	// Test with too short key
	result = checkExponent("AQAB") // Very short
	assert.True(t, result)
}

// Test_isSupportedDNSKEYAlgorithm_RSAMD5 locks in the RFC 8624 /
// miekg/dns reality that RSAMD5 is not verifiable: if the DS-level
// filter ever classifies it as supported again, an RSAMD5-only DS set
// would be treated as usable and then bogus at RRSIG.Verify time
// instead of downgraded to insecure.
func Test_isSupportedDNSKEYAlgorithm_RSAMD5(t *testing.T) {
	assert.False(t, isSupportedDNSKEYAlgorithm(dns.RSAMD5),
		"RSAMD5 must be treated as unsupported — miekg/dns RRSIG.Verify returns ErrAlg for it")
	assert.True(t, isSupportedDNSKEYAlgorithm(dns.RSASHA256))
	assert.True(t, isSupportedDNSKEYAlgorithm(dns.ECDSAP256SHA256))
	assert.True(t, isSupportedDNSKEYAlgorithm(dns.ED25519))
}

// Test_filterToZone_NSECNextDomain pins the defense against the
// "in-zone owner with out-of-zone NextDomain" forgery: an attacker
// should not be able to satisfy the NSEC coverage check with an NSEC
// whose owner is inside the validated zone but whose NextDomain
// straddles a sibling zone, because a legitimate NSEC's NextDomain is
// always another owner in the same zone.
func Test_filterToZone_NSECNextDomain(t *testing.T) {
	crossZone := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
		NextDomain: "z.com.",
	}
	inZone := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "!.example.com.", Rrtype: dns.TypeNSEC},
		NextDomain: "zz.example.com.",
	}

	got := filterToZone([]dns.RR{crossZone, inZone}, "example.com.")
	assert.Len(t, got, 1, "NSEC with cross-zone NextDomain must be filtered out")
	assert.Equal(t, "!.example.com.", got[0].Header().Name)
}
