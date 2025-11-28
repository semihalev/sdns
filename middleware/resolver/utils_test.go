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

	// Add DNAME record for exact match
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
	assert.Equal(t, "target.com.", target)

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
}

func Test_checkExponent(t *testing.T) {
	// Test with invalid base64
	result := checkExponent("!!!invalid!!!")
	assert.True(t, result) // Returns true on error

	// Test with too short key
	result = checkExponent("AQAB") // Very short
	assert.True(t, result)
}
