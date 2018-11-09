package resolver

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_upperName(t *testing.T) {

	qlist := []struct {
		Asset  string
		Expect string
	}{
		{"demo-domain.com.", "com."},
		{"demo-domain.com.tr.", "com.tr."},
		{"go.istanbul.", "istanbul."},
		{"com.", ""},
	}

	for _, e := range qlist {

		if u := upperName(e.Asset); u != e.Expect {
			t.Errorf("unexpected value. asset: %s, expect: %s, value: %s", e.Asset, e.Expect, u)
		}
	}
}

func Test_randInt(t *testing.T) {
	for i := 0; i < 20; i++ {
		val := randInt(0, 10)
		assert.Equal(t, true, val < 10)
	}

	val := randInt(0, 0)
	assert.Equal(t, 0, val)
}

func Test_shuffleRR(t *testing.T) {

	vals := make([]dns.RR, 1)
	vals[0] = *new(dns.RR)

	rr := shuffleRR(vals)

	if len(rr) != 1 {
		t.Error("invalid array length")
	}
}

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

	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		A: net.ParseIP("127.0.0.1")}
	m.Answer = append(m.Answer, a)

	addr, found := searchAddr(m)
	assert.Equal(t, addr, "127.0.0.1")
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
