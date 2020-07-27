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
