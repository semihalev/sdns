package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_keyGen(t *testing.T) {

	q := Question{"@", "A", "ANY"}

	asset := keyGen(q)

	assert.Equal(t, asset, "b78555bf3268be8a25d31ab80a47b6e9")
}

func Test_unFqdn(t *testing.T) {

	q := "demo-domain.com."

	asset := unFqdn(q)

	if strings.HasSuffix(asset, ".") {
		t.Error("dot not removed dot in unFqdn func. asset:", asset)
	}

	q = "demo-domain.com"
	assert.Equal(t, unFqdn(q), q)
}

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

func Test_findLocalIPAddresses(t *testing.T) {
	var err error
	localIPs, err = findLocalIPAddresses()

	assert.NoError(t, err)
	assert.Equal(t, len(localIPs) > 0, true)

	assert.Equal(t, isLocalIP(localIPs[0]), true)

	assert.Equal(t, isLocalIP("255.255.255.255"), false)
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
