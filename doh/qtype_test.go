package doh

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_ParseQTYPE(t *testing.T) {
	qtype := ParseQTYPE("")
	assert.Equal(t, qtype, dns.TypeA)

	qtype = ParseQTYPE("1")
	assert.Equal(t, qtype, dns.TypeA)

	qtype = ParseQTYPE("CNAME")
	assert.Equal(t, qtype, dns.TypeCNAME)

	qtype = ParseQTYPE("TEST")
	assert.Equal(t, qtype, dns.TypeNone)
}
