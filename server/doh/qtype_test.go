package doh

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func Test_ParseQTYPE(t *testing.T) {
	qtype := ParseQTYPE("")
	if !reflect.DeepEqual(qtype, dns.TypeA) {
		t.Errorf("dns.TypeA = %v, want %v", dns.TypeA, qtype)
	}

	qtype = ParseQTYPE("1")
	if !reflect.DeepEqual(qtype, dns.TypeA) {
		t.Errorf("dns.TypeA = %v, want %v", dns.TypeA, qtype)
	}

	qtype = ParseQTYPE("CNAME")
	if !reflect.DeepEqual(qtype, dns.TypeCNAME) {
		t.Errorf("dns.TypeCNAME = %v, want %v", dns.TypeCNAME, qtype)
	}

	qtype = ParseQTYPE("TEST")
	if !reflect.DeepEqual(qtype, dns.TypeNone) {
		t.Errorf("dns.TypeNone = %v, want %v", dns.TypeNone, qtype)
	}
}
