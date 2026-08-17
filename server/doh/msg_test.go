package doh

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func Test_Msg(t *testing.T) {
	m := NewMsg(nil)
	if m != nil {
		t.Errorf("m = %v, want nil", m)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)

	rr, err := dns.NewRR(".			518400	IN	NS	a.root-servers.net.")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	msg.Answer = append(msg.Answer, rr)

	rr, err = dns.NewRR("a.gtld-servers.net.	172800	IN	A	192.5.6.30")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	msg.Ns = append(msg.Ns, rr)

	m = NewMsg(msg)

	if !reflect.DeepEqual(m.Answer[0].Data, msg.Answer[0].(*dns.NS).Ns) {
		t.Errorf("msg.Answer[0].(*dns.NS).Ns = %v, want %v", msg.Answer[0].(*dns.NS).Ns, m.Answer[0].Data)
	}
	if !reflect.DeepEqual(m.Authority[0].Data, msg.Ns[0].(*dns.A).A.String()) {
		t.Errorf("msg.Ns[0].(*dns.A).A.String() = %v, want %v", msg.Ns[0].(*dns.A).A.String(), m.Authority[0].Data)
	}
}
