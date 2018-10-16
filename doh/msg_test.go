package doh

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_Msg(t *testing.T) {
	m := NewMsg(nil)
	assert.Nil(t, m)

	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)

	rr, err := dns.NewRR(".			518400	IN	NS	a.root-servers.net.")
	assert.NoError(t, err)

	msg.Answer = append(msg.Answer, rr)

	rr, err = dns.NewRR("a.gtld-servers.net.	172800	IN	A	192.5.6.30")
	assert.NoError(t, err)

	msg.Ns = append(msg.Ns, rr)

	m = NewMsg(msg)

	assert.Equal(t, m.Answer[0].Data, msg.Answer[0].(*dns.NS).Ns)
	assert.Equal(t, m.Authority[0].Data, msg.Ns[0].(*dns.A).A.String())
}
