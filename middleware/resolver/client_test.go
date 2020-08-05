package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/stretchr/testify/assert"
)

func Test_ClientTimeout(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	var err error
	co.Conn, err = dialer.Dial("udp4", "127.1.0.255:53")
	assert.NoError(t, err)

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	assert.NoError(t, err)

	_, _, err = co.Exchange(req)
	assert.Error(t, err)
	assert.NoError(t, co.Close())
}

func Test_Client(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	var err error
	co.Conn, err = dialer.Dial("udp4", "198.41.0.4:53")
	assert.NoError(t, err)

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	assert.NoError(t, err)

	r, _, err := co.Exchange(req)
	assert.NoError(t, err)
	assert.NotNil(t, r)
}
