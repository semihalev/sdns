package mock

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_Writer(t *testing.T) {
	mw := NewWriter("udp", "127.0.0.1:0")

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	mw.WriteMsg(m)

	assert.True(t, mw.Written())
	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)
	assert.NotNil(t, mw.Msg())
	assert.Equal(t, mw.LocalAddr().String(), "127.0.0.1:53")
	assert.Equal(t, mw.RemoteAddr().String(), "127.0.0.1:0")
	assert.Nil(t, mw.Close())
	assert.Nil(t, mw.TsigStatus())

	mw = NewWriter("tcp", "127.0.0.1:0")
	assert.False(t, mw.Written())
	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	_, err := mw.Write([]byte{})
	assert.Error(t, err)

	data, err := m.Pack()
	assert.NoError(t, err)
	mw.Write(data)
	assert.True(t, mw.Written())
	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)
}
