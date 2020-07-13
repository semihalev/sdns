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
	err := mw.WriteMsg(m)

	assert.NoError(t, err)
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

	assert.Equal(t, "tcp", mw.Proto())
	assert.Equal(t, "127.0.0.1", mw.RemoteIP().String())

	_, err = mw.Write([]byte{})
	assert.Error(t, err)

	data, err := m.Pack()
	assert.NoError(t, err)
	_, err = mw.Write(data)
	assert.NoError(t, err)
	assert.True(t, mw.Written())
	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)
	assert.True(t, mw.Internal())
}
