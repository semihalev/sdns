package middleware

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Chain(t *testing.T) {
	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := NewChain([]Handler{&dummy{}})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(512, true)
	ch.Reset(w, req)

	ch.Next(context.Background())

	req.Rcode = dns.RcodeSuccess
	err := ch.Writer.WriteMsg(req)
	assert.NoError(t, err)

	data, err := req.Pack()
	assert.NoError(t, err)

	assert.Equal(t, true, ch.Writer.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	_, err = ch.Writer.Write(data)
	assert.Equal(t, errAlreadyWritten, err)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), req)
	size, err := ch.Writer.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), size)
	assert.NotNil(t, ch.Writer.Msg())

	err = ch.Writer.WriteMsg(req)
	assert.Equal(t, errAlreadyWritten, err)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), req)
	_, err = ch.Writer.Write([]byte{})
	assert.Error(t, err)

	assert.Equal(t, "tcp", ch.Writer.Proto())
	assert.Equal(t, "127.0.0.1", ch.Writer.RemoteIP().String())

	ch.Cancel()
	assert.Equal(t, 0, ch.count)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), req)

	ch.CancelWithRcode(dns.RcodeServerFailure, true)
	assert.True(t, ch.Writer.Written())
	assert.Equal(t, dns.RcodeServerFailure, ch.Writer.Rcode())
	assert.Equal(t, 0, ch.count)
}
