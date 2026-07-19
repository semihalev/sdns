package middleware

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestResponseMeta_ConcurrentBoundCut(t *testing.T) {
	var meta ResponseMeta
	base := time.Now()
	earliest := base.Add(time.Second)
	const earliestKey = uint64(0xfeed)

	deadlines := make([]time.Time, 128)
	for i := range deadlines {
		deadlines[i] = base.Add(time.Duration(i+2) * time.Second)
	}
	deadlines[len(deadlines)/2] = earliest

	var wg sync.WaitGroup
	for i, deadline := range deadlines {
		deadline := deadline
		key := uint64(i + 1)
		if deadline.Equal(earliest) {
			key = earliestKey
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta.BoundCutFor(deadline, key)
		}()
	}
	wg.Wait()

	if got := meta.CutUntil(); !got.Equal(earliest) {
		t.Fatalf("CutUntil = %v, want earliest concurrent deadline %v", got, earliest)
	}
	if got := meta.CutKey(); got != earliestKey {
		t.Fatalf("CutKey = %#x, want earliest cut key %#x", got, earliestKey)
	}

	meta.Reset()
	if got := meta.CutUntil(); !got.IsZero() {
		t.Fatalf("CutUntil after Reset = %v, want zero", got)
	}
	if got := meta.CutKey(); got != 0 {
		t.Fatalf("CutKey after Reset = %#x, want zero", got)
	}
}

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
