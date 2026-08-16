package middleware

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// flushRecordingTransport records whether FlushStaged ran before the
// slow handler proceeded.
type flushRecordingTransport struct {
	flushed bool
	wrote   []byte
}

func (t *flushRecordingTransport) FlushStaged() { t.flushed = true }
func (t *flushRecordingTransport) Write(b []byte) (int, error) {
	t.wrote = append(t.wrote[:0], b...)
	return len(b), nil
}
func (t *flushRecordingTransport) WriteMsg(m *dns.Msg) error {
	raw, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = t.Write(raw)
	return err
}
func (t *flushRecordingTransport) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (t *flushRecordingTransport) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 5353}
}
func (t *flushRecordingTransport) Close() error { return nil }

// TestDetachFlushesStagedReplies pins the head-of-line fix: the moment a
// request leaves the strict path — slow work is now certain — replies
// already staged on the transport go out. Without this, a cache hit
// staged a moment earlier sat in the batch for the whole recursion of
// the unrelated query behind it.
func TestDetachFlushesStagedReplies(t *testing.T) {
	transport := &flushRecordingTransport{}

	slow := HandlerFunc(func(ctx context.Context, ch *Chain) {
		// The handler materializes — the transition every miss makes —
		// and by the time it could start slow work, the staged replies
		// must already be gone.
		_, req := ch.Materialize(ctx)
		if req == nil {
			t.Error("materialize failed")
			return
		}
		if !transport.flushed {
			t.Error("staged replies were not flushed at the strict-path detach; " +
				"they would wait out this handler's recursion")
		}
		m := new(dns.Msg)
		m.SetReply(req)
		_ = ch.Writer.WriteMsg(m)
		ch.Cancel()
	})

	q := new(dns.Msg)
	q.SetQuestion("hol.example.", dns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	ch := NewChain([]Handler{slow})
	var req Request
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("wire parse failed")
	}
	ch.ResetWire(transport, &req)
	ch.Next(context.Background())
	ch.Finish()

	if len(transport.wrote) == 0 {
		t.Fatal("no reply written")
	}
}
