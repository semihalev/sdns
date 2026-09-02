package middleware

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// byteSink is a transport double that records what arrives on each of the
// two doors: raw bytes through Write, messages through WriteMsg. The direct
// path must use exactly one of them.
type byteSink struct {
	raw      [][]byte
	msgs     []*dns.Msg
	writeErr error
	remote   net.Addr
}

func (s *byteSink) Write(b []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	// Copied: the slice is borrowed pooled storage, valid only for the call.
	s.raw = append(s.raw, append([]byte(nil), b...))
	return len(b), nil
}

func (s *byteSink) WriteMsg(m *dns.Msg) error { s.msgs = append(s.msgs, m); return nil }
func (s *byteSink) LocalAddr() net.Addr       { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (s *byteSink) RemoteAddr() net.Addr      { return s.remote }
func (s *byteSink) Close() error              { return nil }
func (s *byteSink) TsigStatus() error         { return nil }
func (s *byteSink) TsigTimersOnly(bool)       {}
func (s *byteSink) Hijack()                   {}

func externalUDPSink() *byteSink {
	return &byteSink{remote: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 5353}}
}

func directPackResponse(tb testing.TB) (*dns.Msg, []byte) {
	tb.Helper()
	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Id = 99
	resp.Response = true
	rr, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	if err != nil {
		tb.Fatal(err)
	}
	resp.Answer = []dns.RR{rr}
	resp.Compress = true
	want, err := resp.Copy().Pack()
	if err != nil {
		tb.Fatal(err)
	}
	return resp, want
}

func directPackChain(tb testing.TB, sink dns.ResponseWriter) *Chain {
	tb.Helper()
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ch := NewChain(nil)
	ch.Reset(sink, req)
	return ch
}

// TestDirectPackWritesRawBytes pins the declared path end to end at the
// writer level: raw library-parity bytes through Write, nothing through
// WriteMsg, and the observable state, Written, Size, Rcode, Msg with
// pointer identity, exactly as the Msg path would leave it.
func TestDirectPackWritesRawBytes(t *testing.T) {
	sink := externalUDPSink()
	ch := directPackChain(t, sink)
	ch.AllowDirectPack()

	resp, want := directPackResponse(t)
	if err := ch.Writer.WriteMsg(resp); err != nil {
		t.Fatal(err)
	}

	if len(sink.msgs) != 0 {
		t.Fatal("the direct path handed the transport a message")
	}
	if len(sink.raw) != 1 || !bytes.Equal(sink.raw[0], want) {
		t.Fatalf("raw writes = %d, parity = %v",
			len(sink.raw), len(sink.raw) == 1 && bytes.Equal(sink.raw[0], want))
	}
	if !ch.Writer.Written() {
		t.Fatal("not marked written")
	}
	if got := ResponseSize(ch.Writer); got != len(want) {
		t.Fatalf("Size() = %d, want %d", got, len(want))
	}
	if ch.Writer.Rcode() != resp.Rcode {
		t.Fatalf("Rcode() = %d", ch.Writer.Rcode())
	}
	if ch.Writer.Msg() != resp {
		t.Fatal("Msg() lost pointer identity; request-local provenance is keyed on it")
	}

	// A second write is refused, exactly as on the Msg path.
	if err := ch.Writer.WriteMsg(resp); !errors.Is(err, errAlreadyWritten) {
		t.Fatalf("second write: %v", err)
	}
}

// TestDirectPackIsDeclaredNotInferred pins the capability model: a writer
// that merely looks like a datagram transport gets the Msg path unless the
// owned-listener ingress declared otherwise.
func TestDirectPackIsDeclaredNotInferred(t *testing.T) {
	sink := externalUDPSink()
	ch := directPackChain(t, sink) // no AllowDirectPack

	resp, _ := directPackResponse(t)
	if err := ch.Writer.WriteMsg(resp); err != nil {
		t.Fatal(err)
	}
	if len(sink.raw) != 0 {
		t.Fatal("an undeclared writer received raw bytes")
	}
	if len(sink.msgs) != 1 || sink.msgs[0] != resp {
		t.Fatal("the Msg path did not carry the message")
	}
}

// TestDirectPackDoesNotSurviveReset pins the pooled-chain hazard: the
// capability is per-request, and a chain reused for the next writer must not
// carry it over.
func TestDirectPackDoesNotSurviveReset(t *testing.T) {
	first := externalUDPSink()
	ch := directPackChain(t, first)
	ch.AllowDirectPack()

	second := externalUDPSink()
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ch.Reset(second, req)

	resp, _ := directPackResponse(t)
	if err := ch.Writer.WriteMsg(resp); err != nil {
		t.Fatal(err)
	}
	if len(second.raw) != 0 {
		t.Fatal("the capability leaked across Reset")
	}
	if len(second.msgs) != 1 {
		t.Fatal("the Msg path did not carry the message")
	}
}

// TestDirectPackFallsBackThroughTheMsgPath pins the fallback: a message
// TryPack cannot handle takes the library path with zero raw bytes written
// first.
func TestDirectPackFallsBackThroughTheMsgPath(t *testing.T) {
	sink := externalUDPSink()
	ch := directPackChain(t, sink)
	ch.AllowDirectPack()

	// An extended rcode with no OPT to carry it: the library's own error
	// belongs to the library, so the direct path steps aside.
	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Rcode = dns.RcodeBadVers
	_ = ch.Writer.WriteMsg(resp)

	if len(sink.raw) != 0 {
		t.Fatal("bytes were written before the fallback")
	}
	if len(sink.msgs) != 1 {
		t.Fatal("the fallback did not reach the transport's WriteMsg")
	}
}

// TestDirectPackTransportErrorIsFinal pins the no-retry contract: after a
// transport error, bytes may be partially out. The response is marked
// written and nothing writes a second one.
func TestDirectPackTransportErrorIsFinal(t *testing.T) {
	sink := externalUDPSink()
	sink.writeErr = errors.New("transport failed")
	ch := directPackChain(t, sink)
	ch.AllowDirectPack()

	resp, want := directPackResponse(t)
	if err := ch.Writer.WriteMsg(resp); !errors.Is(err, sink.writeErr) {
		t.Fatalf("WriteMsg = %v, want the transport's error", err)
	}
	if len(sink.msgs) != 0 {
		t.Fatal("a message was written after the transport error")
	}
	if !ch.Writer.Written() {
		t.Fatal("an errored write must still mark the response written")
	}
	if got := ResponseSize(ch.Writer); got != len(want) {
		t.Fatalf("Size() = %d, want %d", got, len(want))
	}
	if err := ch.Writer.WriteMsg(resp); !errors.Is(err, errAlreadyWritten) {
		t.Fatalf("second write: %v", err)
	}
}

// TestDirectPackSkipsInternalQueries pins the internal exclusion: a
// sub-query's consumer wants the message, and packing it would only be
// unpacked again.
func TestDirectPackSkipsInternalQueries(t *testing.T) {
	sink := &byteSink{remote: &net.UDPAddr{IP: internalIP, Port: 0}}
	ch := directPackChain(t, sink)
	ch.AllowDirectPack()

	resp, _ := directPackResponse(t)
	if err := ch.Writer.WriteMsg(resp); err != nil {
		t.Fatal(err)
	}
	if len(sink.raw) != 0 {
		t.Fatal("an internal query was served raw bytes")
	}
	if len(sink.msgs) != 1 || sink.msgs[0] != resp {
		t.Fatal("the internal query lost its message")
	}
}
