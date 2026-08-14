package dnstap

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// wireSink is a mock middleware writer that is also a byte sink, recording
// arrival order so the tap's position relative to the transport write is
// observable.
type wireSink struct {
	*mock.Writer
	capability middleware.WireCapability
	bodies     [][]byte
	writeSeen  func()
}

func (s *wireSink) WireReady() (middleware.WireCapability, bool) {
	return s.capability, true
}

func (s *wireSink) WriteWire(body []byte, _ middleware.WireInfo) error {
	if s.writeSeen != nil {
		s.writeSeen()
	}
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	return nil
}

func tapForTest() *Dnstap {
	return &Dnstap{
		identity:     []byte("test"),
		version:      []byte("test"),
		messageQueue: make(chan *DnstapMessage, 4),
		done:         make(chan struct{}),
	}
}

func tapWrapped(next middleware.ResponseWriter, d *Dnstap) *responseWriter {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 7
	return &responseWriter{
		ResponseWriter: next,
		query:          query,
		queryTime:      time.Now(),
		dnstap:         d,
	}
}

// TestDnstapPassesTheBytePathThrough pins the whole point of the pair: the
// tap observes, the bytes pass unchanged, and the tap's copy is its own —
// the body it saw is borrowed pooled storage that will be overwritten by the
// next response.
func TestDnstapPassesTheBytePathThrough(t *testing.T) {
	d := tapForTest()
	sink := &wireSink{
		Writer:     mock.NewWriter("udp", "203.0.113.9:5353"),
		capability: middleware.WireCapability{Reserve: 11, MaxSize: 1232},
	}
	rw := tapWrapped(sink, d)

	capability, ok := rw.WireReady()
	if !ok || capability != sink.capability {
		t.Fatalf("WireReady = %+v, %v; want the sink's capability through", capability, ok)
	}

	body := []byte{0x12, 0x34, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := rw.WriteWire(body, middleware.WireInfo{Rcode: dns.RcodeSuccess}); err != nil {
		t.Fatal(err)
	}
	if len(sink.bodies) != 1 || !bytes.Equal(sink.bodies[0], body) {
		t.Fatal("the bytes did not pass through unchanged")
	}

	var tap *DnstapMessage
	select {
	case tap = <-d.messageQueue:
	default:
		t.Fatal("no tap message was enqueued")
	}
	if tap.Type != MessageTypeResponse {
		t.Fatalf("tap type = %v", tap.Type)
	}
	if !bytes.Equal(tap.ResponseMsg, body) {
		t.Fatal("the tap does not carry the response bytes")
	}
	if len(tap.QueryMessage) == 0 {
		t.Fatal("the tap lost the query the WriteMsg path records")
	}

	// The queue is asynchronous: the tap's bytes must survive the pooled
	// buffer being reused for the next response.
	for i := range body {
		body[i] = 0xEE
	}
	if bytes.Equal(tap.ResponseMsg, body) {
		t.Fatal("the tap aliases the borrowed body instead of owning a copy")
	}
}

// TestDnstapTapsBeforeTheTransportWrite pins the order: an observer must not
// learn a different sequence from a different serving path, and WriteMsg
// taps before it forwards.
func TestDnstapTapsBeforeTheTransportWrite(t *testing.T) {
	d := tapForTest()
	sink := &wireSink{Writer: mock.NewWriter("udp", "203.0.113.9:5353")}
	sink.writeSeen = func() {
		if len(d.messageQueue) == 0 {
			t.Error("the transport write ran before the tap was enqueued")
		}
	}
	rw := tapWrapped(sink, d)

	if err := rw.WriteWire([]byte{0x12, 0x34}, middleware.WireInfo{}); err != nil {
		t.Fatal(err)
	}
}

// TestDnstapWireFallsBackOverAPlainWriter pins the chain rule.
func TestDnstapWireFallsBackOverAPlainWriter(t *testing.T) {
	d := tapForTest()
	rw := tapWrapped(mock.NewWriter("udp", "203.0.113.9:5353"), d)

	if _, ok := rw.WireReady(); ok {
		t.Fatal("WireReady reported a byte sink over a plain writer")
	}
	if err := rw.WriteWire([]byte{0}, middleware.WireInfo{}); !errors.Is(err, middleware.ErrWireFallback) {
		t.Fatalf("WriteWire = %v, want ErrWireFallback", err)
	}
	if len(d.messageQueue) != 0 {
		t.Fatal("a fallback enqueued a tap; the Msg path will tap it again")
	}
}
