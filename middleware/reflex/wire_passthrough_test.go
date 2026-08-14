package reflex

import (
	"bytes"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// wireSink is a mock middleware writer that is also a byte sink, recording
// what reaches it on the wire door.
type wireSink struct {
	*mock.Writer
	capability middleware.WireCapability
	bodies     [][]byte
	infos      []middleware.WireInfo
}

func (s *wireSink) WireReady() (middleware.WireCapability, bool) {
	return s.capability, true
}

func (s *wireSink) WriteWire(body []byte, info middleware.WireInfo) error {
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	s.infos = append(s.infos, info)
	return nil
}

func reflexWrapped(next middleware.ResponseWriter) (*responseWriter, *IPTracker) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	tracker := NewIPTracker(100)
	// RecordResponse only counts against a source the tracker has seen ask.
	tracker.RecordQuery("203.0.113.9", dns.TypeANY, getAmpFactor(dns.TypeANY), req.Len())
	return &responseWriter{
		ResponseWriter: next,
		request:        req,
		tracker:        tracker,
		ip:             "203.0.113.9",
	}, tracker
}

// TestReflexPassesTheBytePathThrough pins the reason this layer implements
// the wire pair at all: its presence must not push a cache hit back onto the
// Msg path.
func TestReflexPassesTheBytePathThrough(t *testing.T) {
	sink := &wireSink{
		Writer:     mock.NewWriter("udp", "203.0.113.9:5353"),
		capability: middleware.WireCapability{DO: true, Reserve: 11, MaxSize: 1232},
	}
	rw, tracker := reflexWrapped(sink)

	capability, ok := rw.WireReady()
	if !ok || capability != sink.capability {
		t.Fatalf("WireReady = %+v, %v; want the sink's capability through", capability, ok)
	}

	body := []byte{0x12, 0x34, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	info := middleware.WireInfo{Rcode: dns.RcodeSuccess, AuthenticatedData: true}
	if err := rw.WriteWire(body, info); err != nil {
		t.Fatal(err)
	}
	if len(sink.bodies) != 1 || !bytes.Equal(sink.bodies[0], body) {
		t.Fatal("the bytes did not pass through unchanged")
	}
	if sink.infos[0] != info {
		t.Fatal("the info did not pass through unchanged")
	}

	// The observation this layer exists for: the response's true wire
	// length, recorded against the source.
	tracker.mu.Lock()
	entry := tracker.entries["203.0.113.9"]
	tracker.mu.Unlock()
	if entry == nil || entry.TotalResponseBytes != uint64(len(body)) {
		t.Fatalf("the tracker recorded %v response bytes, want %d",
			entry, len(body))
	}
}

// TestReflexWireFallsBackOverAPlainWriter pins the chain rule: a writer
// beneath that is not a byte sink turns the pair off cleanly.
func TestReflexWireFallsBackOverAPlainWriter(t *testing.T) {
	rw, _ := reflexWrapped(mock.NewWriter("udp", "203.0.113.9:5353"))

	if _, ok := rw.WireReady(); ok {
		t.Fatal("WireReady reported a byte sink over a plain writer")
	}
	if err := rw.WriteWire([]byte{0}, middleware.WireInfo{}); !errors.Is(err, middleware.ErrWireFallback) {
		t.Fatalf("WriteWire = %v, want ErrWireFallback", err)
	}
}
