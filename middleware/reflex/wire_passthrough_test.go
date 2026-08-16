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
	wireErr    error
}

func (s *wireSink) WireReady() (middleware.WireCapability, bool) {
	return s.capability, true
}

func (s *wireSink) WriteWire(body []byte, info middleware.WireInfo) error {
	if s.wireErr != nil {
		return s.wireErr
	}
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
		reqLen:         req.Len(),
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

// TestReflexCountsAResponseOnce pins the fallback contract review
// demonstrated the violation of: the amplification observation commits only
// when the chain actually served the bytes. On ErrWireFallback the Msg
// retry records that serve — counting here too would credit the source with
// the same response twice and inflate its score toward the block threshold.
func TestReflexCountsAResponseOnce(t *testing.T) {
	sink := &wireSink{Writer: mock.NewWriter("udp", "203.0.113.9:5353")}
	sink.wireErr = middleware.ErrWireFallback
	rw, tracker := reflexWrapped(sink)

	body := make([]byte, 200)
	if err := rw.WriteWire(body, middleware.WireInfo{}); !errors.Is(err, middleware.ErrWireFallback) {
		t.Fatalf("WriteWire = %v, want the fallback through", err)
	}

	// The cache's retry on the Msg path.
	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeANY)
	rr, err := dns.NewRR("example.com. 300 IN TXT \"answer\"")
	if err != nil {
		t.Fatal(err)
	}
	resp.Answer = []dns.RR{rr}
	if err := rw.WriteMsg(resp); err != nil {
		t.Fatal(err)
	}

	tracker.mu.Lock()
	entry := tracker.entries["203.0.113.9"]
	tracker.mu.Unlock()
	if entry == nil {
		t.Fatal("the tracker saw no response at all")
	}
	if want := uint64(resp.Len()); entry.TotalResponseBytes != want { //nolint:gosec // a message length is positive
		t.Fatalf("the tracker recorded %d response bytes, want %d — the "+
			"declined wire write was counted on top of the Msg retry",
			entry.TotalResponseBytes, want)
	}

	// A terminal transport error is the opposite case: bytes left the
	// process and the observation stands.
	sink2 := &wireSink{Writer: mock.NewWriter("udp", "203.0.113.9:5353")}
	sink2.wireErr = errors.New("transport failed")
	rw2, tracker2 := reflexWrapped(sink2)
	if err := rw2.WriteWire(body, middleware.WireInfo{}); !errors.Is(err, sink2.wireErr) {
		t.Fatalf("WriteWire = %v, want the transport's error", err)
	}
	tracker2.mu.Lock()
	entry2 := tracker2.entries["203.0.113.9"]
	tracker2.mu.Unlock()
	if entry2 == nil || entry2.TotalResponseBytes != uint64(len(body)) {
		t.Fatal("an errored serve was not recorded")
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
