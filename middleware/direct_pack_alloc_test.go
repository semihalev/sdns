//go:build !race

package middleware

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// discardSink is a transport double that swallows bytes without recording
// them, so a measurement over it sees the write path and nothing else.
type discardSink struct{ wrote int }

func (s *discardSink) Write(b []byte) (int, error) { s.wrote = len(b); return len(b), nil }
func (s *discardSink) WriteMsg(*dns.Msg) error     { s.wrote = -1; return nil }
func (s *discardSink) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (s *discardSink) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 5353}
}
func (s *discardSink) Close() error        { return nil }
func (s *discardSink) TsigStatus() error   { return nil }
func (s *discardSink) TsigTimersOnly(bool) {}
func (s *discardSink) Hijack()             {}

// TestDirectPackWriteDoesNotAllocate is the point of the whole path: writing
// an ordinary answer to an owned transport costs neither the library's
// compression dictionary nor its output buffer nor anything of this layer's
// own.
//
// Excluded under the race detector, whose sync.Pool instrumentation is what
// an allocation count taken there would measure.
func TestDirectPackWriteDoesNotAllocate(t *testing.T) {
	sink := &discardSink{}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp, _ := directPackResponse(t)

	// Reset happens once per query regardless of how the response leaves;
	// what this measures is the write. Rewinding the written marker is the
	// one piece of test scaffolding inside the loop, and it allocates
	// nothing.
	ch := NewChain(nil)
	ch.Reset(sink, req)
	ch.AllowDirectPack()
	w := ch.Writer.(*responseWriter)

	allocs := testing.AllocsPerRun(200, func() {
		w.size = -1
		if err := w.WriteMsg(resp); err != nil {
			t.Fatal(err)
		}
		if sink.wrote <= 0 {
			t.Fatal("the direct path did not write raw bytes")
		}
	})
	if allocs != 0 {
		t.Fatalf("a direct response write cost %.0f allocations", allocs)
	}
}
