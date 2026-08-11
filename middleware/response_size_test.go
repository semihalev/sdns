package middleware

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
)

// compressibleReply is a response whose repeated owner names make its
// compressed form materially shorter than the length a decoded message
// reports — the gap that made access logs overstate response sizes.
func compressibleReply(t *testing.T) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion("www.a-fairly-long-name.example.com.", dns.TypeA)
	msg := new(dns.Msg)
	msg.SetReply(req)
	for i := range 8 {
		rr, err := dns.NewRR("www.a-fairly-long-name.example.com. 300 IN A 192.0.2." +
			strings.TrimSpace(string(rune('1'+i))))
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	msg.Compress = true
	return msg
}

// TestResponseSizeReportsWireLength pins the observers' contract on every
// route a response can take to the transport: the number reported is the
// number of bytes that actually went out.
func TestResponseSizeReportsWireLength(t *testing.T) {
	reply := compressibleReply(t)
	compressed, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	uncompressed := *reply
	uncompressed.Compress = false
	if plain, err := uncompressed.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	} else if len(plain) <= len(compressed) {
		t.Skip("fixture is not compressible on this library version")
	}

	t.Run("raw write", func(t *testing.T) {
		w := &responseWriter{}
		w.Reset(mock.NewWriter("udp", "192.0.2.1:53000"))
		if _, err := w.Write(compressed); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := ResponseSize(w); got != len(compressed) {
			t.Fatalf("size = %d, want the %d bytes written; a decoded message "+
				"loses Compress and overstates the response", got, len(compressed))
		}
	})

	t.Run("wire write", func(t *testing.T) {
		w := &responseWriter{}
		w.Reset(mock.NewWriter("udp", "192.0.2.1:53000"))
		if err := w.WriteWire(compressed, WireInfo{Rcode: dns.RcodeSuccess}); err != nil {
			t.Fatalf("write wire: %v", err)
		}
		if got := ResponseSize(w); got != len(compressed) {
			t.Fatalf("size = %d, want %d", got, len(compressed))
		}
	})

	t.Run("message write", func(t *testing.T) {
		w := &responseWriter{}
		w.Reset(mock.NewWriter("udp", "192.0.2.1:53000"))
		if err := w.WriteMsg(reply); err != nil {
			t.Fatalf("write msg: %v", err)
		}
		// No byte count exists on this route; the message's own length is
		// the honest answer, and it accounts for compression because the
		// message still carries the flag.
		if got, want := ResponseSize(w), reply.Len(); got != want {
			t.Fatalf("size = %d, want %d", got, want)
		}
	})
}

// streamWriter models a stream transport: miekg's TCP and DoQ writers
// prepend a two-byte length prefix and return the framed count, so a writer
// that trusts that return value overstates every stream response.
type streamWriter struct {
	*mock.Writer
	framed int
}

func (w *streamWriter) Write(b []byte) (int, error) {
	w.framed = len(b) + 2
	return w.framed, nil
}

// TestResponseSizeExcludesStreamFraming pins the payload/framing boundary:
// the size an observer reports is the DNS message's own length, never the
// transport's framed byte count.
func TestResponseSizeExcludesStreamFraming(t *testing.T) {
	reply := compressibleReply(t)
	body, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	for _, tc := range []struct {
		name  string
		write func(w *responseWriter) error
	}{
		{"raw write", func(w *responseWriter) error {
			_, err := w.Write(body)
			return err
		}},
		{"wire write", func(w *responseWriter) error {
			return w.WriteWire(body, WireInfo{Rcode: dns.RcodeSuccess})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &streamWriter{Writer: mock.NewWriter("tcp", "192.0.2.1:53000")}
			w := &responseWriter{}
			w.Reset(stream)
			if err := tc.write(w); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := ResponseSize(w); got != len(body) {
				t.Fatalf("size = %d, want the %d-byte payload; the transport "+
					"reported %d including its length prefix",
					got, len(body), stream.framed)
			}
		})
	}
}

// sizelessWriter implements ResponseWriter without Size, standing in for a
// plugin writer that predates the optional interface.
type sizelessWriter struct {
	ResponseWriter
	msg *dns.Msg
}

func (w *sizelessWriter) Msg() *dns.Msg { return w.msg }

// TestResponseSizeToleratesWritersWithoutSize pins the compatibility
// promise: a writer that never heard of Size still works, and callers get a
// sensible answer rather than a compile error or a zero.
func TestResponseSizeToleratesWritersWithoutSize(t *testing.T) {
	reply := compressibleReply(t)
	w := &sizelessWriter{msg: reply}
	if got, want := ResponseSize(w), reply.Len(); got != want {
		t.Fatalf("size = %d, want %d", got, want)
	}
	if got := ResponseSize(&sizelessWriter{}); got != 0 {
		t.Fatalf("size with no response = %d, want 0", got)
	}
}
