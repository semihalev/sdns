package accesslog

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// countingWriter is the transport beneath the chain. It records the bytes it
// receives and, crucially, never decodes them — so a log line that reports
// the right size can only have got it without a decode.
type countingWriter struct {
	*mock.Writer
	wrote int
}

func (w *countingWriter) Write(b []byte) (int, error) {
	w.wrote = len(b)
	return len(b), nil
}

func (w *countingWriter) WriteMsg(m *dns.Msg) error {
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	w.wrote = len(packed)
	return w.Writer.WriteMsg(m)
}

// TestLogsWireSizeThroughEDNSWrapper pins the size an access log records
// against the bytes that actually left the server, with the EDNS wrapper in
// place exactly as the standard chain arranges it. The wrapper embeds the
// narrow writer interface, so unless it forwards the optional size accessor
// the log falls back to decoding the response — the very work the byte path
// exists to avoid, and a measurement that overstates compressed replies.
func TestLogsWireSizeThroughEDNSWrapper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	cfg := new(config.Config)
	cfg.AccessLog = path
	logger := New(cfg)
	if logger.logFile == nil {
		t.Fatalf("access log %s was not opened", path)
	}
	// Release the handle before TempDir's cleanup runs: Windows refuses to
	// remove a file that is still open, which would fail the test for a
	// reason that has nothing to do with what it asserts.
	t.Cleanup(func() { _ = logger.logFile.Close() })

	e := edns.New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("www.a-repeated-and-fairly-long-name.example.com.", dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(1232, false)

	// A compressible answer: its packed form is materially shorter than the
	// length a decoded message would report.
	answer := new(dns.Msg)
	answer.SetReply(req)
	for i := range 8 {
		rr, err := dns.NewRR("www.a-repeated-and-fairly-long-name.example.com. 300 IN A 192.0.2." +
			strconv.Itoa(i+1))
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		answer.Answer = append(answer.Answer, rr)
	}

	// Respond the way a cache hit does: hand the chain packed bytes. This is
	// the only route where the fallback is both wrong and expensive — a
	// message written as an object still carries its Compress flag, so
	// measuring it happens to agree.
	responder := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		writer, ok := ch.Writer.(middleware.WireWriter)
		if !ok {
			t.Fatal("chain does not offer the byte path")
		}
		capability, ready := writer.WireReady()
		if !ready {
			t.Fatal("byte path refused")
		}
		answer.Compress = true
		packed, err := answer.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		body := make([]byte, len(packed), len(packed)+capability.Reserve)
		copy(body, packed)
		if err := writer.WriteWire(body, middleware.WireInfo{Rcode: dns.RcodeSuccess}); err != nil {
			t.Fatalf("write wire: %v", err)
		}
		ch.Cancel()
	})

	transport := &countingWriter{Writer: mock.NewWriter("udp", "192.0.2.9:40000")}
	ch := middleware.NewChain([]middleware.Handler{e, logger, responder})
	ch.Reset(transport, req)
	ch.Next(context.Background())

	if transport.wrote == 0 {
		t.Fatal("nothing reached the transport")
	}

	contents, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(contents)))
	if len(fields) == 0 {
		t.Fatal("no access log line written")
	}
	logged, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		t.Fatalf("last field %q is not a size: %v", fields[len(fields)-1], err)
	}

	if logged != transport.wrote {
		t.Fatalf("logged size %d, but %d bytes were written; the wrapper is not "+
			"forwarding the response size and the log measured a decoded message",
			logged, transport.wrote)
	}
}
