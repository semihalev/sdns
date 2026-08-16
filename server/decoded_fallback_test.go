package server

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// flushRecorder wraps a transport and records whether the serving path
// released staged replies through it.
type flushRecorder struct {
	middleware.Transport
	flushed bool
}

func (f *flushRecorder) FlushStaged() { f.flushed = true }

// TestDecodedFallbackFlushesStaged pins the slow lane's entry contract: a
// packet the strict parser refuses but Unpack accepts enters potentially
// slow resolution, and replies already staged on the transport — the
// previous pipelined answers on TCP, other clients' answers in the same
// UDP worker burst — must leave first, exactly as a strict
// materialization flushes them.
func TestDecodedFallbackFlushesStaged(t *testing.T) {
	s := New(&config.Config{})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	rr, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	// An answer record makes the packet strict-ineligible while Unpack
	// still accepts it.
	q.Answer = append(q.Answer, rr)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	tr := &flushRecorder{Transport: mock.NewWriter("udp", "127.0.0.1:0")}
	if !s.ServeRaw(tr, raw, time.Now()) {
		t.Fatal("decodable packet refused by the fallback")
	}
	if !tr.flushed {
		t.Fatal("decoded fallback served without flushing staged replies")
	}
}

// The rewrite must not cost embedders the library entry: a *Server
// mounted under the dns package's mux has to keep compiling.
var _ dns.Handler = (*Server)(nil)

// dnsWriterShim completes the mock transport to the library's writer
// surface, the way an embedder's writer arrives.
type dnsWriterShim struct{ middleware.Transport }

func (dnsWriterShim) TsigStatus() error           { return nil }
func (dnsWriterShim) TsigTimersOnly(bool)         {}
func (dnsWriterShim) Hijack()                     {}
func (s dnsWriterShim) WriteMsg(m *dns.Msg) error { return s.Transport.WriteMsg(m) }

func TestServeDNSCompatibilityEntries(t *testing.T) {
	s := New(&config.Config{})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	s.ServeDNS(dnsWriterShim{mock.NewWriter("udp", "127.0.0.1:0")}, q)
	s.ServeDNSContext(nil, dnsWriterShim{mock.NewWriter("udp", "127.0.0.1:0")}, q) //nolint:staticcheck // SA1012 — the nil-parent default is the compatibility contract under test
}
