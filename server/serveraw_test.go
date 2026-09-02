package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// strictTestJob is a transport that offers the strict-path job slots, so
// ServeRaw's eligible branch runs exactly as it does on the owned
// UDP/TCP jobs, with the reply captured for inspection.
type strictTestJob struct {
	remote net.UDPAddr
	wrote  []byte
	tx     [4096]byte

	req        middleware.Request
	chain      middleware.Chain
	carrier    jobCarrier
	ednsWriter edns.ResponseWriter
}

// LeaseWire mirrors the real jobs' body lease so the wire fast path runs
// exactly as it does on the owned transports.
func (j *strictTestJob) LeaseWire(capacity int) []byte {
	if capacity > len(j.tx) {
		return nil
	}
	return j.tx[:0]
}

func (j *strictTestJob) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (j *strictTestJob) RemoteAddr() net.Addr { return &j.remote }
func (j *strictTestJob) Close() error         { return nil }

func (j *strictTestJob) Write(b []byte) (int, error) {
	j.wrote = append(j.wrote[:0], b...)
	return len(b), nil
}

func (j *strictTestJob) WriteMsg(m *dns.Msg) error {
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = j.Write(packed)
	return err
}

func (j *strictTestJob) StrictSlots() (*middleware.Request, *middleware.Chain, *jobCarrier, *edns.ResponseWriter) {
	return &j.req, &j.chain, &j.carrier, &j.ednsWriter
}

// rawAnswerStub materializes (the composite-miss shape) and answers with a
// fixed A record, so the strict serve exercises the full wire→Msg
// transition end to end.
type rawAnswerStub struct{}

func (rawAnswerStub) Name() string { return "raw-answer-stub" }

func (rawAnswerStub) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	_ = ctx
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	rr, err := dns.NewRR(req.Question[0].Name + " 300 IN A 192.0.2.53")
	if err == nil {
		resp.Answer = []dns.RR{rr}
	}
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

func newRawTestServer(t *testing.T) *Server {
	t.Helper()
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
	middleware.Register("raw-answer-stub", func(*config.Config) middleware.Handler { return rawAnswerStub{} })
	cfg := &config.Config{Bind: "127.0.0.1:0"}
	middleware.Setup(cfg)
	return New(cfg)
}

func packRawQuery(t *testing.T, name string, withEDNS bool) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	if withEDNS {
		m.SetEdns0(1232, true)
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return raw
}

// TestServeRawStrictClassicDifferential sends the identical query through
// the strict ingress (job slots) and the classic decoded entry, and pins
// that the client-visible answers agree.
func TestServeRawStrictClassicDifferential(t *testing.T) {
	s := newRawTestServer(t)
	raw := packRawQuery(t, "diff.example.", true)

	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4242}}
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("eligible packet not handled")
	}
	if job.req.Raw() == nil {
		t.Fatal("strict slots unused: the eligible packet took the classic branch")
	}
	if deadline, ok := job.carrier.Deadline(); !ok || deadline.IsZero() {
		t.Fatal("job carrier deadline not set")
	}
	strict := new(dns.Msg)
	if err := strict.Unpack(job.wrote); err != nil {
		t.Fatalf("strict reply unpack: %v", err)
	}

	q := new(dns.Msg)
	if err := q.Unpack(raw); err != nil {
		t.Fatalf("query unpack: %v", err)
	}
	mw := mock.NewWriter("udp", "203.0.113.7:4242")
	s.ServeMsg(context.Background(), mw, q)
	classic := mw.Msg()
	if classic == nil {
		t.Fatal("classic entry wrote nothing")
	}

	if strict.Id != q.Id || classic.Id != q.Id {
		t.Fatalf("reply IDs diverge: strict %d classic %d want %d", strict.Id, classic.Id, q.Id)
	}
	if strict.Rcode != classic.Rcode {
		t.Fatalf("rcode diverges: strict %d classic %d", strict.Rcode, classic.Rcode)
	}
	if len(strict.Answer) != 1 || len(classic.Answer) != 1 ||
		strict.Answer[0].String() != classic.Answer[0].String() {
		t.Fatalf("answers diverge:\n strict:  %v\n classic: %v", strict.Answer, classic.Answer)
	}
	strictOPT, classicOPT := strict.IsEdns0(), classic.IsEdns0()
	if (strictOPT == nil) != (classicOPT == nil) {
		t.Fatalf("OPT presence diverges: strict %v classic %v", strictOPT, classicOPT)
	}
	if strictOPT != nil &&
		(strictOPT.UDPSize() != classicOPT.UDPSize() || strictOPT.Do() != classicOPT.Do()) {
		t.Fatalf("OPT diverges: strict size=%d do=%v classic size=%d do=%v",
			strictOPT.UDPSize(), strictOPT.Do(), classicOPT.UDPSize(), classicOPT.Do())
	}
}

// TestServeRawJobReuse pins that recycled job slots serve back-to-back
// requests cleanly: the second parse resets the request and the carrier.
func TestServeRawJobReuse(t *testing.T) {
	s := newRawTestServer(t)
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 4242}}

	for i, name := range []string{"first.example.", "second.example."} {
		raw := packRawQuery(t, name, true)
		if !s.ServeRaw(job, raw, time.Now()) {
			t.Fatalf("serve %d not handled", i)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(job.wrote); err != nil {
			t.Fatalf("serve %d reply unpack: %v", i, err)
		}
		if len(resp.Question) != 1 || resp.Question[0].Name != name {
			t.Fatalf("serve %d answered %v, want %s", i, resp.Question, name)
		}
	}
}

// TestServeRawClassicFallback pins the ineligible branch: a shape the
// strict parser refuses still gets the ordinary decoded serve, here the
// two-question packet, which the shared entry guard answers with FORMERR.
func TestServeRawClassicFallback(t *testing.T) {
	s := newRawTestServer(t)
	m := new(dns.Msg)
	m.SetQuestion("multi.example.", dns.TypeA)
	m.Question = append(m.Question, dns.Question{
		Name: "second.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4242}}
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("decodable packet must be handled")
	}
	if job.req.Raw() != nil {
		t.Fatal("ineligible packet must not enter the strict slots")
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(job.wrote); err != nil {
		t.Fatalf("reply unpack: %v", err)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode %d, want FORMERR", resp.Rcode)
	}
}

// TestServeRawUndecodable pins the false return: an accepted header hiding
// an undecodable body is the engine's FORMERR, not the server's.
func TestServeRawUndecodable(t *testing.T) {
	s := newRawTestServer(t)
	// A header claiming one question followed by a compression pointer
	// loop: ParseWire refuses (pointer), Unpack errors (loop).
	raw := []byte{
		0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
	}
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 4242}}
	if s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("undecodable body must report false for the engine reject")
	}
	if len(job.wrote) != 0 {
		t.Fatal("server must not write for an undecodable body")
	}
}
