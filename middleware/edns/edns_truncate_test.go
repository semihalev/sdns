package edns

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// bulkResponder writes a response with the requested section sizes, each
// record ~44 wire bytes, so tests can steer exactly which section overflows
// the client's buffer.
type bulkResponder struct {
	answer, ns, extra int
}

func (b *bulkResponder) Name() string { return "bulk" }

func (b *bulkResponder) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req := ch.Request.Msg()
	resp := new(dns.Msg)
	resp.SetReply(req)

	rr := func(i int) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   fmt.Sprintf("padding-record-%03d.example.com.", i),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(192, 0, 2, byte(i%250+1)), //nolint:gosec // G115 - bounded by the modulo
		}
	}
	for i := 0; i < b.answer; i++ {
		resp.Answer = append(resp.Answer, rr(i))
	}
	for i := 0; i < b.ns; i++ {
		resp.Ns = append(resp.Ns, rr(1000+i))
	}
	for i := 0; i < b.extra; i++ {
		resp.Extra = append(resp.Extra, rr(2000+i))
	}

	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

func truncateHarness(t *testing.T) *EDNS {
	t.Helper()
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(new(config.Config))
	return middleware.Get("edns").(*EDNS)
}

// serveBulk drives one UDP request with the given advertised size (0 =
// no EDNS) through [edns, bulkResponder] and returns the written message.
func serveBulk(t *testing.T, e *EDNS, udpSize uint16, b *bulkResponder) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion("truncate.example.com.", dns.TypeA)
	if udpSize > 0 {
		req.SetEdns0(udpSize, false)
	}

	w := mock.NewWriter("udp", "192.0.2.7:40000")
	ch := middleware.NewChain([]middleware.Handler{e, b})
	ch.Reset(w, req)
	ch.Next(context.Background())

	if !w.Written() {
		t.Fatal("no response written")
	}
	return w.Msg()
}

// TestTruncatedResponseIsMinimal pins RFC 6891 §7: the truncated response
// is the header, the question, and the OPT record, nothing else.
func TestTruncatedResponseIsMinimal(t *testing.T) {
	e := truncateHarness(t)

	m := serveBulk(t, e, 512, &bulkResponder{answer: 60})
	if !m.Truncated {
		t.Fatal("an overflowing answer must truncate")
	}
	if len(m.Answer) != 0 || len(m.Ns) != 0 {
		t.Fatalf("truncated response carries answer/authority: %d/%d", len(m.Answer), len(m.Ns))
	}
	if len(m.Extra) != 1 || m.IsEdns0() == nil {
		t.Fatalf("truncated response must carry exactly the OPT (RFC 6891 §7): extra=%v", m.Extra)
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > 512 {
		t.Fatalf("truncated response is %d bytes, larger than the advertised 512", len(packed))
	}
}

// TestTruncationDropsAnOverflowingExtra pins the defect this change fixes:
// when the additional section itself is what overflows, the truncated
// message used to keep it, TC=1 on a message still larger than the
// client's buffer.
func TestTruncationDropsAnOverflowingExtra(t *testing.T) {
	e := truncateHarness(t)

	m := serveBulk(t, e, 512, &bulkResponder{answer: 2, extra: 60})
	if !m.Truncated {
		t.Fatal("an overflowing additional section must truncate")
	}
	if len(m.Extra) != 1 || m.IsEdns0() == nil {
		t.Fatalf("extra must reduce to the OPT: %d records", len(m.Extra))
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > 512 {
		t.Fatalf("truncated response is %d bytes, larger than the advertised 512", len(packed))
	}
}

// TestTruncationWithoutEDNSCarriesNoOPT pins the other direction of
// RFC 6891 §6: a requestor without an OPT record must not receive one,
// truncation included.
func TestTruncationWithoutEDNSCarriesNoOPT(t *testing.T) {
	e := truncateHarness(t)

	m := serveBulk(t, e, 0, &bulkResponder{answer: 60})
	if !m.Truncated {
		t.Fatal("an overflowing answer must truncate for a plain client too")
	}
	if len(m.Answer) != 0 || len(m.Ns) != 0 || len(m.Extra) != 0 {
		t.Fatalf("plain client's truncated response must be header+question only: %d/%d/%d",
			len(m.Answer), len(m.Ns), len(m.Extra))
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > 512 {
		t.Fatalf("truncated response is %d bytes, larger than the 512 minimum", len(packed))
	}
}
