package as112

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func wireAS112Request(t *testing.T, qname string, qtype uint16) *middleware.Request {
	t.Helper()

	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused by ParseWire")
	}
	return req
}

// TestAS112WireLegitimateReverseStaysUndecoded pins the point: a PTR under
// a delegated (non-empty) reverse zone, a third of real traffic, passes
// through without being materialized.
func TestAS112WireLegitimateReverseStaysUndecoded(t *testing.T) {
	a := New(new(config.Config))

	var sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	for _, qname := range []string{
		"4.4.8.8.in-addr.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.8.8.8.0.6.2.ip6.arpa.",
		"HOME.ARPA.example.com.arpa.",
	} {
		sawUndecoded = false
		req := wireAS112Request(t, qname, dns.TypePTR)
		w := mock.NewWriter("udp", "192.0.2.1:40000")
		ch := middleware.NewChain([]middleware.Handler{a, next})
		ch.ResetWire(w, req)
		ch.Next(context.Background())
		if !sawUndecoded {
			t.Fatalf("%s: delegated-zone reverse lookup was decoded", qname)
		}
	}
}

// TestAS112WireHitParity drives the same empty-zone queries once wire-born
// and once message-born and requires byte-identical responses.
func TestAS112WireHitParity(t *testing.T) {
	a := New(new(config.Config))

	cases := []struct {
		qname string
		qtype uint16
	}{
		{"1.0.0.10.IN-ADDR.ARPA.", dns.TypePTR},    // below the zone: NXDOMAIN + SOA
		{"10.in-addr.arpa.", dns.TypeSOA},          // whole zone: SOA answer
		{"10.in-addr.arpa.", dns.TypeNS},           // whole zone: NS answer
		{"home.arpa.", dns.TypeA},                  // whole zone, other type: NOERROR + SOA
		{"x.168.192.in-addr.arpa.", dns.TypeDS},    // DS: parent-side match, NXDOMAIN
		{"sub.deep.127.in-addr.arpa.", dns.TypeMX}, // deep below: NXDOMAIN + SOA
	}
	for _, tc := range cases {
		req := wireAS112Request(t, tc.qname, tc.qtype)
		w := mock.NewWriter("udp", "192.0.2.2:40000")
		ch := middleware.NewChain([]middleware.Handler{a})
		ch.ResetWire(w, req)
		ch.Next(context.Background())

		if !w.Written() {
			t.Fatalf("%s/%d: wire hit not served", tc.qname, tc.qtype)
		}
		if !req.Undecoded() {
			t.Fatalf("%s/%d: wire hit materialized the request", tc.qname, tc.qtype)
		}

		q := new(dns.Msg)
		q.SetQuestion(tc.qname, tc.qtype)
		q.RecursionDesired = true
		wd := mock.NewWriter("udp", "192.0.2.2:40000")
		chd := middleware.NewChain([]middleware.Handler{a})
		chd.Reset(wd, q)
		chd.Next(context.Background())

		if !wd.Written() {
			t.Fatalf("%s/%d: decoded hit not served", tc.qname, tc.qtype)
		}

		got, want := w.Msg(), wd.Msg()
		got.Id, want.Id = 0, 0
		if got.MsgHdr != want.MsgHdr {
			t.Fatalf("%s/%d: header mismatch\nwire:    %+v\ndecoded: %+v", tc.qname, tc.qtype, got.MsgHdr, want.MsgHdr)
		}
		if !reflect.DeepEqual(got.Question, want.Question) {
			t.Fatalf("%s/%d: question mismatch: %v vs %v", tc.qname, tc.qtype, got.Question, want.Question)
		}
		if !reflect.DeepEqual(got.Answer, want.Answer) {
			t.Fatalf("%s/%d: answer mismatch: %v vs %v", tc.qname, tc.qtype, got.Answer, want.Answer)
		}
		if !reflect.DeepEqual(got.Ns, want.Ns) {
			t.Fatalf("%s/%d: authority mismatch: %v vs %v", tc.qname, tc.qtype, got.Ns, want.Ns)
		}
	}
}

// TestAS112WireDSSingleLabel: a DS query for a name whose only label is
// arpa-suffixed walks the parent, the root, and must pass through.
func TestAS112WireDSSingleLabel(t *testing.T) {
	a := New(new(config.Config))

	var passed bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		ch.Cancel()
	})

	req := wireAS112Request(t, "arpa.", dns.TypeDS)
	w := mock.NewWriter("udp", "192.0.2.3:40000")
	ch := middleware.NewChain([]middleware.Handler{a, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if !passed || w.Written() {
		t.Fatalf("DS at a single label must pass: passed=%v written=%v", passed, w.Written())
	}
}

// TestAS112WireEscapedDotNoFalseMatch: a single label whose bytes spell an
// empty zone with embedded dots must not match, the suffix walk works on
// label boundaries, not rendered dots.
func TestAS112WireEscapedDotNoFalseMatch(t *testing.T) {
	a := New(new(config.Config))

	var sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	// One label containing "10.in-addr" (dots inside), then "arpa": the
	// canonical form renders 10\.in-addr.arpa., never the zone key.
	raw := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		10, '1', '0', '.', 'i', 'n', '-', 'a', 'd', 'd', 'r',
		4, 'a', 'r', 'p', 'a',
		0,
		0x00, 0x0C, 0x00, 0x01,
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("crafted query refused by ParseWire")
	}
	w := mock.NewWriter("udp", "192.0.2.4:40000")
	ch := middleware.NewChain([]middleware.Handler{a, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if w.Written() {
		t.Fatal("escaped-dot label falsely matched an empty zone")
	}
	if !sawUndecoded {
		t.Fatal("escaped-dot miss should continue undecoded")
	}
}

// TestAS112ConfigZoneCaseNormalized: a mixed-case emptyzones entry must
// serve, the old dns.Fqdn storage left it a dead key that neither path
// could ever match.
func TestAS112ConfigZoneCaseNormalized(t *testing.T) {
	cfg := new(config.Config)
	cfg.EmptyZones = []string{"10.In-Addr.ARPA"}
	a := New(cfg)

	req := wireAS112Request(t, "1.0.0.10.in-addr.arpa.", dns.TypePTR)
	w := mock.NewWriter("udp", "192.0.2.5:40000")
	ch := middleware.NewChain([]middleware.Handler{a})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if !w.Written() || w.Rcode() != dns.RcodeNameError {
		t.Fatalf("configured mixed-case zone did not serve on wire: written=%v rcode=%v", w.Written(), w.Rcode())
	}

	// Decoded path too.
	q := new(dns.Msg)
	q.SetQuestion("1.0.0.10.in-addr.arpa.", dns.TypePTR)
	wd := mock.NewWriter("udp", "192.0.2.5:40000")
	chd := middleware.NewChain([]middleware.Handler{a})
	chd.Reset(wd, q)
	chd.Next(context.Background())
	if !wd.Written() || wd.Rcode() != dns.RcodeNameError {
		t.Fatalf("decoded path: written=%v rcode=%v", wd.Written(), wd.Rcode())
	}
}

// TestAS112WireMissAllocatesNothing pins the fast path's cost: the suffix
// probe for a delegated-zone reverse name is zero-allocation.
func TestAS112WireMissAllocatesNothing(t *testing.T) {
	a := New(new(config.Config))
	req := wireAS112Request(t, "4.4.8.8.in-addr.arpa.", dns.TypePTR)

	if n := testing.AllocsPerRun(100, func() {
		var buf [dnsname.MaxPresentationLength]byte
		var offs [dnsname.MaxLabels]int
		canon, labels, ok := dnsname.AppendCanonicalLabels(buf[:0], req.WireName(), offs[:])
		if !ok {
			t.Fatal("refused")
		}
		for i := 0; i < labels; i++ {
			if a.zones[string(canon[offs[i]:])] {
				t.Fatal("unexpected zone match")
			}
		}
	}); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}
