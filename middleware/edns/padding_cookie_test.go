package edns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// hidingWrapper wraps the writer the way dnstap does, by embedding the
// interface, which hides whatever the concrete writer offers beyond it.
type hidingWrapper struct{}

type hiddenWriter struct{ middleware.ResponseWriter }

func (hidingWrapper) Name() string { return "hiding-wrapper" }

func (hidingWrapper) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer
	ch.Writer = hiddenWriter{w}
	defer func() { ch.Writer = w }()
	ch.Next(ctx)
}

// serveOver drives req through handlers on a transport of the given proto,
// wire-born or decoded, and returns the reply and its packed length. A
// packet the strict parser declines is decoded, as the server does.
func serveOver(t *testing.T, proto string, handlers []middleware.Handler, req *dns.Msg, wireBorn bool) (*dns.Msg, int) {
	t.Helper()
	w := mock.NewWriter(proto, "192.0.2.7:40000")
	ch := middleware.NewChain(handlers)
	if wireBorn {
		raw, err := req.Pack()
		if err != nil {
			t.Fatal(err)
		}
		r := new(middleware.Request)
		if r.ParseWire(raw, time.Now(), nil) {
			ch.ResetWire(w, r)
		} else {
			m := new(dns.Msg)
			if err := m.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			ch.Reset(w, m)
		}
	} else {
		ch.Reset(w, req.Copy())
	}
	ch.Next(context.Background())
	if !w.Written() {
		t.Fatal("no reply")
	}
	resp := w.Msg()
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return resp, len(packed)
}

func withOptions(opts ...dns.EDNS0) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("pad.example.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, opts...)
	return req
}

func cookieOf(n int) *dns.EDNS0_COOKIE {
	return &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: strings.Repeat("ab", n)}
}

func hasOption(m *dns.Msg, code uint16) bool {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if o.Option() == code {
				return true
			}
		}
	}
	return false
}

// Whether a reply is padded depends on the transport, which the chain
// records when it is bound: a writer wrapper ahead of the EDNS layer, as
// dnstap installs, cannot hide it.
func TestPaddingSurvivesAWriterWrapper(t *testing.T) {
	e := truncateHarness(t)
	handlers := []middleware.Handler{hidingWrapper{}, e, &bulkResponder{answer: 1}}
	pad := &dns.EDNS0_PADDING{Padding: make([]byte, 16)}
	for _, wireBorn := range []bool{true, false} {
		resp, n := serveOver(t, "doq", handlers, withOptions(pad), wireBorn)
		if !hasOption(resp, dns.EDNS0PADDING) || n%paddingBlock != 0 {
			t.Fatalf("wire-born=%v: %d-byte reply, padded=%v; want a multiple of %d",
				wireBorn, n, hasOption(resp, dns.EDNS0PADDING), paddingBlock)
		}
	}
}

// A query carries one OPT at most, owned by the root (RFC 6891 §6.1.1):
// two, or one owned by another name, is FORMERR. The reply carries a
// single root OPT of the server's own (§7), with no server cookie, and is
// padded over an encrypted transport. Wire-born and decoded; the strict
// parser hands these packets to the decoded entry.
func TestMalformedOPTIsFormErr(t *testing.T) {
	e := truncateHarness(t)
	handlers := []middleware.Handler{e, &bulkResponder{answer: 1}}
	pad := &dns.EDNS0_PADDING{Padding: make([]byte, 16)}
	for _, tc := range []struct {
		name  string
		shape func(*dns.Msg)
		rcode int
	}{
		{"one root OPT", func(*dns.Msg) {}, dns.RcodeSuccess},
		{"two OPTs", func(m *dns.Msg) {
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			o.SetUDPSize(1232)
			o.SetVersion(1)
			m.Extra = append(m.Extra, o)
		}, dns.RcodeFormatError},
		{"an OPT owned by another name", func(m *dns.Msg) { m.IsEdns0().Hdr.Name = "example.com." }, dns.RcodeFormatError},
	} {
		for _, proto := range []string{"udp", "doq"} {
			for _, wireBorn := range []bool{true, false} {
				req := withOptions(cookieOf(8), pad)
				tc.shape(req)
				resp, n := serveOver(t, proto, handlers, req, wireBorn)
				where := tc.name + ", " + proto
				if resp.Rcode != tc.rcode {
					t.Fatalf("%s, wire-born=%v: %s, want %s", where, wireBorn,
						dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
				}
				var opts []*dns.OPT
				for _, rr := range resp.Extra {
					if o, ok := rr.(*dns.OPT); ok {
						opts = append(opts, o)
					}
				}
				if len(opts) != 1 || opts[0].Hdr.Name != "." || opts[0].Version() != 0 {
					t.Fatalf("%s, wire-born=%v: reply OPTs %v, want one root OPT of version 0", where, wireBorn, opts)
				}
				if tc.rcode != dns.RcodeFormatError {
					continue
				}
				if hasOption(resp, dns.EDNS0COOKIE) {
					t.Fatalf("%s, wire-born=%v: FORMERR carries a server cookie", where, wireBorn)
				}
				if proto == "doq" && (!hasOption(resp, dns.EDNS0PADDING) || n%paddingBlock != 0) {
					t.Fatalf("%s, wire-born=%v: %d-byte FORMERR, padded=%v; want a multiple of %d",
						where, wireBorn, n, hasOption(resp, dns.EDNS0PADDING), paddingBlock)
				}
			}
		}
	}
}

// Only the first COOKIE option counts (RFC 7873 §5.2): a malformed one
// after a valid first is ignored, and a malformed first is FORMERR
// whatever follows.
func TestOnlyTheFirstCookieCounts(t *testing.T) {
	e := truncateHarness(t)
	handlers := []middleware.Handler{e, &bulkResponder{answer: 1}}
	for _, tc := range []struct {
		name    string
		cookies []dns.EDNS0
		rcode   int
	}{
		{"valid, then 5 bytes", []dns.EDNS0{cookieOf(8), cookieOf(5)}, dns.RcodeSuccess},
		{"valid, then 12 bytes", []dns.EDNS0{cookieOf(8), cookieOf(12)}, dns.RcodeSuccess},
		{"valid, then 41 bytes", []dns.EDNS0{cookieOf(16), cookieOf(41)}, dns.RcodeSuccess},
		{"5 bytes, then valid", []dns.EDNS0{cookieOf(5), cookieOf(8)}, dns.RcodeFormatError},
	} {
		for _, wireBorn := range []bool{true, false} {
			resp, _ := serveOver(t, "udp", handlers, withOptions(tc.cookies...), wireBorn)
			if resp.Rcode != tc.rcode {
				t.Fatalf("%s, wire-born=%v: %s, want %s", tc.name, wireBorn,
					dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
		}
	}
}

// The FORMERR a malformed cookie draws is a reply like any other: padded
// when the client padded over an encrypted transport (RFC 7830 §4), and
// with no server cookie, a malformed cookie is not one to answer.
func TestMalformedCookieFormErrIsPadded(t *testing.T) {
	e := truncateHarness(t)
	handlers := []middleware.Handler{e, &bulkResponder{answer: 1}}
	pad := &dns.EDNS0_PADDING{Padding: make([]byte, 16)}
	for _, wireBorn := range []bool{true, false} {
		resp, n := serveOver(t, "doq", handlers, withOptions(cookieOf(5), pad), wireBorn)
		if resp.Rcode != dns.RcodeFormatError {
			t.Fatalf("wire-born=%v: %s, want FORMERR", wireBorn, dns.RcodeToString[resp.Rcode])
		}
		if !hasOption(resp, dns.EDNS0PADDING) || n%paddingBlock != 0 {
			t.Fatalf("wire-born=%v: %d-byte FORMERR, padded=%v; want a multiple of %d",
				wireBorn, n, hasOption(resp, dns.EDNS0PADDING), paddingBlock)
		}
		if hasOption(resp, dns.EDNS0COOKIE) {
			t.Fatalf("wire-born=%v: FORMERR answered a malformed cookie with a server cookie", wireBorn)
		}
	}
}
