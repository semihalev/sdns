package blocklist

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// wireBlocklist is a blocklist with n generated entries plus a few named
// ones: an exact block, a wildcard, and a whitelisted name under a block.
func wireBlocklist(tb testing.TB, n int) *BlockList {
	tb.Helper()
	logger := zlog.NewStructured()
	logger.SetWriter(io.Discard)
	zlog.SetDefault(logger)
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(tb.TempDir(), "bl")
	bl := New(cfg)
	keys := make([]string, 0, n+3)
	for i := range n {
		keys = append(keys, fmt.Sprintf("ads%d.tracker%d.example.", i, i%97))
	}
	keys = append(keys, "blocked.test.", "*.wild.test.", "parent.test.")
	for _, k := range keys {
		bl.set(k)
	}
	bl.w[dns.CanonicalName("safe.parent.test.")] = true
	return bl
}

func wireRequest(tb testing.TB, qname string, qtype uint16) *middleware.Request {
	tb.Helper()
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		tb.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		tb.Fatal("eligible query refused by ParseWire")
	}
	return req
}

var passOn = middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { ch.Cancel() })

func benchmarkServeWire(b *testing.B, qname string) {
	bl := wireBlocklist(b, 100000)
	req := wireRequest(b, qname, dns.TypeA)
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{bl, passOn})
	b.ReportAllocs()
	for b.Loop() {
		ch.ResetWire(w, req)
		ch.Next(context.Background())
	}
}

// BenchmarkServeWireMiss is the common case, a name the list does not hold,
// with a full list loaded.
func BenchmarkServeWireMiss(b *testing.B) { benchmarkServeWire(b, "www.example.com.") }

// BenchmarkServeWireBlocked is a blocked name, answered by the blocklist.
func BenchmarkServeWireBlocked(b *testing.B) { benchmarkServeWire(b, "ads42.tracker42.example.") }

// wireName packs presentation-free labels into wire form, so a test can
// put any byte in a label, a dot included.
func wireName(labels ...string) []byte {
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l))) //nolint:gosec // G115 - test labels are short
		out = append(out, l...)
	}
	return append(out, 0)
}

// The wire lookup and Exists agree on every name: case, escaped bytes, a
// dot inside a label, wildcard and parent blocks, a whitelisted name under
// a block, the root.
func TestExistsWireMatchesExists(t *testing.T) {
	bl := wireBlocklist(t, 50)
	bl.set(`a\.b.example.`)
	bl.set("*.deep.test.")
	for _, labels := range [][]string{
		{"blocked", "test"},
		{"BLOCKED", "Test"},
		{"sub", "blocked", "test"},
		{"x", "wild", "test"},
		{"wild", "test"},
		{"parent", "test"},
		{"safe", "parent", "test"},
		{"deeper", "safe", "parent", "test"},
		{"a.b", "example"},
		{"b", "example"},
		{"x", "a.b", "example"},
		{"c", "d", "deep", "test"},
		{"deep", "test"},
		{"ads7", "tracker7", "example"},
		{"www", "ads7", "tracker7", "example"},
		{"has space", "test"},
		{"semi;colon", "blocked", "test"},
		{"\x01\xff", "blocked", "test"},
		{"clean", "example", "com"},
		{},
	} {
		wire := wireName(labels...)
		blocked, ok := bl.existsWire(wire)
		if !ok {
			t.Fatalf("%q: no key built", labels)
		}
		pres, _ := dnsname.AppendPresentation(nil, wire)
		if want := bl.Exists(string(pres)); blocked != want {
			t.Errorf("%s: wire lookup says %v, Exists says %v", pres, blocked, want)
		}
	}
}

// A name the list does not hold goes on down the chain undecoded.
func TestServeWireMissStaysUndecoded(t *testing.T) {
	bl := wireBlocklist(t, 50)
	var undecoded, reached bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		reached, undecoded = true, ch.Request.Undecoded()
		ch.Cancel()
	})
	for _, name := range []string{"www.example.com.", "safe.parent.test.", "wild.test."} {
		req := wireRequest(t, name, dns.TypeA)
		ch := middleware.NewChain([]middleware.Handler{bl, next})
		ch.ResetWire(mock.NewWriter("udp", "192.0.2.1:40000"), req)
		ch.Next(context.Background())
		if !reached || !undecoded {
			t.Fatalf("%s: reached=%v undecoded=%v, want passed on undecoded", name, reached, undecoded)
		}
	}
}

// A blocked name is answered on the wire path exactly as on the decoded
// one, without decoding the request, for the null routes and the SOA.
func TestServeWireBlockedMatchesDecoded(t *testing.T) {
	bl := wireBlocklist(t, 50)
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"blocked.test.", dns.TypeA},
		{"Sub.Blocked.TEST.", dns.TypeAAAA},
		{"x.wild.test.", dns.TypeMX},
		{"ads3.tracker3.example.", dns.TypeTXT},
	} {
		req := wireRequest(t, tc.name, tc.qtype)
		w := mock.NewWriter("udp", "192.0.2.1:40000")
		ch := middleware.NewChain([]middleware.Handler{bl, passOn})
		ch.ResetWire(w, req)
		ch.Next(context.Background())
		if !w.Written() || !req.Undecoded() {
			t.Fatalf("%s: written=%v undecoded=%v, want answered without a decode",
				tc.name, w.Written(), req.Undecoded())
		}

		q := new(dns.Msg)
		q.SetQuestion(tc.name, tc.qtype)
		q.RecursionDesired = true
		wd := mock.NewWriter("udp", "192.0.2.1:40000")
		chd := middleware.NewChain([]middleware.Handler{bl, passOn})
		chd.Reset(wd, q)
		chd.Next(context.Background())

		got, want := w.Msg(), wd.Msg()
		got.Id, want.Id = 0, 0
		if got.String() != want.String() {
			t.Fatalf("%s %s: wire\n%v\ndecoded\n%v", tc.name, dns.TypeToString[tc.qtype], got, want)
		}
	}
}
