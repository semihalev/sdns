package hostsfile

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func wireHostsfile(t *testing.T) *Hostsfile {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 probe.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(&config.Config{HostsFile: path})
	if h == nil {
		t.Fatal("hostsfile failed to load")
	}
	return h
}

func wireHostsRequest(t *testing.T, qname string, qtype uint16) *middleware.Request {
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

// TestHostsfileWireMissStaysUndecoded pins the common case: a wire-born
// query that misses the hosts database continues down the chain without
// ever being materialized.
func TestHostsfileWireMissStaysUndecoded(t *testing.T) {
	h := wireHostsfile(t)

	var sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	req := wireHostsRequest(t, "other.test.", dns.TypeA)
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{h, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())

	if !sawUndecoded {
		t.Fatal("a hosts miss must not decode the request")
	}
}

// TestHostsfileWireHitParity serves the same query once wire-born and once
// message-born and requires identical responses; the wire serve must also
// leave the request undecoded. A hit is built from parsed scalars.
func TestHostsfileWireHitParity(t *testing.T) {
	h := wireHostsfile(t)

	req := wireHostsRequest(t, "probe.test.", dns.TypeA)
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{h})
	ch.ResetWire(w, req)
	ch.Next(context.Background())

	if !w.Written() {
		t.Fatal("wire hit not served")
	}
	if !req.Undecoded() {
		t.Fatal("wire hit materialized the request")
	}

	q := new(dns.Msg)
	q.SetQuestion("probe.test.", dns.TypeA)
	q.RecursionDesired = true
	wd := mock.NewWriter("udp", "192.0.2.1:40000")
	chd := middleware.NewChain([]middleware.Handler{h})
	chd.Reset(wd, q)
	chd.Next(context.Background())

	if !wd.Written() {
		t.Fatal("decoded hit not served")
	}

	got, want := w.Msg(), wd.Msg()
	if got.Id != req.ID() {
		t.Fatalf("wire reply Id = %d, want the request's %d", got.Id, req.ID())
	}
	// The two requests carry different random Ids; equalize before the
	// whole-header comparison.
	got.Id, want.Id = 0, 0
	if got.MsgHdr != want.MsgHdr {
		t.Fatalf("header mismatch: wire %+v, decoded %+v", got.MsgHdr, want.MsgHdr)
	}
	if !reflect.DeepEqual(got.Question, want.Question) {
		t.Fatalf("question mismatch: wire %v, decoded %v", got.Question, want.Question)
	}
	if !reflect.DeepEqual(got.Answer, want.Answer) {
		t.Fatalf("answer mismatch: wire %v, decoded %v", got.Answer, want.Answer)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answer))
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("answer = %v, want probe.test A 127.0.0.1", got.Answer[0])
	}
}

// TestHostsfileWireLookupAllocatesNothing pins the point of the wire
// branch: deriving the key and asking the database costs zero heap
// allocations, hit and miss alike.
func TestHostsfileWireLookupAllocatesNothing(t *testing.T) {
	h := wireHostsfile(t)
	db := h.getDB()

	hit := wireHostsRequest(t, "Probe.Test.", dns.TypeA)
	miss := wireHostsRequest(t, "other.example.", dns.TypeA)

	if n := testing.AllocsPerRun(100, func() {
		var buf [dnsname.MaxPresentationLength]byte
		for _, req := range []*middleware.Request{hit, miss} {
			key, ok := dnsname.AppendFoldedKey(buf[:0], req.WireName())
			if !ok {
				t.Fatal("refused")
			}
			lookupKeyed(h, db, key, dns.TypeA)
		}
	}); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}

// TestHostsfileWireNODATA: a known host queried for a type the hosts
// database cannot answer gets an empty NOERROR, matching the decoded body.
func TestHostsfileWireNODATA(t *testing.T) {
	h := wireHostsfile(t)

	req := wireHostsRequest(t, "probe.test.", dns.TypeMX)
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{h})
	ch.ResetWire(w, req)
	ch.Next(context.Background())

	if !w.Written() {
		t.Fatal("NODATA for a known host must be served")
	}
	if w.Rcode() != dns.RcodeSuccess || len(w.Msg().Answer) != 0 {
		t.Fatalf("rcode = %v answers = %d, want NOERROR with no answers", w.Rcode(), len(w.Msg().Answer))
	}
	if !req.Undecoded() {
		t.Fatal("NODATA serve materialized the request")
	}
}

// A name the hosts file holds is answered from it alone: an address
// family it lists nothing for is NODATA, where it used to be asked
// upstream. An exact name is not completed from a wildcard, a wildcard
// name takes each family from whichever matching line lists one, and a
// name listed on two lines, once as an alias, keeps both families.
// Wire-born and decoded.
func TestHostsfileMissingFamilyIsNODATA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	hosts := "127.0.0.1 localhost\n" +
		"::1 ip6-localhost localhost\n" +
		"127.0.0.1 v4only.test\n" +
		"::1 v6only.test\n" +
		"10.0.0.1 exact.wild.test\n" +
		"10.0.0.2 *.wild.test\n" +
		"fd00::2 *.wild.test\n" +
		"10.0.0.3 *.v4wild.test\n"
	if err := os.WriteFile(path, []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(&config.Config{HostsFile: path})
	if h == nil {
		t.Fatal("hostsfile failed to load")
	}

	const upstream = "upstream"
	for _, tc := range []struct {
		qname string
		qtype uint16
		want  string // an address, "NODATA", or upstream
	}{
		{"v4only.test.", dns.TypeAAAA, "NODATA"},
		{"v6only.test.", dns.TypeA, "NODATA"},
		{"v4only.test.", dns.TypeA, "127.0.0.1"},
		{"localhost.", dns.TypeA, "127.0.0.1"},
		{"localhost.", dns.TypeAAAA, "::1"},
		{"localhost.", dns.TypeCNAME, "ip6-localhost."},
		{"exact.wild.test.", dns.TypeAAAA, "NODATA"},
		{"x.wild.test.", dns.TypeA, "10.0.0.2"},
		{"x.wild.test.", dns.TypeAAAA, "fd00::2"},
		{"x.v4wild.test.", dns.TypeAAAA, "NODATA"},
		{"other.test.", dns.TypeAAAA, upstream},
	} {
		for _, wireBorn := range []bool{true, false} {
			passed := false
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				passed = true
				ch.Cancel()
			})
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{h, next})
			if wireBorn {
				ch.ResetWire(w, wireHostsRequest(t, tc.qname, tc.qtype))
			} else {
				q := new(dns.Msg)
				q.SetQuestion(tc.qname, tc.qtype)
				ch.Reset(w, q)
			}
			ch.Next(context.Background())

			got := upstream
			if !passed {
				if !w.Written() || w.Rcode() != dns.RcodeSuccess {
					t.Fatalf("%s %s, wire-born=%v: no NOERROR reply", tc.qname, dns.TypeToString[tc.qtype], wireBorn)
				}
				switch ans := w.Msg().Answer; {
				case len(ans) == 0:
					got = "NODATA"
				case len(ans) > 1:
					got = fmt.Sprint(ans)
				default:
					switch rr := ans[0].(type) {
					case *dns.A:
						got = rr.A.String()
					case *dns.AAAA:
						got = rr.AAAA.String()
					case *dns.CNAME:
						got = rr.Target
					default:
						got = rr.String()
					}
				}
			}
			if got != tc.want {
				t.Fatalf("%s %s, wire-born=%v: %s, want %s", tc.qname, dns.TypeToString[tc.qtype], wireBorn, got, tc.want)
			}
		}
	}
}
