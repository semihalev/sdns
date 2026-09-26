package ddr

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// addressQueryer answers the target's A and AAAA lookups with n records
// each, TTL 300, and lets a test bound each lookup's lease and see what the
// lookup was handed.
type addressQueryer struct {
	n      int
	bound  map[uint16]time.Duration // lease each lookup's answer carries
	onCall func(ctx context.Context, qtype uint16)
}

func (q *addressQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	qtype := req.Question[0].Qtype
	if q.onCall != nil {
		q.onCall(ctx, qtype)
	}
	if d, ok := q.bound[qtype]; ok {
		middleware.ResponseMetaFrom(ctx).BoundLease(lease.Until(time.Now().Add(d)))
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := range q.n {
		hdr := dns.RR_Header{Name: req.Question[0].Name, Rrtype: qtype, Class: dns.ClassINET, Ttl: 300}
		if qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, byte(i+1))})
		} else {
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))})
		}
	}
	return resp, nil
}

// ask runs a discovery query through the real edns layer and DDR, as a
// client on proto with the given EDNS buffer (0 for no EDNS).
func ask(t *testing.T, d *DDR, proto string, bufsize uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(discovery, dns.TypeSVCB)
	if bufsize > 0 {
		req.SetEdns0(bufsize, false)
	}
	w := mock.NewWriter(proto, "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{edns.New(enabled(":443", ":853", "")), d})
	ch.Reset(w, req)
	ch.Next(context.Background())
	if !w.Written() {
		t.Fatal("no response")
	}
	return w.Msg()
}

func count(rrs []dns.RR, rrtype uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype {
			n++
		}
	}
	return n
}

// The addresses are optional (RFC 2181 §9): an RRset that does not fit the
// client's buffer is left out whole, and the discovery answer never gives
// way to it. Over a stream every set is carried.
func TestAdditionalFitsTheClientBuffer(t *testing.T) {
	d := New(enabled(":443", ":853", ""))
	d.SetQueryer(&addressQueryer{n: 48})

	for _, c := range []struct {
		name    string
		proto   string
		bufsize uint16
		limit   int
		a, aaaa int
	}{
		{"no EDNS", "udp", 0, dns.MinMsgSize, 0, 0},
		{"EDNS 512", "udp", 512, dns.MinMsgSize, 0, 0},
		{"EDNS 1232", "udp", 1232, 1232, 48, 0},
		{"TCP", "tcp", 1232, dns.MaxMsgSize, 48, 48},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := ask(t, d, c.proto, c.bufsize)
			if resp.Truncated || len(resp.Answer) != 2 {
				t.Fatalf("TC=%v with %d answers, want the discovery answer whole", resp.Truncated, len(resp.Answer))
			}
			if got := resp.Len(); got > c.limit {
				t.Fatalf("response is %d bytes, over the client's %d", got, c.limit)
			}
			if a, aaaa := count(resp.Extra, dns.TypeA), count(resp.Extra, dns.TypeAAAA); a != c.a || aaaa != c.aaaa {
				t.Fatalf("additional carries %d A and %d AAAA, want %d and %d, whole sets only", a, aaaa, c.a, c.aaaa)
			}
			if c.bufsize > 0 && resp.IsEdns0() == nil {
				t.Fatal("no OPT in the response")
			}
		})
	}

	// Small sets fit a plain 512-byte answer.
	d.SetQueryer(&addressQueryer{n: 2})
	if resp := ask(t, d, "udp", 0); count(resp.Extra, dns.TypeA) != 2 || count(resp.Extra, dns.TypeAAAA) != 2 {
		t.Fatalf("two of each did not fit 512 bytes: %v", resp.Extra)
	}
}

// Each address is published no longer than its own lookup's lease allows,
// and a lookup whose lease has run out contributes nothing.
func TestAdditionalTTLsKeepTheirLease(t *testing.T) {
	d := New(enabled(":443", ":853", ""))
	d.SetQueryer(&addressQueryer{n: 1, bound: map[uint16]time.Duration{
		dns.TypeA:    2 * time.Second,
		dns.TypeAAAA: -time.Second,
	}})
	resp, _, _ := serve(t, d, discovery, dns.TypeSVCB, dns.ClassINET, false)
	if len(resp.Extra) != 1 || resp.Extra[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("additional %v, want the A alone, the AAAA's lease is spent", resp.Extra)
	}
	if ttl := resp.Extra[0].Header().Ttl; ttl > 2 {
		t.Fatalf("A published with TTL %d, over its 2-second lease", ttl)
	}
}

// The A and AAAA lookups are separate questions with separate lineages: the
// AAAA is not handed the bound the A lookup found, and the discovery
// request is not bounded by either. Both are optional work.
func TestAdditionalLookupsAreIndependent(t *testing.T) {
	d := New(enabled(":443", ":853", ""))
	var aaaaCut middleware.Lease
	bestEffort := map[uint16]bool{}
	d.SetQueryer(&addressQueryer{
		n:     1,
		bound: map[uint16]time.Duration{dns.TypeA: 2 * time.Second},
		onCall: func(ctx context.Context, qtype uint16) {
			bestEffort[qtype] = middleware.IsBestEffortRecursionWork(ctx)
			if qtype == dns.TypeAAAA {
				aaaaCut = middleware.ResponseMetaFrom(ctx).Cut()
			}
		},
	})

	req := new(dns.Msg)
	req.SetQuestion(discovery, dns.TypeSVCB)
	meta := new(middleware.ResponseMeta)
	ctx := middleware.WithResponseMeta(context.Background(), meta)
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{d})
	ch.Reset(w, req)
	ch.Next(ctx)

	if !aaaaCut.IsZero() {
		t.Fatalf("the AAAA lookup started under the A lookup's bound %+v", aaaaCut)
	}
	if !meta.Cut().IsZero() {
		t.Fatalf("the discovery request took a lookup's bound %+v", meta.Cut())
	}
	if !bestEffort[dns.TypeA] || !bestEffort[dns.TypeAAAA] {
		t.Fatalf("lookups charged as required work: %v", bestEffort)
	}
	if count(w.Msg().Extra, dns.TypeAAAA) != 1 || count(w.Msg().Extra, dns.TypeA) != 1 {
		t.Fatalf("additional %v, want one A and one AAAA", w.Msg().Extra)
	}
}

// The budget holds at every edge: across record counts and buffer sizes,
// with the OPT carrying a server cookie and an NSID, no response truncates,
// none exceeds the client's buffer, and each family is carried whole or not
// at all.
func TestAdditionalBudgetEdges(t *testing.T) {
	cfg := enabled(":443", ":853", "")
	cfg.NSID = "resolver-1.example"
	cfg.CookieSecret = "cookie-secret"
	layer := edns.New(cfg)
	for n := 1; n <= 60; n++ {
		d := New(cfg)
		d.SetQueryer(&addressQueryer{n: n})
		for bufsize := uint16(512); bufsize <= 1232; bufsize += 24 {
			req := new(dns.Msg)
			req.SetQuestion(discovery, dns.TypeSVCB)
			req.SetEdns0(bufsize, false)
			opt := req.IsEdns0()
			opt.Option = append(opt.Option,
				&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"},
				&dns.EDNS0_NSID{Code: dns.EDNS0NSID})
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{layer, d})
			ch.Reset(w, req)
			ch.Next(context.Background())
			resp := w.Msg()
			if resp.Truncated || len(resp.Answer) != 2 {
				t.Fatalf("n=%d bufsize=%d: TC=%v with %d answers", n, bufsize, resp.Truncated, len(resp.Answer))
			}
			if resp.Len() > int(bufsize) {
				t.Fatalf("n=%d bufsize=%d: %d bytes", n, bufsize, resp.Len())
			}
			for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if got := count(resp.Extra, rrtype); got != 0 && got != n {
					t.Fatalf("n=%d bufsize=%d: %d of %d %s records", n, bufsize, got, n, dns.TypeToString[rrtype])
				}
			}
			var hasCookie, hasNSID bool
			for _, o := range resp.IsEdns0().Option {
				switch o.(type) {
				case *dns.EDNS0_COOKIE:
					hasCookie = true
				case *dns.EDNS0_NSID:
					hasNSID = true
				}
			}
			if !hasCookie || !hasNSID {
				t.Fatalf("n=%d bufsize=%d: OPT without the cookie or NSID the budget reserved for", n, bufsize)
			}
		}
	}
}

// A set's TTL is read against its lease when the answer is composed, not
// when its own lookup returned: time spent on the other lookup comes off
// it. An A whose 1.5-second lease has run below a second by then is left
// out, not published with a TTL of one.
func TestAdditionalTTLsAtComposition(t *testing.T) {
	d := New(enabled(":443", ":853", ""))
	d.SetQueryer(&addressQueryer{
		n:     1,
		bound: map[uint16]time.Duration{dns.TypeA: 1500 * time.Millisecond},
		onCall: func(_ context.Context, qtype uint16) {
			if qtype == dns.TypeAAAA {
				time.Sleep(700 * time.Millisecond)
			}
		},
	})
	resp, _, _ := serve(t, d, discovery, dns.TypeSVCB, dns.ClassINET, false)
	if n := count(resp.Extra, dns.TypeA); n != 0 {
		t.Fatalf("A published with %d record(s) after its lease fell below a second: %v", n, resp.Extra)
	}
	if count(resp.Extra, dns.TypeAAAA) != 1 {
		t.Fatalf("additional %v, want the AAAA", resp.Extra)
	}
}
