package cache

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// captureSink is a mock transport that leases bodies from its own buffer and
// keeps a copy of the last one written.
type captureSink struct {
	*mock.Writer
	buf  [4096]byte
	last []byte
}

func (s *captureSink) LeaseWire(capacity int) []byte {
	if capacity > len(s.buf) {
		return nil
	}
	return s.buf[:0]
}

func (s *captureSink) Write(b []byte) (int, error) {
	s.last = append(s.last[:0], b...)
	return len(b), nil
}

// A chain composed on the byte path writes every owner that repeats a name
// already in the reply, the question or the target before it, as a pointer,
// and spells each record as stored, the client's spelling of the question
// included.
func TestComposedChainIsNameCompressed(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	cname := func(owner, target string) dns.RR {
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: target,
		}
	}
	const (
		alias = "www.example.test."
		edge  = "edge.cdn.example.net."
		host  = "a1.g.cdn.example.net."
	)
	c.store.SetFromResponseWithCut(seamResponse(alias, cname(alias, edge)), false, lease.Lease{})
	c.store.SetFromResponseWithCut(seamResponse(edge, cname(edge, host)), false, lease.Lease{})
	var hosts []dns.RR
	for i := range 4 {
		a := seamA(host)
		a.A = []byte{192, 0, 2, byte(10 + i)}
		hosts = append(hosts, a)
	}
	c.store.SetFromResponseWithCut(seamResponse(host, hosts...), false, lease.Lease{})

	for _, qname := range []string{alias, "WwW.ExAmPlE.TeSt."} {
		t.Run(qname, func(t *testing.T) {
			req, _ := wireTestRequest(t, qname, dns.TypeA, false)
			w := &captureSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
			ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				ch.Cancel()
			})})
			before := wireChaseServed.Value()
			ch.ResetWire(w, req)
			ch.AllowDirectPack()
			ch.Next(context.Background())
			if wireChaseServed.Value() == before || w.last == nil {
				t.Fatal("the chain was not composed on the byte path")
			}

			got := new(dns.Msg)
			if err := got.Unpack(w.last); err != nil {
				t.Fatalf("composed reply does not unpack: %v", err)
			}
			if len(got.Answer) != 6 {
				t.Fatalf("answer %v, want the two aliases and four addresses", got.Answer)
			}
			if got.Answer[0].Header().Name != qname {
				t.Fatalf("first owner %q, want the client's spelling %q", got.Answer[0].Header().Name, qname)
			}
			for i, want := range []string{edge, host} {
				if target := got.Answer[i].(*dns.CNAME).Target; target != want {
					t.Fatalf("CNAME %d target %q, want %q as stored", i, target, want)
				}
			}

			// Every owner repeats a name already in the reply, the question
			// or the target before it, and goes out as a two-octet pointer.
			q, _ := wire.ParseQuestion(w.last, wire.HeaderLen)
			off := q.End
			for i := range got.Answer {
				rr, ok := wire.ParseRR(w.last, off)
				if !ok {
					t.Fatalf("record %d does not parse", i)
				}
				if w.last[rr.NameOff]&0xC0 != 0xC0 {
					t.Fatalf("record %d owner %q written in full, want a pointer", i, got.Answer[i].Header().Name)
				}
				off = rr.End
			}
		})
	}
}

// A cached alias chain says the same thing on the byte path and the Msg
// path: the alias's own EDE, or else the nearest hop's when it is the
// reason that hop's records are insecure (an unusable DS). A nearer hop's
// EDE of another kind is that hop's own and hides the ones behind it. The
// byte path composes the chain without allocating, EDE included.
func TestComposedChainCarriesTheTargetsInsecureReason(t *testing.T) {
	const none = -1
	unsupported := int(dns.ExtendedErrorCodeUnsupportedDSDigestType)
	algorithm := int(dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm)
	filtered := int(dns.ExtendedErrorCodeFiltered)
	other := int(dns.ExtendedErrorCodeOther)
	for _, tc := range []struct {
		name string
		hops []int // each hop's EDE, alias first, address last; none for no EDE
		want int
	}{
		{"the target's reason", []int{none, unsupported}, unsupported},
		{"the alias's own EDE first", []int{filtered, unsupported}, filtered},
		{"through a middle alias without an EDE", []int{none, none, unsupported}, unsupported},
		{"a middle alias's own EDE hides the target's", []int{none, filtered, unsupported}, none},
		{"a middle alias's EDE 0 hides the target's", []int{none, other, unsupported}, none},
		{"the nearest reason", []int{none, algorithm, unsupported}, algorithm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 600})
			defer c.Stop()
			terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				ch.Cancel()
			})
			c.SetQueryer(&internalQueryer{handlers: []middleware.Handler{c, terminal}})
			e := edns.New(&config.Config{})

			names := make([]string, len(tc.hops))
			for i := range names {
				names[i] = fmt.Sprintf("hop%d.reason.test.", i)
			}
			for i, code := range tc.hops {
				var rr dns.RR = seamA(names[i])
				if i < len(names)-1 {
					rr = &dns.CNAME{
						Hdr:    dns.RR_Header{Name: names[i], Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: names[i+1],
					}
				}
				resp := seamResponse(names[i], rr)
				if code != none {
					resp.SetEdns0(1232, true)
					resp.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_EDE{InfoCode: uint16(code)}} //nolint:gosec // test codes
				}
				c.store.SetFromResponseWithCut(resp, false, lease.Lease{})
			}
			check := func(path string, got *dns.Msg) {
				t.Helper()
				if len(got.Answer) != len(tc.hops) {
					t.Fatalf("%s: answer %v, want the whole chain", path, got.Answer)
				}
				ede := dnsutil.GetEDE(got)
				switch {
				case tc.want == none && ede != nil:
					t.Fatalf("%s: EDE %v, want none", path, ede)
				case tc.want != none && (ede == nil || int(ede.InfoCode) != tc.want):
					t.Fatalf("%s: EDE %v, want %d", path, ede, tc.want)
				}
			}

			// Byte path.
			req, _ := wireTestRequest(t, names[0], dns.TypeA, false)
			w := &captureSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
			ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
			var meta middleware.ResponseMeta
			ctx := middleware.WithResponseMeta(context.Background(), &meta)
			serve := func() {
				ch.ResetWire(w, req)
				ch.AllowDirectPack()
				ch.Next(ctx)
			}
			before := wireChaseServed.Value()
			serve()
			if wireChaseServed.Value() == before || w.last == nil {
				t.Fatal("the chain was not composed on the byte path")
			}
			got := new(dns.Msg)
			if err := got.Unpack(w.last); err != nil {
				t.Fatalf("composed reply does not unpack: %v", err)
			}
			check("byte path", got)
			if allocs := testing.AllocsPerRun(100, serve); allocs != 0 {
				t.Fatalf("a composed chain allocated %.2f objects per serve", allocs)
			}

			// Msg path: the same question decoded, the hops chased through
			// the cache.
			q := new(dns.Msg)
			q.SetQuestion(names[0], dns.TypeA)
			q.SetEdns0(1232, false)
			mw := mock.NewWriter("udp", "192.0.2.9:53000")
			mch := middleware.NewChain([]middleware.Handler{e, c, terminal})
			mch.Reset(mw, q)
			mch.Next(context.Background())
			if !mw.Written() {
				t.Fatal("Msg path: no reply")
			}
			check("Msg path", mw.Msg())
		})
	}
}

// Composing a chain still allocates nothing.
func TestComposedChainAllocatesNothing(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()
	const alias, host = "alias.alloc.test.", "host.alloc.example.net."
	c.store.SetFromResponseWithCut(seamResponse(alias, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: alias, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: host,
	}), false, lease.Lease{})
	c.store.SetFromResponseWithCut(seamResponse(host, seamA(host)), false, lease.Lease{})

	req, _ := wireTestRequest(t, alias, dns.TypeA, false)
	w := &leaseSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
	ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		ch.Cancel()
	})})
	// The server always carries a ResponseMeta; without one the chain
	// creates it, which is the harness's allocation, not the serve's.
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	before := wireChaseServed.Value()
	allocs := testing.AllocsPerRun(200, func() {
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(ctx)
	})
	if wireChaseServed.Value() == before {
		t.Fatal("the chain never served bytes; the pin measured nothing")
	}
	if allocs != 0 {
		t.Fatalf("a composed chain allocated %.2f objects per serve; the contract is none", allocs)
	}
}
