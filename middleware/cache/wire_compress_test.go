package cache

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
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
