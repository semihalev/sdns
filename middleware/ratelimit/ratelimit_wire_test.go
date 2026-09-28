package ratelimit

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

const wireTestCookie = "aabbccdd11223344" // 8 raw bytes in the hex form miekg packs

func wireRequest(t *testing.T, cookie string) *middleware.Request {
	t.Helper()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, true)
	if cookie != "" {
		opt := q.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: cookie,
		})
	}
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

// TestRateLimitWireStaysUndecoded pins the fast path: a wire-born request
// with no cookie, and one with a cookie, both pass the limiter without
// being materialized.
func TestRateLimitWireStaysUndecoded(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 100, CookieSecret: "secret"})

	var passed, sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	for _, cookie := range []string{"", wireTestCookie} {
		passed, sawUndecoded = false, false
		req := wireRequest(t, cookie)
		w := mock.NewWriter("udp", "10.0.0.1:0")
		ch := middleware.NewChain([]middleware.Handler{r, next})
		ch.ResetWire(w, req)
		ch.Next(context.Background())
		if !passed || !sawUndecoded {
			t.Fatalf("cookie %q: passed=%v undecoded=%v, want both true", cookie, passed, sawUndecoded)
		}
	}
}

// TestRateLimitWireOverLimit checks the plain limiter still bites on the
// wire path: with a rate of 1, the second cookieless query is dropped
// without a reply.
func TestRateLimitWireOverLimit(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 1, CookieSecret: "secret"})

	var passes int
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passes++
		ch.Cancel()
	})

	for i := 0; i < 3; i++ {
		req := wireRequest(t, "")
		w := mock.NewWriter("udp", "10.0.0.4:0")
		ch := middleware.NewChain([]middleware.Handler{r, next})
		ch.ResetWire(w, req)
		ch.Next(context.Background())
		if w.Written() {
			t.Fatal("over-limit drop must not write a reply")
		}
	}
	if passes >= 3 {
		t.Fatalf("passes = %d, want the limiter to drop some of 3", passes)
	}
}

// answerer stands in for the resolver: every query it sees is answered.
type answerer struct{}

func (answerer) Name() string { return "answerer" }

func (answerer) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	_, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	_ = ch.Writer.WriteMsg(m)
	ch.Cancel()
}

// provedWriter is a DoH transport that says whether its handshake proved
// the source, as the server's DoH writer does.
type provedWriter struct {
	*mock.Writer
	proved bool
}

func (w provedWriter) SourceVerified() bool { return w.proved }

// pipeline is the production order of the two layers a cookie passes
// through, with the resolver's place taken by answerer.
type pipeline struct {
	t        *testing.T
	handlers []middleware.Handler
	wireBorn bool
}

func newPipeline(t *testing.T, rate int, wireBorn bool) *pipeline {
	cfg := &config.Config{ClientRateLimit: rate, CookieSecret: "00112233445566778899aabbccddeeff"}
	return &pipeline{t: t, handlers: []middleware.Handler{New(cfg), edns.New(cfg), answerer{}}, wireBorn: wireBorn}
}

// reply is one query's outcome: dropped, or its rcode and COOKIE option.
type reply struct {
	dropped bool
	rcode   int
	cookie  string
	options int
}

// ask sends one query from addr over w's transport, carrying cookie (hex,
// none when empty) and whatever shape adds.
func (p *pipeline) ask(w middleware.Transport, cookie string, shape func(*dns.Msg)) reply {
	p.t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(1232, false)
	if cookie != "" {
		opt := q.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie})
	}
	if shape != nil {
		shape(q)
	}
	ch := middleware.NewChain(p.handlers)
	req := new(middleware.Request)
	raw, err := q.Pack()
	if err != nil {
		p.t.Fatal(err)
	}
	if p.wireBorn && req.ParseWire(raw, time.Now(), nil) {
		ch.ResetWire(w, req)
	} else {
		m := new(dns.Msg)
		if err := m.Unpack(raw); err != nil {
			p.t.Fatal(err)
		}
		ch.Reset(w, m)
	}
	ch.Next(context.Background())

	var mw *mock.Writer
	switch v := w.(type) {
	case *mock.Writer:
		mw = v
	case provedWriter:
		mw = v.Writer
	case addrWriter:
		mw = v.Writer
	}
	if !mw.Written() {
		return reply{dropped: true}
	}
	out := reply{rcode: mw.Rcode()}
	if opt := mw.Msg().IsEdns0(); opt != nil {
		out.options = len(opt.Option)
		for _, o := range opt.Option {
			if c, ok := o.(*dns.EDNS0_COOKIE); ok {
				out.cookie = c.Cookie
			}
		}
	}
	return out
}

func udp(addr string) *mock.Writer { return mock.NewWriter("udp", addr+":5353") }

func bothBirths(t *testing.T, f func(t *testing.T, wireBorn bool)) {
	for _, wireBorn := range []bool{true, false} {
		t.Run(map[bool]string{true: "wire-born", false: "decoded"}[wireBorn], func(t *testing.T) {
			f(t, wireBorn)
		})
	}
}

// Clients behind one address hold cookies of their own: each is answered,
// never challenged, with a server cookie for its own client cookie, and a
// cookie one of them brings back verifies whatever the others sent in
// between. A limiter that stored one cookie per address answered them in
// turn with BADCOOKIE.
func TestCookiesBehindOneAddressDoNotCollide(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 1000, wireBorn)
		clients := []string{"1111111111111111", "2222222222222222", "3333333333333333"}
		learned := map[string]string{}
		for range 3 {
			for _, c := range clients {
				sent := c
				if l, ok := learned[c]; ok {
					sent = l
				}
				got := p.ask(udp("198.51.100.9"), sent, nil)
				if got.dropped || got.rcode != dns.RcodeSuccess {
					t.Fatalf("client %s: dropped=%v rcode=%s, want an answer", c, got.dropped, dns.RcodeToString[got.rcode])
				}
				if len(got.cookie) != 48 || got.cookie[:16] != c {
					t.Fatalf("client %s: reply cookie %q, want 24 bytes for its own client cookie", c, got.cookie)
				}
				if l, ok := learned[c]; ok && got.cookie != l {
					t.Fatalf("client %s: a young valid cookie came back as %q, want it echoed as %q", c, got.cookie, l)
				}
				learned[c] = got.cookie
			}
		}
	})
}

// Over its quota, an unproved client that sent a cookie is challenged:
// BADCOOKIE with a server cookie and nothing of its own options, within a
// budget, past which it is dropped like a cookieless query. The server
// cookie it was handed proves it on the retry, which draws from its proved
// bucket.
func TestOverQuotaChallenge(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 1, wireBorn)
		const client = "4444444444444444"
		pad := func(m *dns.Msg) {
			opt := m.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 8)})
		}

		if got := p.ask(udp("198.51.100.10"), client, nil); got.rcode != dns.RcodeSuccess || got.dropped {
			t.Fatalf("within quota: dropped=%v rcode=%s", got.dropped, dns.RcodeToString[got.rcode])
		}
		if got := p.ask(udp("198.51.100.10"), "", nil); !got.dropped {
			t.Fatal("over quota without a cookie: answered, want dropped")
		}
		challenge := p.ask(udp("198.51.100.10"), client, pad)
		if challenge.dropped || challenge.rcode != dns.RcodeBadCookie {
			t.Fatalf("over quota with a cookie: dropped=%v rcode=%s, want BADCOOKIE",
				challenge.dropped, dns.RcodeToString[challenge.rcode])
		}
		if len(challenge.cookie) != 48 || challenge.cookie[:16] != client || challenge.options != 1 {
			t.Fatalf("BADCOOKIE carries cookie %q among %d options, want only a server cookie for %s",
				challenge.cookie, challenge.options, client)
		}
		if got := p.ask(udp("198.51.100.10"), client, nil); !got.dropped {
			t.Fatalf("past the challenge budget: rcode=%s, want dropped", dns.RcodeToString[got.rcode])
		}
		if got := p.ask(udp("198.51.100.10"), challenge.cookie, nil); got.dropped || got.rcode != dns.RcodeSuccess {
			t.Fatalf("retry with the handed cookie: dropped=%v rcode=%s, want an answer",
				got.dropped, dns.RcodeToString[got.rcode])
		}
		if got := p.ask(udp("198.51.100.10"), challenge.cookie, nil); !got.dropped {
			t.Fatalf("the proved bucket over its quota: rcode=%s, want dropped", dns.RcodeToString[got.rcode])
		}
	})
}

// A flood of cookieless queries in a client's name spends only the
// unproved bucket: its queries with a valid server cookie, and over a
// transport whose handshake proved it, still draw from its own.
func TestSpoofedFloodCannotSpendAProvedQuota(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 2, wireBorn)
		first := p.ask(udp("198.51.100.11"), "5555555555555555", nil)
		if first.rcode != dns.RcodeSuccess || len(first.cookie) != 48 {
			t.Fatalf("first query: rcode=%s cookie=%q", dns.RcodeToString[first.rcode], first.cookie)
		}
		for range 50 {
			p.ask(udp("198.51.100.11"), "", nil)
		}
		if got := p.ask(udp("198.51.100.11"), first.cookie, nil); got.dropped || got.rcode != dns.RcodeSuccess {
			t.Fatalf("valid cookie after the flood: dropped=%v rcode=%s, want an answer", got.dropped, dns.RcodeToString[got.rcode])
		}
		if got := p.ask(mock.NewWriter("tcp", "198.51.100.11:5353"), "", nil); got.dropped || got.rcode != dns.RcodeSuccess {
			t.Fatalf("TCP after the flood: dropped=%v rcode=%s, want an answer", got.dropped, dns.RcodeToString[got.rcode])
		}
	})
}

// A request over DoH3 early data arrives before the handshake proves its
// source, and draws from the unproved bucket; once the transport says the
// handshake completed, from the proved one.
func TestDoHEarlyDataIsNotProved(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 1, wireBorn)
		p.ask(udp("198.51.100.12"), "", nil) // spends the unproved bucket
		early := provedWriter{mock.NewWriter("doh", "198.51.100.12:443"), false}
		if got := p.ask(early, "", nil); !got.dropped {
			t.Fatal("early data drew from the proved bucket")
		}
		done := provedWriter{mock.NewWriter("doh", "198.51.100.12:443"), true}
		if got := p.ask(done, "", nil); got.dropped || got.rcode != dns.RcodeSuccess {
			t.Fatalf("a completed handshake: dropped=%v rcode=%s, want an answer", got.dropped, dns.RcodeToString[got.rcode])
		}
	})
}

// A challenged query that is malformed draws its own error: BADVERS for an
// EDNS version this server does not speak. A malformed cookie is not one to
// challenge, and over quota it is dropped.
func TestChallengeYieldsToProtocolErrors(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 1, wireBorn)
		p.ask(udp("198.51.100.13"), "", nil) // spends the unproved bucket
		v1 := func(m *dns.Msg) { m.IsEdns0().SetVersion(1) }
		if got := p.ask(udp("198.51.100.13"), "6666666666666666", v1); got.dropped || got.rcode != dns.RcodeBadVers {
			t.Fatalf("EDNS version 1: dropped=%v rcode=%s, want BADVERS", got.dropped, dns.RcodeToString[got.rcode])
		}
		if got := p.ask(udp("198.51.100.14"), "", nil); got.dropped {
			t.Fatal("a fresh address was dropped")
		}
		if got := p.ask(udp("198.51.100.14"), "66666666666666", nil); !got.dropped {
			t.Fatalf("a malformed cookie over quota: rcode=%s, want dropped", dns.RcodeToString[got.rcode])
		}
	})
}

// With the limiter off, cookies are still answered: a client cookie and a
// server cookie that does not verify both get an answer and a fresh server
// cookie, never BADCOOKIE.
func TestCookiesWithTheLimiterOff(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 0, wireBorn)
		for _, sent := range []string{
			"7777777777777777",
			"7777777777777777" + "01000000" + "00000000" + "0000000000000000",
		} {
			got := p.ask(udp("198.51.100.15"), sent, nil)
			if got.dropped || got.rcode != dns.RcodeSuccess {
				t.Fatalf("cookie %s: dropped=%v rcode=%s, want an answer", sent, got.dropped, dns.RcodeToString[got.rcode])
			}
			if len(got.cookie) != 48 || got.cookie[:16] != sent[:16] || got.cookie == sent {
				t.Fatalf("cookie %s: reply cookie %q, want a fresh server cookie", sent, got.cookie)
			}
			if _, err := hex.DecodeString(got.cookie); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// Proved buckets live in a store of their own: however many addresses an
// unproved flood brings, a proved client's spent bucket is not evicted and
// refilled.
func TestProvedEntriesSurviveAnAddressFlood(t *testing.T) {
	p := newPipeline(t, 1, true)
	tcp := func() *mock.Writer { return mock.NewWriter("tcp", "198.51.100.16:5353") }
	if got := p.ask(tcp(), "", nil); got.dropped {
		t.Fatal("first TCP query dropped")
	}
	r := p.handlers[0].(*RateLimit)
	for i := range cacheSize + 10 {
		r.getLimiter(net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)))
	}
	if n := r.verified.Len(); n != 1 {
		t.Fatalf("the proved store holds %d entries after the flood, want only the proved client's", n)
	}
	if got := p.ask(tcp(), "", nil); !got.dropped {
		t.Fatal("the proved bucket was evicted by unproved addresses and refilled")
	}
}

// addrWriter hands the chain the client address in a form of its own
// choosing, as transports do: 4 bytes from one, 16 from another.
type addrWriter struct {
	provedWriter
	addr net.Addr
}

func (w addrWriter) RemoteAddr() net.Addr { return w.addr }

// One IPv4 client is one client however its transport spells the address:
// its proved bucket, spent by a cookie over UDP where the address arrived
// as 4 bytes, is the one a DoH query draws from where it arrived as 16.
func TestAnAddressIsOneClientInEitherForm(t *testing.T) {
	bothBirths(t, func(t *testing.T, wireBorn bool) {
		p := newPipeline(t, 2, wireBorn)
		v4 := net.IPv4(198, 51, 100, 17).To4()
		v16 := net.IPv4(198, 51, 100, 17).To16()
		overUDP := func() addrWriter {
			return addrWriter{provedWriter{mock.NewWriter("udp", "198.51.100.17:5353"), false}, &net.UDPAddr{IP: v4, Port: 5353}}
		}
		overDoH := addrWriter{provedWriter{mock.NewWriter("doh", "198.51.100.17:443"), true}, &net.TCPAddr{IP: v16, Port: 443}}

		first := p.ask(overUDP(), "8888888888888888", nil)
		if first.dropped || len(first.cookie) != 48 {
			t.Fatalf("first query: dropped=%v cookie=%q", first.dropped, first.cookie)
		}
		for range 2 {
			if got := p.ask(overUDP(), first.cookie, nil); got.dropped {
				t.Fatal("a valid cookie within the proved quota was dropped")
			}
		}
		if got := p.ask(overDoH, "", nil); !got.dropped {
			t.Fatal("the same address in its 16-byte form drew from a second proved bucket")
		}
	})
}
