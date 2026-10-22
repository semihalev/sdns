package cache

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// storeAnswer caches rr as the answer to its own name and type.
func storeAnswer(t *testing.T, c *Cache, rr string) {
	t.Helper()
	r := makeRR(rr)
	q := new(dns.Msg)
	q.SetQuestion(r.Header().Name, r.Header().Rrtype)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = []dns.RR{r}
	c.store.SetFromResponse(resp, false, time.Time{})
}

// wantTruncated fails unless w was answered with an empty truncated reply,
// what an answer over its limit gets over UDP.
func wantTruncated(t *testing.T, w *mock.Writer, what string) {
	t.Helper()
	if !w.Written() {
		t.Fatalf("%s wrote nothing; want a truncated reply", what)
	}
	m := w.Msg()
	if !m.Truncated || len(m.Answer)+len(m.Ns) != 0 || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s = TC %v, %d answers, rcode %s; want an empty truncated reply",
			what, m.Truncated, len(m.Answer), dns.RcodeToString[m.Rcode])
	}
}

// askWire sends one wire-born query for name and qtype from addr over
// proto through the cache alone, and returns the writer it answered on.
func askWire(t *testing.T, c *Cache, proto, addr, name string, qtype uint16) *mock.Writer {
	t.Helper()
	req, _ := wireTestRequest(t, name, qtype, false)
	w := mock.NewWriter(proto, addr)
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	return w
}

// A flood on one answer must not silence another. The limit used to be
// held in a fixed pool of shared buckets that answers hashed into, so an
// answer drained by a flood took every answer sharing its bucket down
// with it. These two are such a pair: a flood of root DNSKEY queries left
// this A record unanswerable on every transport.
func TestAFloodedAnswerLimitsNoOther(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 100
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	storeAnswer(t, c, cfg.RootKeys[1])
	storeAnswer(t, c, "api.cloudflare.com. 300 IN A 192.0.2.53")

	for range 300 {
		askWire(t, c, "udp", "203.0.113.9:53000", ".", dns.TypeDNSKEY)
	}

	w := askWire(t, c, "udp", "198.51.100.7:53000", "api.cloudflare.com.", dns.TypeA)
	if !w.Written() {
		t.Fatal("api.cloudflare.com A went unanswered while the root DNSKEY " +
			"answer was flooded: the two share a limit")
	}
	if m := w.Msg(); m.Truncated || answerA(m) != "192.0.2.53" {
		t.Fatalf("api.cloudflare.com A answered %v, want the cached address", m)
	}
}

// A datagram over its answer's rate is told to retry over TCP: an empty
// truncated reply carrying the question, no larger than the query, so it
// reflects nothing worth spoofing for, while a real client still gets
// its answer.
func TestAnswerOverItsRateIsTruncatedOverUDP(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 2
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	storeAnswer(t, c, "limit.example. 300 IN A 192.0.2.1")

	var truncated int
	for i := range 10 {
		w := askWire(t, c, "udp", "203.0.113.9:53000", "limit.example.", dns.TypeA)
		if !w.Written() {
			t.Fatalf("query %d over the limit was dropped without a reply", i)
		}
		m := w.Msg()
		if !m.Truncated {
			continue
		}
		truncated++
		if len(m.Answer)+len(m.Ns) != 0 || m.Rcode != dns.RcodeSuccess {
			t.Fatalf("truncated reply carries records or rcode %s: %v", dns.RcodeToString[m.Rcode], m)
		}
		if len(m.Question) != 1 || m.Question[0].Name != "limit.example." || m.Question[0].Qtype != dns.TypeA {
			t.Fatalf("truncated reply does not echo the question: %v", m.Question)
		}
	}
	if truncated < 7 {
		t.Fatalf("%d of 10 queries truncated at a limit of 2, want at least 7", truncated)
	}
}

// A client that sends cookies does not need TCP to get past the limit: the
// truncated reply carries the server cookie like any other answer, and the
// retry that returns it has proved its address and is answered over UDP.
func TestTruncatedReplyHandsOutTheCookieThatProvesTheRetry(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	cfg.CookieSecret = "6c6f6f6b61686172646c6f6f6b6168617264"
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()
	storeAnswer(t, c, "cookie-retry.example. 300 IN A 192.0.2.7")
	e := edns.New(cfg)

	ask := func(cookieHex string) *dns.Msg {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion("cookie-retry.example.", dns.TypeA)
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookieHex}}
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("eligible query refused")
		}
		w := &captureSink{Writer: mock.NewWriter("udp", "203.0.113.9:53000")}
		ch := middleware.NewChain([]middleware.Handler{e, c})
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(context.Background())
		if w.last == nil {
			t.Fatal("query went unanswered")
		}
		m := new(dns.Msg)
		if err := m.Unpack(w.last); err != nil {
			t.Fatal(err)
		}
		return m
	}
	serverCookie := func(m *dns.Msg) string {
		if opt := m.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if c, ok := o.(*dns.EDNS0_COOKIE); ok && len(c.Cookie) > 16 {
					return c.Cookie
				}
			}
		}
		return ""
	}

	const client = "0102030405060708"
	if m := ask(client); m.Truncated || answerA(m) != "192.0.2.7" {
		t.Fatalf("first query = %v, want the answer", m)
	}
	tc := ask(client)
	if !tc.Truncated {
		t.Fatalf("second query = %v, want truncated at a limit of 1", tc)
	}
	full := serverCookie(tc)
	if full == "" {
		t.Fatalf("truncated reply carries no server cookie: %v", tc)
	}
	if m := ask(full); m.Truncated || answerA(m) != "192.0.2.7" {
		t.Fatalf("retry with the server cookie = %v, want the answer over UDP", m)
	}
}

// A chain composed on the byte path is charged to its alias after the
// chain's body has been leased, so its refusal must release that lease
// before the truncated reply takes one of its own: the reply is the
// truncated one, through the edns layer like any other.
func TestComposedChainOverItsLimitIsTruncated(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	cfg.CookieSecret = "6c6f6f6b61686172646c6f6f6b6168617264"
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()
	e := edns.New(cfg)

	const alias, host = "www.chain-limit.test.", "edge.chain-limit.test."
	c.store.SetFromResponseWithCut(seamResponse(alias, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: alias, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: host,
	}), false, lease.Lease{})
	c.store.SetFromResponseWithCut(seamResponse(host, seamA(host)), false, lease.Lease{})

	ask := func() *dns.Msg {
		t.Helper()
		req, _ := wireTestRequest(t, alias, dns.TypeA, false)
		w := &captureSink{Writer: mock.NewWriter("udp", "203.0.113.9:53000")}
		ch := middleware.NewChain([]middleware.Handler{e, c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			ch.Cancel()
		})})
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(context.Background())
		if w.last == nil {
			t.Fatal("query went unanswered")
		}
		m := new(dns.Msg)
		if err := m.Unpack(w.last); err != nil {
			t.Fatal(err)
		}
		return m
	}

	before := wireChaseServed.Value()
	if m := ask(); m.Truncated || len(m.Answer) != 2 || wireChaseServed.Value() == before {
		t.Fatalf("first query = %v, want the chain composed on the byte path", m)
	}
	m := ask()
	if !m.Truncated || len(m.Answer) != 0 || len(m.Question) != 1 || m.Question[0].Name != alias {
		t.Fatalf("second query = %v, want an empty truncated reply to the alias", m)
	}
	if m.IsEdns0() == nil {
		t.Fatal("truncated reply carries no OPT; the edns layer never saw it")
	}
}

// A token the old entry granted was spent on the same question: the entry
// a refresh publishes must not grant it again, and the old one, closed
// while the refresh publishes, grants nothing in that window.
func TestRefreshKeepsTokensSpentWhileItPublishes(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("publish.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = []dns.RR{makeRR("publish.example. 300 IN A 192.0.2.1")}
	old := NewCacheEntry(resp, time.Minute, 1)
	fresh := NewCacheEntry(resp, time.Minute, 1)

	now := limitNow()
	if !old.allowAnswer(now) {
		t.Fatal("the old entry had no token to spend")
	}
	carryLimit(fresh, old, func() bool {
		// An hour on, an open bucket would have refilled.
		if old.allowAnswer(now + int64(time.Hour)) {
			t.Fatal("the entry being replaced granted while the refresh published")
		}
		return true
	})
	if fresh.allowAnswer(now) {
		t.Fatal("the refreshed entry granted again the token its predecessor " +
			"spent while the refresh was publishing")
	}
}

// A query that looked the old entry up before the refresh published can
// still be charging it after the refresh is done. The question has one
// bucket, so it and a query on the new entry must not both be answered.
func TestRefreshLeavesNoTokenOnTheEntryItReplaced(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("retired.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = []dns.RR{makeRR("retired.example. 300 IN A 192.0.2.1")}
	old := NewCacheEntry(resp, time.Minute, 1)
	fresh := NewCacheEntry(resp, time.Minute, 1)

	// Queries charge both entries the moment the store write lands, while
	// the refresh has yet to take the old bucket over, and again once it
	// has. Every charge is at one instant, so one token is all there is.
	now := limitNow()
	granted := 0
	charge := func() {
		for _, e := range []*CacheEntry{old, fresh} {
			if e.allowAnswer(now) {
				granted++
			}
		}
	}
	carryLimit(fresh, old, func() bool { charge(); return true })
	charge()
	if granted != 1 {
		t.Fatalf("ratelimit 1 answered %d times across a refresh, want 1", granted)
	}

	// A refresh that loses its swap leaves the entry it found serving.
	kept := NewCacheEntry(resp, time.Minute, 1)
	lost := NewCacheEntry(resp, time.Minute, 1)
	carryLimit(lost, kept, func() bool { return false })
	if !kept.allowAnswer(now) {
		t.Fatal("a refresh that never published took the current entry's token")
	}
}

// Writers storing the same question at once each replace what the one
// before left, and queries charge whatever is current between them. At one
// instant and ratelimit 1, all of them together get one answer: no write
// may hand the question a bucket that another write's entry already spent.
func TestConcurrentWritesShareOneBucket(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("writers.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = []dns.RR{makeRR("writers.example. 300 IN A 192.0.2.1")}
	key := CacheKey{Question: q.Question[0]}.Hash()

	// Half the rounds start from an empty key, where the first writers
	// race to store the question's first entry.
	const writers = 8
	for round := range 400 {
		pc := NewPositiveCache(1024, time.Second, time.Hour, &CacheMetrics{})
		if round%2 == 0 {
			pc.Set(key, NewCacheEntry(resp, time.Minute, 1))
		}
		now := limitNow()
		var granted atomic.Int32
		var wg sync.WaitGroup
		for range writers {
			wg.Go(func() {
				pc.Set(key, NewCacheEntry(resp, time.Minute, 1))
				if e, ok := pc.Get(key); ok && e.allowAnswer(now) {
					granted.Add(1)
				}
			})
		}
		wg.Wait()
		if e, ok := pc.Get(key); ok && e.allowAnswer(now) {
			granted.Add(1)
		}
		if n := granted.Load(); n > 1 {
			t.Fatalf("ratelimit 1 answered %d times across concurrent writes, want 1", n)
		}
		pc.cache.Stop()
	}
}

// The cache key folds ASCII case, so a refresh that comes back spelled
// differently is the same question: it keeps the bucket, and a query whose
// byte path paid on the old spelling is not charged again on the new.
func TestRefreshUnderAnotherCaseIsTheSameQuestion(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	store := func(name string) *CacheEntry {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{makeRR(name + " 300 IN A 192.0.2.1")}
		c.store.SetFromResponse(resp, false, time.Time{})
		entry, ok := c.store.LookupByKey(CacheKey{Question: q.Question[0]}.Hash())
		if !ok {
			t.Fatal("entry not stored")
		}
		return entry
	}

	first := store("case.example.")
	if !first.allowAnswer(limitNow()) {
		t.Fatal("the first entry had no token to spend")
	}
	spent := first.limit.tat.Load()
	second := store("CASE.EXAMPLE.")
	if second == first {
		t.Fatal("the store reused the entry; this test needs a replacement")
	}
	if !second.sameQuestion(first) {
		t.Fatal("a refresh spelled in another case is not the same question")
	}
	if second.limit.tat.Load() != spent {
		t.Fatal("a refresh spelled in another case started from a full bucket")
	}

	q := new(dns.Msg)
	q.SetQuestion("case.example.", dns.TypeA)
	w := mock.NewWriter("udp", "203.0.113.9:53000")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.Reset(w, q)
	c.handleCacheHit(context.Background(), ch, second, CacheKey{Question: q.Question[0]}.Hash(), netip.Prefix{}, first)
	if !w.Written() || w.Msg().Truncated {
		t.Fatal("a question that had already paid was charged again because the " +
			"entry answering it is spelled in another case")
	}
}

// A truncated reply must not grow past the query that drew it: optional
// options a client can ask for, NSID among them, are left off it, so a
// long configured NSID gives a flood nothing to amplify.
func TestTruncatedReplyIsNoLargerThanTheQuery(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	cfg.NSID = strings.Repeat("n", 1000)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()
	storeAnswer(t, c, "nsid.example. 300 IN A 192.0.2.1")
	e := edns.New(cfg)

	q := new(dns.Msg)
	q.SetQuestion("nsid.example.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}}
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []struct {
		name string
		wire bool
	}{{"byte path", true}, {"message path", false}} {
		t.Run(path.name, func(t *testing.T) {
			var last []byte
			ask := func() *dns.Msg {
				req := new(middleware.Request)
				if !req.ParseWire(raw, time.Now(), nil) {
					t.Fatal("eligible query refused")
				}
				sink := &captureSink{Writer: mock.NewWriter("udp", "203.0.113.9:53000")}
				ch := middleware.NewChain([]middleware.Handler{e, c})
				ch.ResetWire(sink, req)
				if path.wire {
					ch.AllowDirectPack()
				}
				ch.Next(context.Background())
				last = sink.last
				if path.wire {
					m := new(dns.Msg)
					if err := m.Unpack(last); err != nil {
						t.Fatal(err)
					}
					return m
				}
				m := sink.Msg()
				if packed, err := m.Pack(); err == nil {
					last = packed
				}
				return m
			}
			ask()
			m := ask()
			if !m.Truncated {
				t.Fatalf("second query = %v, want truncated at a limit of 1", m)
			}
			if len(last) > len(raw) {
				t.Fatalf("truncated reply is %d bytes for a %d byte query: %v", len(last), len(raw), m)
			}
		})
	}
}

// The limit exists against reflection, and a source that has proved its
// address cannot be reflecting: a TCP client completed a handshake, a
// loopback one cannot be spoofed from outside. Neither is limited, so the
// TCP retry a truncated reply asks for is always answered.
func TestProvedSourcesAreNotAnswerLimited(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 2
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	storeAnswer(t, c, "proved.example. 300 IN A 192.0.2.2")

	for _, src := range []struct{ proto, addr string }{
		{"tcp", "203.0.113.9:53000"},
		{"udp", "127.0.0.1:53000"},
	} {
		for i := range 10 {
			w := askWire(t, c, src.proto, src.addr, "proved.example.", dns.TypeA)
			if !w.Written() || w.Msg().Truncated || answerA(w.Msg()) != "192.0.2.2" {
				t.Fatalf("%s query %d from %s was limited: written=%v", src.proto, i, src.addr, w.Written())
			}
		}
	}
}
