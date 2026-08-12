package cache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// transportWriter models the real DNS transport: WriteMsg packs the message
// before handing bytes to the socket (miekg/dns server.go), while Write
// sends the caller's bytes untouched. mock.Writer does the opposite —
// storing the pointer and unpacking raw writes — which would credit the Msg
// path with a free Pack and charge the byte path an unpack it never does in
// production.
type transportWriter struct {
	*mock.Writer
	packed int
}

func (w *transportWriter) WriteMsg(m *dns.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	w.packed = len(data)
	return nil
}

func (w *transportWriter) Write(b []byte) (int, error) {
	w.packed = len(b)
	return len(b), nil
}

// msgPathShim hides the WireWriter implementation of everything beneath it,
// forcing the byte path's chain-support probe to fail so the same request
// can be served through the historical Msg path for comparison.
type msgPathShim struct {
	middleware.ResponseWriter
}

func wireFastTestPipeline(tb testing.TB, entryMsg *dns.Msg) (*Cache, *edns.EDNS) {
	tb.Helper()
	cfg := makeTestConfig()
	cfg.CookieSecret = "6c6f6f6b61686172646c6f6f6b6168617264"
	// Per-entry rate limiters live in a process-wide map keyed by
	// (limit, key), so a benchmark's millions of hits would exhaust one
	// and turn later iterations into silent cancels. Serving is what these
	// cases measure; rate limiting has its own coverage.
	cfg.RateLimit = 0
	c := New(cfg)
	tb.Cleanup(c.Stop)
	e := edns.New(cfg)

	key := CacheKey{Question: entryMsg.Question[0], CD: entryMsg.CheckingDisabled}.Hash()
	c.store.SetFromResponseWithKey(key, entryMsg, time.Time{}, 0)
	return c, e
}

// serveThrough runs req through edns→cache exactly as the live chain wires
// them, and returns the final response the client would see.
func serveThrough(
	tb testing.TB,
	c *Cache,
	e *edns.EDNS,
	req *dns.Msg,
	forceMsgPath bool,
) *dns.Msg {
	tb.Helper()
	writer := mock.NewWriter("udp", "198.51.100.77:40000")
	terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		tb.Fatal("request missed the cache and reached the terminal handler")
	})
	ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
	ch.Reset(writer, req.Copy())
	if forceMsgPath {
		ch.Writer = &msgPathShim{ResponseWriter: ch.Writer}
	}
	ch.Next(context.Background())
	if !writer.Written() {
		tb.Fatal("no response written")
	}
	return writer.Msg()
}

// normalize prepares a response for semantic comparison: TTLs are zeroed
// (the two paths may compute remaining TTL a second apart) and RR sets are
// compared through their canonical string forms.
func normalize(tb testing.TB, msg *dns.Msg) (header string, rrs []string, options []string) {
	tb.Helper()
	var sb strings.Builder
	sb.WriteString(dns.RcodeToString[msg.Rcode])
	for _, flag := range []struct {
		name string
		on   bool
	}{
		{"QR", msg.Response}, {"AA", msg.Authoritative},
		{"AD", msg.AuthenticatedData}, {"TC", msg.Truncated},
		{"RD", msg.RecursionDesired}, {"RA", msg.RecursionAvailable},
		{"CD", msg.CheckingDisabled},
	} {
		if flag.on {
			sb.WriteString(" " + flag.name)
		}
	}

	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			clone := dns.Copy(rr)
			clone.Header().Ttl = 0
			rrs = append(rrs, strings.ToLower(clone.String()))
		}
	}
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			options = append(options, option.String())
		}
		sb.WriteString(" DO=")
		if opt.Do() {
			sb.WriteString("1")
		} else {
			sb.WriteString("0")
		}
	}
	return sb.String(), rrs, options
}

func assertEquivalent(t *testing.T, name string, wirePath, msgPath *dns.Msg) {
	t.Helper()
	wh, wr, wo := normalize(t, wirePath)
	mh, mr, mo := normalize(t, msgPath)
	if wh != mh {
		t.Fatalf("%s: header/flags diverged\n wire: %s\n  msg: %s", name, wh, mh)
	}
	if len(wr) != len(mr) {
		t.Fatalf("%s: record counts diverged: wire=%d msg=%d\n wire: %v\n  msg: %v",
			name, len(wr), len(mr), wr, mr)
	}
	for i := range wr {
		if wr[i] != mr[i] {
			t.Fatalf("%s: record %d diverged\n wire: %s\n  msg: %s", name, i, wr[i], mr[i])
		}
	}
	if len(wo) != len(mo) {
		t.Fatalf("%s: OPT options diverged: wire=%v msg=%v", name, wo, mo)
	}
	for i := range wo {
		if wo[i] != mo[i] {
			t.Fatalf("%s: OPT option %d diverged\n wire: %s\n  msg: %s", name, i, wo[i], mo[i])
		}
	}
}

func wireFastEntryAA(tb testing.TB, qname string, qtype uint16) *dns.Msg {
	msg := wireFastEntry(tb, qname, qtype, false)
	// A forwarder can hand back an authoritative answer; the cache stores
	// the header as received.
	msg.Authoritative = true
	return msg
}

func wireFastEntry(tb testing.TB, qname string, qtype uint16, dnssec bool) *dns.Msg {
	tb.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.RecursionAvailable = true
	msg.AuthenticatedData = true
	msg.Answer = append(msg.Answer,
		makeRR(qname+" 300 IN A 192.0.2.10"),
		makeRR(qname+" 300 IN A 192.0.2.11"),
	)
	if dnssec {
		msg.Answer = append(msg.Answer, makeRR(
			qname+" 300 IN RRSIG A 13 3 300 20370101000000 20260101000000 7 example.com. ZmFrZXNpZ25hdHVyZQ=="))
	}
	return msg
}

// TestWireFastPathEquivalence pins the whole point of the byte path: for
// every client profile it serves, the bytes must decode to the same
// response the Msg path produces — flags, records, and per-client OPT
// contents (server cookie included) alike.
func TestWireFastPathEquivalence(t *testing.T) {
	type client struct {
		name    string
		shape   func(req *dns.Msg)
		dnssec  bool // entry carries RRSIG
		expWire bool // byte path expected to serve
	}
	cases := []client{
		{"do1_dnssec", func(r *dns.Msg) { r.SetEdns0(1232, true) }, true, true},
		{"do0_plain", func(r *dns.Msg) { r.SetEdns0(1232, false) }, false, true},
		// A client without DO is served the stripped body, so the byte path
		// covers it too — and assertEquivalent is what proves the stripped
		// body carries exactly what the Msg path would have sent, DNSSEC
		// records removed and everything else identical.
		{"do0_dnssec_stripped", func(r *dns.Msg) { r.SetEdns0(1232, false) }, true, true},
		{"noedns", func(r *dns.Msg) {}, false, true},
		{"cd1", func(r *dns.Msg) { r.SetEdns0(1232, true); r.CheckingDisabled = true }, true, true},
		// entryShape marks cases that must prime the CD=true cache partition
		{"cookie", func(r *dns.Msg) {
			r.SetEdns0(1232, true)
			opt := r.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
				Code: dns.EDNS0COOKIE, Cookie: "aabbccdd11223344",
			})
		}, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const qname = "host.example.com."
			entry := wireFastEntry(t, qname, dns.TypeA, tc.dnssec)
			if tc.name == "cd1" {
				// A CD=1 client reads the CD=true cache partition; prime it
				// with an AD-bearing entry so both paths must clear AD.
				entry.CheckingDisabled = true
			}
			c, e := wireFastTestPipeline(t, entry)

			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeA)
			req.Id = 4242
			req.RecursionDesired = true
			tc.shape(req)

			servedBefore := wireFastServed.Value()
			viaWire := serveThrough(t, c, e, req, false)
			viaMsg := serveThrough(t, c, e, req, true)
			servedDelta := wireFastServed.Value() - servedBefore

			if tc.expWire && servedDelta != 1 {
				t.Fatalf("expected the byte path to serve exactly once, served %d", servedDelta)
			}
			if !tc.expWire && servedDelta != 0 {
				t.Fatalf("byte path served %d times for an ineligible profile", servedDelta)
			}
			assertEquivalent(t, tc.name, viaWire, viaMsg)
		})
	}
}

// TestWireFastPathCaseEcho pins the 0x20-style question echo: the byte path
// must return the client's exact question spelling, and the answer content
// must remain the stored records.
func TestWireFastPathCaseEcho(t *testing.T) {
	entry := wireFastEntry(t, "case.example.com.", dns.TypeA, false)
	c, e := wireFastTestPipeline(t, entry)

	req := new(dns.Msg)
	req.SetQuestion("CaSe.ExAmPle.CoM.", dns.TypeA)
	req.Id = 7
	req.RecursionDesired = true
	req.SetEdns0(1232, true)

	resp := serveThrough(t, c, e, req, false)
	if got := resp.Question[0].Name; got != "CaSe.ExAmPle.CoM." {
		t.Fatalf("question echo = %q, want the client spelling", got)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("answers = %d, want 2", len(resp.Answer))
	}
}

// TestWireFastPathTruncationFallsBack pins the late-fallback contract: a
// UDP client whose advertised size the reply exceeds must receive the Msg
// path's truncated response, written exactly once.
func TestWireFastPathTruncationFallsBack(t *testing.T) {
	const qname = "big.example.com."
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.RecursionAvailable = true
	for i := range 40 {
		msg.Answer = append(msg.Answer, makeRR(
			qname+" 300 IN TXT \""+strings.Repeat("x", 60)+"\""))
		_ = i
	}
	c, e := wireFastTestPipeline(t, msg)

	client := new(dns.Msg)
	client.SetQuestion(qname, dns.TypeA)
	client.Id = 9
	client.RecursionDesired = true
	client.SetEdns0(512, false)

	servedBefore := wireFastServed.Value()
	fallbackBefore := wireFastFallback.Value()
	resp := serveThrough(t, c, e, client, false)
	if wireFastServed.Value() != servedBefore {
		t.Fatal("an oversized UDP reply must not be served as bytes")
	}
	if wireFastFallback.Value() != fallbackBefore {
		t.Fatal("the size ceiling must be caught by the preflight, " +
			"before a body is built — a late fallback means both paths were paid")
	}
	if !resp.Truncated || len(resp.Answer) != 0 {
		t.Fatalf("fallback response tc=%v answers=%d, want truncated empty",
			resp.Truncated, len(resp.Answer))
	}
}

// TestWireServableGatesRunBeforeCopy pins the "never pay both paths" rule
// at the unit level: ineligible combinations must be rejected by the
// zero-allocation gate, not by a post-copy failure.
func TestWireServableGatesRunBeforeCopy(t *testing.T) {
	plain := wireFastEntry(t, "gate.example.com.", dns.TypeA, false)
	signed := wireFastEntry(t, "gate.example.com.", dns.TypeA, true)

	// Incomplete alias chain: CNAME answer without the terminal qtype.
	chase := new(dns.Msg)
	chaseReq := new(dns.Msg)
	chaseReq.SetQuestion("alias.example.com.", dns.TypeA)
	chase.SetReply(chaseReq)
	chase.Answer = append(chase.Answer, makeRR("alias.example.com. 300 IN CNAME target.example.net."))

	req := new(dns.Msg)
	req.SetQuestion("gate.example.com.", dns.TypeA)

	entryOf := func(msg *dns.Msg) *CacheEntry {
		e := NewCacheEntryWithKey(msg, time.Minute, 0, 1)
		if e == nil {
			t.Fatal("entry not admitted")
		}
		return e
	}

	do0 := middleware.WireCapability{DO: false}
	do1 := middleware.WireCapability{DO: true}
	if !entryOf(plain).wireEligibleFor(req) || !entryOf(plain).wireFitsChain(do0) {
		t.Fatal("plain entry must be servable to DO=0")
	}
	// A signed entry is servable to DO=0 as well, but only from the stripped
	// body — the stored one must never reach a client that did not ask for
	// DNSSEC.
	signedEntry := entryOf(signed)
	if !signedEntry.wireFitsChain(do0) {
		t.Fatal("DNSSEC entry must be servable to DO=0 from its stripped body")
	}
	if body, flags := signedEntry.wireBodyFor(false); body == nil ||
		&body[0] == &signedEntry.wire[0] || flags&wireHasDNSSEC != 0 {
		t.Fatal("DO=0 must be served the stripped body, never the stored one")
	}
	// Without a stripped body the gate still has to turn the request away.
	bare := entryOf(signed)
	bare.stripped, bare.strippedServe = nil, 0
	if bare.wireFitsChain(do0) {
		t.Fatal("a DNSSEC entry with no stripped body must be gated for DO=0")
	}
	if !entryOf(signed).wireFitsChain(do1) {
		t.Fatal("DNSSEC entry must be servable to DO=1")
	}
	// The transport's size ceiling is part of the same allocation-free gate.
	tight := middleware.WireCapability{DO: true, Reserve: 11, MaxSize: len(entryOf(plain).wire) + 10}
	if entryOf(plain).wireFitsChain(tight) {
		t.Fatal("a reply exceeding the transport ceiling must be gated before any copy")
	}
	chaseEntry := NewCacheEntryWithKey(chase, time.Minute, 0, 1)
	if chaseEntry == nil {
		t.Fatal("chase entry not admitted")
	}
	chaseReq2 := new(dns.Msg)
	chaseReq2.SetQuestion("alias.example.com.", dns.TypeA)
	if chaseEntry.wireEligibleFor(chaseReq2) {
		t.Fatal("incomplete CNAME chain must stay on the Msg path")
	}
}

var _ = config.Config{} // keep the config import for makeTestConfig callers

// BenchmarkWireFastPath measures the three serve outcomes the design must
// keep honest: the byte path itself, the pre-copy rejection (which must cost
// nearly nothing on top of the Msg path), and the historical Msg path.
func BenchmarkWireFastPath(b *testing.B) {
	const qname = "bench.example.com."
	run := func(b *testing.B, reqName string, dnssec, do, forceMsg bool, cookie ...string) {
		entry := wireFastEntry(b, qname, dns.TypeA, dnssec)
		c, e := wireFastTestPipeline(b, entry)

		req := new(dns.Msg)
		req.SetQuestion(reqName, dns.TypeA)
		req.Id = 4242
		req.RecursionDesired = true
		// The edns layer appends the server cookie to the *request's* OPT,
		// so a reused request accumulates options across iterations. Every
		// live query arrives with a freshly unpacked OPT; refresh it each
		// iteration so the measurement reflects that (the one OPT
		// allocation is identical across all three variants, leaving the
		// deltas meaningful).
		freshOPT := func() {
			req.Extra = req.Extra[:0]
			req.SetEdns0(1232, do)
			if len(cookie) > 0 {
				opt := req.IsEdns0()
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
					Code: dns.EDNS0COOKIE, Cookie: cookie[0],
				})
			}
		}
		freshOPT()

		writer := &transportWriter{Writer: mock.NewWriter("udp", "198.51.100.77:40000")}
		terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			b.Fatal("missed cache")
		})
		ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
		// Wrap once: Chain.Reset rebinds the existing writer rather than
		// replacing it, so re-wrapping per iteration would nest shims and
		// turn Reset into an O(depth) walk.
		ch.Reset(writer, req)
		if forceMsg {
			ch.Writer = &msgPathShim{ResponseWriter: ch.Writer}
		}
		shim := ch.Writer

		// Verify the intended path actually runs, and that the response is
		// the real cached answer — a benchmark measuring an error return or
		// a silent miss would be worthless.
		servedBefore := wireFastServed.Value()
		ch.Next(context.Background())
		servedDelta := wireFastServed.Value() - servedBefore
		// A signed entry reaches a client without DO too, from its stripped
		// body — the gate only turns a request away when there is no body
		// it may be served.
		wantWire := !forceMsg
		if wantWire != (servedDelta == 1) {
			b.Fatalf("path check: wire served %d, wantWire=%v", servedDelta, wantWire)
		}
		if writer.packed == 0 {
			b.Fatal("nothing reached the transport")
		}

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			freshOPT()
			ch.Writer = shim
			ch.Reset(writer, req)
			ch.Next(context.Background())
		}
	}

	b.Run("wire_served", func(b *testing.B) { run(b, qname, true, true, false) })
	b.Run("wire_served_cookie", func(b *testing.B) { run(b, qname, true, true, false, "0123456789abcdef") })
	// The client's spelling differs from the stored one, so the question has
	// to be re-encoded. This is the path the exact-match shortcut declines;
	// it must stay a byte-served reply, and no dearer than it was.
	b.Run("wire_served_case_rewrite", func(b *testing.B) { run(b, "BeNcH.ExAmPlE.CoM.", true, true, false) })
	// A signed entry answering a client without DO: served from the stripped
	// body, which is the commonest hit a validating resolver has.
	b.Run("wire_served_do0_stripped", func(b *testing.B) { run(b, qname, true, false, false) })
	b.Run("msg_path_baseline", func(b *testing.B) { run(b, qname, true, true, true) })
	b.Run("msg_baseline_cookie", func(b *testing.B) { run(b, qname, true, true, true, "0123456789abcdef") })
}

// TestWireFastPathClearsAuthoritative pins the reply-header contract that
// the message path gets from SetReply plus its own shaping: a cached answer
// is never authoritative, and RD/CD come from the request in flight — not
// from whatever the upstream stored.
func TestWireFastPathClearsAuthoritative(t *testing.T) {
	const qname = "aa.example.com."
	entry := wireFastEntryAA(t, qname, dns.TypeA)
	c, e := wireFastTestPipeline(t, entry)

	// The cache refuses RD=0 queries outright, so the pipeline can only
	// exercise RD=1; the copied-bit contract is pinned at the unit level
	// below.
	for _, rd := range []bool{true} {
		req := new(dns.Msg)
		req.SetQuestion(qname, dns.TypeA)
		req.Id = 11
		req.RecursionDesired = rd
		req.SetEdns0(1232, true)

		servedBefore := wireFastServed.Value()
		viaWire := serveThrough(t, c, e, req, false)
		if wireFastServed.Value() != servedBefore+1 {
			t.Fatal("expected the byte path to serve")
		}
		if viaWire.Authoritative {
			t.Fatal("cached answer served with AA=1")
		}
		if viaWire.RecursionDesired != rd {
			t.Fatalf("RD = %v, want the request's %v", viaWire.RecursionDesired, rd)
		}
		if !viaWire.Response {
			t.Fatal("QR not set on the served reply")
		}
		assertEquivalent(t, "aa", viaWire, serveThrough(t, c, e, req, true))
	}

	// Unit level: the served bytes carry the request's RD and CD, and never
	// the stored AA.
	stored := NewCacheEntryWithKey(entry, time.Minute, 0, 1)
	if stored == nil {
		t.Fatal("entry not admitted")
	}
	for _, want := range []struct{ rd, cd bool }{{true, false}, {false, true}, {false, false}} {
		probe := new(dns.Msg)
		probe.SetQuestion(qname, dns.TypeA)
		probe.Id = 33
		probe.RecursionDesired = want.rd
		probe.CheckingDisabled = want.cd

		body, _, ok := stored.serveWire(probe, 0, true)
		if !ok {
			t.Fatal("serveWire refused a plain request")
		}
		decoded := new(dns.Msg)
		if err := decoded.Unpack(body); err != nil {
			t.Fatalf("served bytes do not decode: %v", err)
		}
		if decoded.Authoritative {
			t.Fatal("served bytes kept the stored AA bit")
		}
		if decoded.RecursionDesired != want.rd || decoded.CheckingDisabled != want.cd {
			t.Fatalf("rd/cd = %v/%v, want %v/%v",
				decoded.RecursionDesired, decoded.CheckingDisabled, want.rd, want.cd)
		}
		if !decoded.Response || decoded.Id != probe.Id {
			t.Fatalf("qr=%v id=%d", decoded.Response, decoded.Id)
		}
	}
}

// TestWireFastPathExcludesNonByteTransports pins the transport gate. DoQ
// requires the reply ID to be zero (RFC 9250 §4.2.1) — a rewrite its raw
// byte write does not perform — and the DoH assembly path unpacks whatever
// bytes it receives only to pack them again. Both must stay on the message
// path until they can carry bytes natively.
func TestWireFastPathExcludesNonByteTransports(t *testing.T) {
	const qname = "proto.example.com."
	entry := wireFastEntry(t, qname, dns.TypeA, false)

	for _, proto := range []string{"doq", "doh", "udp"} {
		c, e := wireFastTestPipeline(t, entry)
		req := new(dns.Msg)
		req.SetQuestion(qname, dns.TypeA)
		req.Id = 4242
		req.RecursionDesired = true
		req.SetEdns0(1232, true)

		writer := mock.NewWriter(proto, "198.51.100.77:40000")
		terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			t.Fatal("missed cache")
		})
		ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
		ch.Reset(writer, req)

		servedBefore := wireFastServed.Value()
		ch.Next(context.Background())
		served := wireFastServed.Value() - servedBefore

		wantServed := proto == "udp"
		if wantServed != (served == 1) {
			t.Fatalf("proto %s: wire served %d, want served=%v", proto, served, wantServed)
		}
		if got := writer.Msg(); got == nil || len(got.Answer) != 2 {
			t.Fatalf("proto %s: response = %v", proto, got)
		}
	}
}

// TestWireFastPathGateRunsBeforeAnyAllocation pins the "never pay both
// paths" property directly: a request the chain cannot serve as bytes must
// not allocate the body copy the byte path would need.
func TestWireFastPathGateRunsBeforeAnyAllocation(t *testing.T) {
	const qname = "gate2.example.com."
	// A signed entry with a DO=0 client: the request's own OPT says DO=1 by
	// the time the cache sees it (the edns layer sets it for upstream
	// validation), so only the writer chain's preflight can tell the truth.
	//
	// Such an entry is normally served from its stripped body, so the one
	// held here has none — the state an entry lands in when its stripped
	// form could not be packed or is not itself byte-servable. That is what
	// still makes the preflight refuse.
	entry := wireFastEntry(t, qname, dns.TypeA, true)
	c, e := wireFastTestPipeline(t, entry)

	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	req.Id = 12
	req.RecursionDesired = true
	req.SetEdns0(1232, false) // client did not ask for DNSSEC

	cached, ok := c.store.LookupByKey(CacheKey{Question: req.Question[0]}.Hash())
	if !ok {
		t.Fatal("the entry under test was not admitted")
	}
	if cached.stripped == nil {
		t.Fatal("fixture is wrong: a signed entry should carry a stripped body")
	}
	cached.stripped, cached.strippedServe = nil, 0

	writer := mock.NewWriter("udp", "198.51.100.77:40000")
	terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		t.Fatal("missed cache")
	})
	ch := middleware.NewChain([]middleware.Handler{e, c, terminal})

	fallbackBefore := wireFastFallback.Value()
	servedBefore := wireFastServed.Value()
	skippedBefore := wireSkipDNSSEC.Value()
	allocs := testing.AllocsPerRun(50, func() {
		ch.Reset(writer, req)
		ch.Next(context.Background())
	})
	if wireFastFallback.Value() != fallbackBefore {
		t.Fatal("a DO=0 client with a signed entry reached the late fallback; " +
			"the preflight must refuse before the body is built")
	}
	if wireFastServed.Value() != servedBefore {
		t.Fatal("an entry with no stripped body was served as bytes to a " +
			"client that did not ask for DNSSEC")
	}
	if wireSkipDNSSEC.Value() == skippedBefore {
		t.Fatal("the refusal was not attributed to the DNSSEC gate")
	}

	// The point of refusing early is that the message path pays for itself
	// and nothing else: no body copy built for a request that cannot take
	// one. The ceiling is loose enough to survive unrelated churn and tight
	// enough that building the byte body too would break it.
	const ceiling = 40
	if allocs > ceiling {
		t.Fatalf("a preflight-refused hit allocated %.0f times, want at most %d",
			allocs, ceiling)
	}
	t.Logf("message-path allocations for a preflight-refused hit: %.0f", allocs)
}
