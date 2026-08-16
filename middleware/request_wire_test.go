package middleware

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
)

// packQuery packs a one-question query, optionally with an OPT carrying
// the given options, and returns the wire bytes.
func packQuery(t *testing.T, name string, qtype uint16, edns bool, opts ...dns.EDNS0) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	if edns {
		m.SetEdns0(1232, true)
		if len(opts) > 0 {
			m.IsEdns0().Option = append(m.IsEdns0().Option, opts...)
		}
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return raw
}

// TestParseWireAccessors pins that a wire-born Request reports exactly the
// facts the decoded form would.
func TestParseWireAccessors(t *testing.T) {
	cookie := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"}
	nsid := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}
	raw := packQuery(t, "WWW.Example.COM.", dns.TypeAAAA, true, cookie, nsid)

	readTime := time.Now()
	slot := &struct{ tag string }{tag: "slot"}
	r := new(Request)
	if !r.ParseWire(raw, readTime, slot) {
		t.Fatal("eligible query refused")
	}

	decoded := new(dns.Msg)
	if err := decoded.Unpack(raw); err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if !r.Undecoded() {
		t.Fatal("wire-born request must start undecoded")
	}
	if got, want := r.ID(), decoded.Id; got != want {
		t.Fatalf("ID %d, want %d", got, want)
	}
	if got, want := r.Qtype(), decoded.Question[0].Qtype; got != want {
		t.Fatalf("Qtype %d, want %d", got, want)
	}
	if got, want := r.Qclass(), decoded.Question[0].Qclass; got != want {
		t.Fatalf("Qclass %d, want %d", got, want)
	}
	if got, want := r.RD(), decoded.RecursionDesired; got != want {
		t.Fatalf("RD %v, want %v", got, want)
	}
	if got, want := r.CD(), decoded.CheckingDisabled; got != want {
		t.Fatalf("CD %v, want %v", got, want)
	}
	if r.Opcode() != dns.OpcodeQuery {
		t.Fatalf("Opcode %d, want query", r.Opcode())
	}
	if !r.HasOPT() || !r.DO() || r.UDPSize() != 1232 || r.EDNSVersion() != 0 {
		t.Fatalf("OPT facts diverge: hasOPT=%v do=%v size=%d version=%d",
			r.HasOPT(), r.DO(), r.UDPSize(), r.EDNSVersion())
	}
	if !r.HasNSID() || r.HasECS() {
		t.Fatalf("option flags diverge: nsid=%v ecs=%v", r.HasNSID(), r.HasECS())
	}
	if got := r.ClientCookie(); len(got) != 8 ||
		binary.BigEndian.Uint64(got) != 0x0123456789abcdef {
		t.Fatalf("client cookie %x", got)
	}
	// The wire name is the client's exact spelling.
	wantName := []byte("\x03WWW\x07Example\x03COM\x00")
	if string(r.WireName()) != string(wantName) {
		t.Fatalf("wire name %q, want %q", r.WireName(), wantName)
	}
	if !r.ReadTime().Equal(readTime) {
		t.Fatal("read time not carried")
	}
	if r.EDNSWriterSlot() != any(slot) {
		t.Fatal("edns writer slot not carried")
	}
}

// TestParseWireEligibility pins the conservative refusal set: everything a
// wire-born request cannot express takes the decoded entry instead.
func TestParseWireEligibility(t *testing.T) {
	base := packQuery(t, "example.com.", dns.TypeA, false)

	mutate := func(f func(b []byte) []byte) []byte {
		b := append([]byte(nil), base...)
		return f(b)
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"response bit", mutate(func(b []byte) []byte { b[2] |= 0x80; return b })},
		{"foreign opcode", mutate(func(b []byte) []byte { b[2] |= byte(dns.OpcodeNotify) << 3; return b })},
		{"qdcount 2", mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[4:6], 2); return b })},
		{"ancount 1", mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[6:8], 1); return b })},
		{"nscount 1", mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[8:10], 1); return b })},
		{"arcount 2", mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[10:12], 2); return b })},
		{"compressed name", func() []byte {
			b := append([]byte(nil), base[:12]...)
			b = append(b, 0xC0, 0x0C) // pointer where a name must be literal
			b = append(b, base[12+len("example.com.")+1:]...)
			return b
		}()},
		{"trailing bytes", append(append([]byte(nil), base...), 0x00)},
		{"truncated question", base[:14]},
		{"arcount without record", mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[10:12], 1); return b })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := new(Request)
			if r.ParseWire(tc.raw, time.Now(), nil) {
				t.Fatal("ineligible packet accepted")
			}
		})
	}

	// Extended-rcode and bad-version OPTs also refuse.
	withOPT := packQuery(t, "example.com.", dns.TypeA, true)
	optOff := len(withOPT) - 11 // fixed OPT: root + type + class + ttl + rdlen(0)
	extRcode := append([]byte(nil), withOPT...)
	extRcode[optOff+5] = 1
	r := new(Request)
	if r.ParseWire(extRcode, time.Now(), nil) {
		t.Fatal("extended-rcode query accepted")
	}
}

// materializeProbe drives Chain.Materialize from inside a handler.
type materializeProbe struct {
	sawWire  bool
	detached context.Context
	msg      *dns.Msg
}

func (p *materializeProbe) Name() string { return "materialize-probe" }

func (p *materializeProbe) ServeDNS(ctx context.Context, ch *Chain) {
	p.sawWire = ch.Request.Undecoded()
	ctx, req := ch.Materialize(ctx)
	p.detached, p.msg = ctx, req
	if req == nil {
		return
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// TestMaterializeTransition pins the one-way wire→Msg transition: the
// handler that needs the decoded request gets it exactly once, on a
// detached deadline context, and the chain closes the detach lifecycle.
func TestMaterializeTransition(t *testing.T) {
	probe := &materializeProbe{}
	ch := NewChain([]Handler{probe})

	raw := packQuery(t, "example.com.", dns.TypeA, true)
	r := new(Request)
	if !r.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	w := mock.NewWriter("udp", "203.0.113.10:4242")
	ch.ResetWire(w, r)
	ch.Next(context.Background())

	if !probe.sawWire {
		t.Fatal("handler did not observe the wire-born request")
	}
	if probe.msg == nil || ch.Request.Msg() != probe.msg {
		t.Fatal("materialization did not latch the decoded request")
	}
	if ch.Request.Undecoded() {
		t.Fatal("a materialized request must not report itself undecoded")
	}
	if probe.detached == context.Background() {
		t.Fatal("materialization must hand back a detached context")
	}
	if _, ok := probe.detached.Deadline(); !ok {
		t.Fatal("detached context carries no deadline")
	}
	if ch.detachCleanup == nil {
		t.Fatal("chain does not own the detach cleanup")
	}

	// Idempotent while the serve is live: a second materialization returns
	// the same message and leaves the caller's context alone.
	ctx2, again := ch.Materialize(context.Background())
	if again != probe.msg || ctx2 != context.Background() {
		t.Fatal("second materialization must be a no-op")
	}

	ch.finishDetach()
	if ch.detachCleanup != nil {
		t.Fatal("finishDetach must clear the cleanup")
	}
	if !w.Written() {
		t.Fatal("reply never reached the transport")
	}
	if w.Msg().Id != r.ID() {
		t.Fatalf("reply ID %d, want %d", w.Msg().Id, r.ID())
	}
}

// lazyMsgHandler is the shape a middleware written against the old
// *dns.Msg API takes after the mechanical migration: it reads
// ch.Request.Msg() and calls Next, never mentioning Materialize.
type lazyMsgHandler struct {
	name string
	saw  *dns.Msg
}

func (h *lazyMsgHandler) Name() string { return h.name }

func (h *lazyMsgHandler) ServeDNS(ctx context.Context, ch *Chain) {
	h.saw = ch.Request.Msg()
	ch.Next(ctx)
}

// downstreamProbe records the context its predecessor handed it.
type downstreamProbe struct{ got context.Context }

func (p *downstreamProbe) Name() string { return "downstream-probe" }

func (p *downstreamProbe) ServeDNS(ctx context.Context, ch *Chain) {
	p.got = ctx
	ch.Cancel()
}

// TestLazyMsgMigrationIsSafe pins the migration contract for middleware
// written against the old API: reading ch.Request.Msg() on a wire-born
// request decodes instead of returning nil, and the chain — not the
// handler — detaches before anything downstream runs on the job carrier.
func TestLazyMsgMigrationIsSafe(t *testing.T) {
	lazy := &lazyMsgHandler{name: "lazy-msg"}
	down := &downstreamProbe{}
	ch := NewChain([]Handler{lazy, down})

	raw := packQuery(t, "lazy.example.", dns.TypeA, true)
	r := new(Request)
	if !r.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	carrier := context.Background()
	ch.ResetWire(mock.NewWriter("udp", "203.0.113.12:4242"), r)
	ch.Next(carrier)

	if lazy.saw == nil {
		t.Fatal("Msg() returned nil to a handler; the migration would panic")
	}
	if len(lazy.saw.Question) != 1 || lazy.saw.Question[0].Name != "lazy.example." {
		t.Fatalf("decoded request is wrong: %v", lazy.saw.Question)
	}
	if down.got == nil || down.got == carrier {
		t.Fatal("downstream ran on the job carrier; the chain must detach after a lazy decode")
	}
	if _, ok := down.got.Deadline(); !ok {
		t.Fatal("detached context carries no deadline")
	}
	if ch.detachCleanup == nil {
		t.Fatal("chain does not own the detach lifecycle")
	}
	ch.finishDetach()
}

// TestAccessorsSurviveMaterialization pins whose facts the accessors
// report. Materializing a wire-born request normalizes it — SetEdns0
// attaches an OPT and forces DO — and a handler asking what the client
// sent must still be told the truth afterwards.
func TestAccessorsSurviveMaterialization(t *testing.T) {
	// A plain query: no OPT, so no DO, no advertised size, no options.
	raw := packQuery(t, "plain.example.", dns.TypeA, false)
	r := new(Request)
	if !r.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	// The edns layer records the normalization it would apply, exactly as
	// its wire branch does before handing the request on.
	r.RecordEDNSNormalization(nil, netip.Addr{})

	before := map[string]any{
		"hasOPT": r.HasOPT(), "do": r.DO(), "udpSize": r.UDPSize(),
		"hasECS": r.HasECS(), "hasNSID": r.HasNSID(), "ad": r.AD(),
		"cd": r.CD(), "rd": r.RD(), "id": r.ID(), "qtype": r.Qtype(),
	}
	if before["hasOPT"] != false || before["do"] != false {
		t.Fatalf("parsed facts wrong before materialization: %v", before)
	}

	msg := r.Msg()
	if msg == nil {
		t.Fatal("materialization failed")
	}
	if msg.IsEdns0() == nil {
		t.Fatal("this test is pointless unless materialization normalizes the message")
	}

	after := map[string]any{
		"hasOPT": r.HasOPT(), "do": r.DO(), "udpSize": r.UDPSize(),
		"hasECS": r.HasECS(), "hasNSID": r.HasNSID(), "ad": r.AD(),
		"cd": r.CD(), "rd": r.RD(), "id": r.ID(), "qtype": r.Qtype(),
	}
	for k, want := range before {
		if after[k] != want {
			t.Fatalf("%s changed under materialization: %v → %v (the client sent neither)",
				k, want, after[k])
		}
	}
}

// TestCancelWithRcodeWireBorn pins the terminal rcode reply on an
// undecoded request: it decodes for the reply shape but detaches nothing.
func TestCancelWithRcodeWireBorn(t *testing.T) {
	ch := NewChain(nil)
	raw := packQuery(t, "example.com.", dns.TypeA, true)
	r := new(Request)
	if !r.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	w := mock.NewWriter("udp", "203.0.113.11:4242")
	ch.ResetWire(w, r)

	ch.CancelWithRcode(dns.RcodeRefused, true)
	if !w.Written() || w.Rcode() != dns.RcodeRefused {
		t.Fatalf("rcode reply missing: written=%v rcode=%d", w.Written(), w.Rcode())
	}
	if ch.detachCleanup != nil {
		t.Fatal("a terminal reply must not establish a detach lifecycle")
	}
}
