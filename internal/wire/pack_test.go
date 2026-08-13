package wire

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mustPackRR(tb testing.TB, s string) dns.RR {
	tb.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		tb.Fatalf("NewRR(%q): %v", s, err)
	}
	return r
}

// tryPackBytes packs through the custom path and returns what consume saw.
func tryPackBytes(tb testing.TB, msg *dns.Msg) ([]byte, bool) {
	tb.Helper()
	var got []byte
	handled, err := TryPack(msg, func(body []byte) error {
		got = append([]byte(nil), body...)
		return nil
	})
	if err != nil {
		tb.Fatalf("consume error: %v", err)
	}
	return got, handled
}

// libraryPack is the reference: the library packing the original message,
// with its one write — the extended rcode into the selected OPT's TTL —
// undone afterwards so the corpus message stays as built for the next
// comparison.
//
// It must be the original, not a Copy. Copy duplicates each record
// separately, so a message carrying the same OPT pointer twice becomes two
// distinct objects, of which the library mutates only the first — while on
// the original it mutates the one object and packs the new TTL at every
// occurrence. Aliasing is part of the semantics being compared, and a copy
// destroys it.
func libraryPack(tb testing.TB, msg *dns.Msg) ([]byte, error) {
	tb.Helper()
	opt, safe := selectOPT(msg)
	if !safe {
		tb.Fatal("libraryPack: a shape IsEdns0 panics on has no reference")
	}
	var saved uint32
	if opt != nil {
		saved = opt.Hdr.Ttl
	}
	packed, err := msg.Pack()
	if opt != nil {
		opt.Hdr.Ttl = saved
	}
	return packed, err
}

func packCorpus(tb testing.TB) []*dns.Msg {
	tb.Helper()

	var corpus []*dns.Msg

	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.Answer = []dns.RR{mustPackRR(tb, "www.example.com. 300 IN A 192.0.2.1")}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.Answer = []dns.RR{
		mustPackRR(tb, "www.example.com. 300 IN CNAME cdn.example.net."),
		mustPackRR(tb, "cdn.example.net. 300 IN CNAME edge.cdn.example.net."),
		mustPackRR(tb, "edge.cdn.example.net. 300 IN A 192.0.2.2"),
	}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion("deep.sub.example.com.", dns.TypeA)
	m.Ns = []dns.RR{
		mustPackRR(tb, "sub.example.com. 172800 IN NS ns1.sub.example.com."),
		mustPackRR(tb, "sub.example.com. 172800 IN NS ns2.sub.example.com."),
	}
	m.Extra = []dns.RR{
		mustPackRR(tb, "ns1.sub.example.com. 172800 IN A 192.0.2.3"),
		mustPackRR(tb, "ns2.sub.example.com. 172800 IN AAAA 2001:db8::1"),
	}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion("nothing.example.com.", dns.TypeA)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{mustPackRR(tb, "example.com. 3600 IN SOA ns1.example.com. "+
		"hostmaster.example.com. 2026081301 7200 3600 1209600 3600")}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion("secure.example.com.", dns.TypeA)
	m.AuthenticatedData = true
	m.Answer = []dns.RR{
		mustPackRR(tb, "secure.example.com. 300 IN A 192.0.2.4"),
		mustPackRR(tb, "secure.example.com. 300 IN RRSIG A 8 3 300 20260901000000 "+
			"20260801000000 12345 example.com. AwEAAcQ8"),
	}
	m.Ns = []dns.RR{
		mustPackRR(tb, "secure.example.com. 3600 IN NSEC t.example.com. A RRSIG NSEC"),
	}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeHTTPS)
	m.Answer = []dns.RR{
		mustPackRR(tb, `example.com. 300 IN HTTPS 1 . alpn="h3,h2"`),
		mustPackRR(tb, `example.com. 300 IN SVCB 2 svc.example.com. port=8443`),
		mustPackRR(tb, `example.com. 300 IN NAPTR 100 50 "s" "SIP+D2U" "" _sip._udp.example.com.`),
	}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeMX)
	m.Answer = []dns.RR{
		mustPackRR(tb, "example.com. 300 IN MX 10 mail.example.com."),
		mustPackRR(tb, "example.com. 300 IN SRV 10 60 5060 sip.example.com."),
		mustPackRR(tb, "1.2.0.192.in-addr.arpa. 300 IN PTR www.example.com."),
	}
	corpus = append(corpus, m)

	m = new(dns.Msg)
	m.SetQuestion(`weird\.name.example.com.`, dns.TypeTXT)
	m.Answer = []dns.RR{
		mustPackRR(tb, `weird\.name.example.com. 300 IN TXT "a" "zzzz"`),
		mustPackRR(tb, `WEIRD\.NAME.EXAMPLE.COM. 300 IN TXT "b"`),
	}
	corpus = append(corpus, m)

	// EDNS0 with options, an ordinary rcode.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = []dns.RR{mustPackRR(tb, "example.com. 300 IN A 192.0.2.6")}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.SetDo()
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{
		InfoCode: dns.ExtendedErrorCodeStaleAnswer, ExtraText: "stale",
	})
	m.Extra = []dns.RR{opt}
	corpus = append(corpus, m)

	// The extended rcode, which lives in the OPT's TTL and is written at
	// pack time.
	m = m.Copy()
	m.Rcode = dns.RcodeBadVers
	corpus = append(corpus, m)

	// Stale extended-rcode bits with a low rcode: the library's write is
	// unconditional and clears them, so ours must too.
	m = m.Copy()
	m.Rcode = dns.RcodeSuccess
	m.IsEdns0().Hdr.Ttl |= 0xAB << 24
	corpus = append(corpus, m)

	// The same OPT pointer twice, and a second distinct OPT: the library
	// rewrites only the record IsEdns0 returns, however often it appears.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Rcode = dns.RcodeBadVers
	twice := new(dns.OPT)
	twice.Hdr.Name = "."
	twice.Hdr.Rrtype = dns.TypeOPT
	twice.SetUDPSize(512)
	other := new(dns.OPT)
	other.Hdr.Name = "."
	other.Hdr.Rrtype = dns.TypeOPT
	other.SetUDPSize(4096)
	other.Hdr.Ttl |= 0x77 << 24
	m.Extra = []dns.RR{twice, twice, other}
	corpus = append(corpus, m)

	// Every flag at once.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Authoritative = true
	m.Truncated = true
	m.RecursionDesired = true
	m.RecursionAvailable = true
	m.Zero = true
	m.AuthenticatedData = true
	m.CheckingDisabled = true
	m.Opcode = dns.OpcodeStatus
	m.Rcode = dns.RcodeRefused
	m.Answer = []dns.RR{mustPackRR(tb, "example.com. 300 IN A 192.0.2.7")}
	corpus = append(corpus, m)

	// More than one question: compressible by the library's private rule,
	// which an earlier version of this packer got wrong.
	m = new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.Question = append(m.Question, dns.Question{
		Name: "mail.example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET,
	})
	corpus = append(corpus, m)

	// Zero-RDATA record shapes, dynamic-update style.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = []dns.RR{
		&dns.ANY{Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeANY, Class: dns.ClassANY,
		}},
		mustPackRR(tb, "example.com. 300 IN A 192.0.2.8"),
	}
	corpus = append(corpus, m)

	// Question only, and empty.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	corpus = append(corpus, m)
	corpus = append(corpus, new(dns.Msg))

	// Names at every depth, so suffix matching finds something at each level.
	m = new(dns.Msg)
	m.SetQuestion("a.b.c.d.e.f.example.com.", dns.TypeA)
	for _, name := range []string{
		"a.b.c.d.e.f.example.com.", "b.c.d.e.f.example.com.",
		"c.d.e.f.example.com.", "d.e.f.example.com.",
		"e.f.example.com.", "f.example.com.", "example.com.",
	} {
		m.Answer = append(m.Answer, mustPackRR(tb, name+" 300 IN A 192.0.2.5"))
	}
	corpus = append(corpus, m)

	// Sizes around the classical limits: 512 and 1232 land mid-buffer, and
	// larger corpora cover the 4096 edge in their own test.
	for _, target := range []int{512, 1232} {
		m = new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeTXT)
		for m.Len() < target {
			m.Answer = append(m.Answer, mustPackRR(tb,
				`example.com. 300 IN TXT "`+strings.Repeat("x", 50)+`"`))
		}
		corpus = append(corpus, m)
	}

	return corpus
}

// messageFingerprint captures everything the packer must not change: the
// rendered message, every record header's Rdlength, and the OPT TTL where the
// library writes the extended rcode.
func messageFingerprint(msg *dns.Msg) string {
	var b strings.Builder
	b.WriteString(msg.String())
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr == nil {
				b.WriteString("|nil")
				continue
			}
			fmt.Fprintf(&b, "|%d:%d", rr.Header().Rdlength, rr.Header().Ttl)
		}
	}
	return b.String()
}

// TestTryPackMatchesLibrary is the whole contract: for every message this
// path handles, the same bytes the library would produce, without the writes
// the library makes into the message.
func TestTryPackMatchesLibrary(t *testing.T) {
	for i, msg := range packCorpus(t) {
		for _, compress := range []bool{false, true} {
			msg.Compress = compress
			before := messageFingerprint(msg)

			want, wantErr := libraryPack(t, msg)
			got, handled := tryPackBytes(t, msg)

			if !handled {
				t.Fatalf("message %d compress=%v: not handled; nothing in "+
					"this corpus should fall back", i, compress)
			}
			if wantErr != nil {
				t.Fatalf("message %d compress=%v: handled a message the "+
					"library rejects: %v", i, compress, wantErr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("message %d compress=%v: %d bytes against the "+
					"library's %d, and they differ\n got: %x\nwant: %x",
					i, compress, len(got), len(want), got, want)
			}
			if after := messageFingerprint(msg); after != before {
				t.Fatalf("message %d compress=%v: packing modified the "+
					"message\nbefore: %s\nafter:  %s", i, compress, before, after)
			}

			var back dns.Msg
			if err := back.Unpack(got); err != nil {
				t.Fatalf("message %d compress=%v: packed bytes do not "+
					"unpack: %v", i, compress, err)
			}
		}
	}
}

// TestTryPackRepeatedAgrees drives the pooled state through many messages in
// sequence. A dictionary or shim returned dirty would not show on the first
// pack — it would show on the one after it.
func TestTryPackRepeatedAgrees(t *testing.T) {
	corpus := packCorpus(t)
	want := make([][]byte, len(corpus))
	for i, msg := range corpus {
		msg.Compress = true
		packed, err := libraryPack(t, msg)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		want[i] = packed
	}

	for round := range 50 {
		for i, msg := range corpus {
			got, handled := tryPackBytes(t, msg)
			if !handled {
				t.Fatalf("round %d message %d: not handled", round, i)
			}
			if !bytes.Equal(got, want[i]) {
				t.Fatalf("round %d message %d: bytes differ from the first "+
					"pack; pooled state carried over", round, i)
			}
		}
	}
}

// TestTryPackSharedMessageConcurrently packs one message from many goroutines
// at once. The message is shared and immutable; everything mutable belongs to
// the per-pack state, so this must be race-free and byte-stable. Run under
// -race, this is the proof that the shim actually protects the records.
func TestTryPackSharedMessageConcurrently(t *testing.T) {
	corpus := packCorpus(t)
	want := make([][]byte, len(corpus))
	for i, msg := range corpus {
		msg.Compress = true
		packed, err := libraryPack(t, msg)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		want[i] = packed
	}

	done := make(chan error, 16)
	for range 16 {
		go func() {
			for range 100 {
				for i, msg := range corpus {
					var got []byte
					handled, err := TryPack(msg, func(body []byte) error {
						got = append([]byte(nil), body...)
						return nil
					})
					if err != nil || !handled {
						done <- fmt.Errorf(
							"message %d: handled=%v err=%v", i, handled, err)
						return
					}
					if !bytes.Equal(got, want[i]) {
						done <- fmt.Errorf(
							"message %d packed differently under concurrency", i)
						return
					}
				}
			}
			done <- nil
		}()
	}
	for range 16 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// TestTryPackFallsBack pins every input the custom path must refuse rather
// than guess at.
func TestTryPackFallsBack(t *testing.T) {
	assertFallback := func(what string, msg *dns.Msg) {
		t.Helper()
		handled, err := TryPack(msg, func([]byte) error {
			t.Fatalf("%s: consume ran on a fallback", what)
			return nil
		})
		if handled || err != nil {
			t.Fatalf("%s: handled=%v err=%v, want an untouched fallback",
				what, handled, err)
		}
	}

	assertFallback("nil message", nil)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Rcode = 0x1000
	assertFallback("rcode out of range", m)

	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Rcode = dns.RcodeBadVers
	assertFallback("extended rcode with no OPT to carry it", m)

	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = []dns.RR{mustPackRR(t, "example.com. 300 IN A 192.0.2.1"), nil}
	assertFallback("nil record", m)

	// A wrapper embedding dns.RR satisfies the interface through promotion
	// and packs — but it is not a library record, and a wrapper hiding a
	// PrivateRR would slip past any single-type assertion. Admission is by
	// dynamic type, so both fall back.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = []dns.RR{wrappedRR{mustPackRR(t, "example.com. 300 IN A 192.0.2.1")}}
	assertFallback("a wrapped builtin record", m)

	// The two shapes that panic IsEdns0 — a nil record in Extra, and a
	// wrapper wearing the OPT type — must be turned away by admission
	// before anything walks Extra looking for the OPT.
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Extra = []dns.RR{nil}
	assertFallback("a nil record in Extra", m)

	fakeOPT := new(dns.OPT)
	fakeOPT.Hdr.Name = "."
	fakeOPT.Hdr.Rrtype = dns.TypeOPT
	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Extra = []dns.RR{wrappedRR{fakeOPT}}
	assertFallback("a wrapped record wearing the OPT type", m)
}

// wrappedRR is the external-embedding shape the type admission must refuse:
// every dns.RR method promotes, so nothing but the dynamic type gives it away.
type wrappedRR struct{ dns.RR }

// TestTryPackFallsBackOnPrivateRR keeps the caller-registered packing
// protocol on the library path, whose sizing pass this one does not run —
// bare, and hidden inside a wrapper, which is how it would sneak past a type
// assertion.
func TestTryPackFallsBackOnPrivateRR(t *testing.T) {
	const privateType = 0xFF70
	dns.PrivateHandle("TESTPRIV", privateType, func() dns.PrivateRdata {
		return new(testPrivateRdata)
	})
	defer dns.PrivateHandleRemove(privateType)

	rr := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: privateType,
			Class: dns.ClassINET, Ttl: 300,
		},
		Data: &testPrivateRdata{data: "abc"},
	}
	for _, tc := range []struct {
		name   string
		record dns.RR
	}{
		{"bare", rr},
		{"wrapped", wrappedRR{rr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			m.Compress = true
			m.Answer = []dns.RR{
				mustPackRR(t, "example.com. 300 IN A 192.0.2.1"), tc.record,
			}
			handled, err := TryPack(m, func([]byte) error { return nil })
			if handled || err != nil {
				t.Fatalf("handled=%v err=%v, want a fallback", handled, err)
			}
			if _, err := m.Pack(); err != nil {
				t.Fatalf("fixture is wrong: the library cannot pack it "+
					"either: %v", err)
			}
		})
	}

	// The registry snapshot must not have admitted the private type even
	// though registration put it in dns.TypeToRR.
	if _, admitted := builtinRR[reflect.TypeFor[*dns.PrivateRR]()]; admitted {
		t.Fatal("*dns.PrivateRR is in the admission set")
	}
}

// TestTryPackHandlesEveryRegisteredType sweeps the library's whole registry:
// every record type the library defines, packed through both paths. Where
// the library packs a zero-value record, this must produce the same bytes;
// where it errors, this must have fallen back or errored the same way.
func TestTryPackHandlesEveryRegisteredType(t *testing.T) {
	handledCount := 0
	for rrtype, newRR := range dns.TypeToRR {
		rr := newRR()
		if _, private := rr.(*dns.PrivateRR); private {
			continue
		}
		hdr := rr.Header()
		hdr.Name = "example.com."
		hdr.Rrtype = rrtype
		hdr.Class = dns.ClassINET
		hdr.Ttl = 300

		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		m.Compress = true
		m.Answer = []dns.RR{rr}

		want, wantErr := libraryPack(t, m)
		var got []byte
		handled, err := TryPack(m, func(body []byte) error {
			got = append([]byte(nil), body...)
			return nil
		})
		if err != nil {
			t.Fatalf("type %d: consume error: %v", rrtype, err)
		}
		if !handled {
			continue
		}
		handledCount++
		if wantErr != nil {
			t.Fatalf("type %d: handled a record the library rejects: %v",
				rrtype, wantErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("type %d: bytes differ from the library", rrtype)
		}
	}
	// The sweep is meaningless if everything fell back.
	if handledCount < len(dns.TypeToRR)/2 {
		t.Fatalf("only %d of %d registered types were handled",
			handledCount, len(dns.TypeToRR))
	}
}

type testPrivateRdata struct{ data string }

func (r *testPrivateRdata) String() string         { return r.data }
func (r *testPrivateRdata) Parse(s []string) error { r.data = strings.Join(s, " "); return nil }
func (r *testPrivateRdata) Len() int               { return len(r.data) }
func (r *testPrivateRdata) Pack(buf []byte) (int, error) {
	return copy(buf, r.data), nil
}
func (r *testPrivateRdata) Unpack(data []byte) (int, error) {
	r.data = string(data)
	return len(data), nil
}
func (r *testPrivateRdata) Copy(dest dns.PrivateRdata) error {
	d, ok := dest.(*testPrivateRdata)
	if !ok {
		return dns.ErrRdata
	}
	d.data = r.data
	return nil
}

// sizedMessage builds an uncompressed message whose packed length is exactly
// target, by tuning one TXT string. With compression off the library's Len is
// the packed length, so the tuning is exact.
func sizedMessage(tb testing.TB, target int) *dns.Msg {
	tb.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	m.Compress = false
	for m.Len() < target-250 {
		m.Answer = append(m.Answer, mustPackRR(tb,
			`example.com. 300 IN TXT "`+strings.Repeat("x", 200)+`"`))
	}
	// The tuning record costs its owner (13), fixed fields (10) and the
	// string's length octet on top of the padding itself.
	pad := target - m.Len() - 24
	if pad < 0 || pad > 255 {
		tb.Fatalf("fixture is wrong: pad %d for target %d", pad, target)
	}
	m.Answer = append(m.Answer, mustPackRR(tb,
		`example.com. 300 IN TXT "`+strings.Repeat("y", pad)+`"`))
	if m.Len() != target {
		tb.Fatalf("fixture is wrong: built %d bytes, want %d", m.Len(), target)
	}
	return m
}

// TestTryPackBufferBoundary pins the pooled buffer's edge: one byte under
// fits, the exact size fits, one byte over falls back — and a zero-RDATA
// record arriving exactly at the boundary is refused by the guard, not
// half-written.
func TestTryPackBufferBoundary(t *testing.T) {
	for _, target := range []int{packBufferSize - 1, packBufferSize} {
		msg := sizedMessage(t, target)
		want, err := libraryPack(t, msg)
		if err != nil {
			t.Fatalf("%d bytes: %v", target, err)
		}
		got, handled := tryPackBytes(t, msg)
		if !handled {
			t.Fatalf("%d bytes: fell back though it fits", target)
		}
		if len(got) != target || !bytes.Equal(got, want) {
			t.Fatalf("%d bytes: packed %d and they differ", target, len(got))
		}
	}

	over := sizedMessage(t, packBufferSize+1)
	if _, handled := tryPackBytes(t, over); handled {
		t.Fatalf("%d bytes: handled a message larger than the buffer",
			packBufferSize+1)
	}

	// A zero-RDATA record at exactly the boundary: the message before it
	// fills the buffer completely, so the guard must turn it away before
	// PackRR sees an empty window.
	edge := sizedMessage(t, packBufferSize)
	edge.Answer = append(edge.Answer, &dns.ANY{Hdr: dns.RR_Header{
		Name: ".", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}})
	got, handled := tryPackBytes(t, edge)
	if handled {
		if len(got) <= packBufferSize {
			t.Fatalf("a zero-RDATA record past the boundary was absorbed "+
				"into %d bytes", len(got))
		}
		t.Fatalf("handled a message that cannot fit")
	}
	// And it still packs correctly, one byte at a time smaller: the same
	// shape inside the buffer is fine.
	inside := sizedMessage(t, packBufferSize-11)
	inside.Answer = append(inside.Answer, &dns.ANY{Hdr: dns.RR_Header{
		Name: ".", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}})
	want, err := libraryPack(t, inside)
	if err != nil {
		t.Fatalf("inside: %v", err)
	}
	got, handled = tryPackBytes(t, inside)
	if !handled || !bytes.Equal(got, want) {
		t.Fatalf("a zero-RDATA record at the last usable offset: handled=%v, "+
			"parity=%v", handled, bytes.Equal(got, want))
	}
}

// TestTryPackPointerBoundary covers the 0x3fff compression-offset limit
// through the fallback: a message whose names would first be pointable past
// it does not fit this buffer, so what matters is that the fallback triggers
// and the library path serves it. The parity of pointer arithmetic below the
// limit is the fuzzer's and corpus's job.
func TestTryPackPointerBoundary(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	m.Compress = true
	for i := range 300 {
		m.Answer = append(m.Answer, mustPackRR(t, fmt.Sprintf(
			`n%03d.example.com. 300 IN TXT "%s"`, i, strings.Repeat("x", 60))))
	}
	if m.Len() <= maxCompressionOffsetProbe {
		t.Fatalf("fixture is wrong: %d bytes does not cross the pointer limit",
			m.Len())
	}
	if _, handled := tryPackBytes(t, m); handled {
		t.Fatal("handled a message larger than the buffer")
	}
	if _, err := m.Pack(); err != nil {
		t.Fatalf("the library fallback fails too: %v", err)
	}
}

// maxCompressionOffsetProbe mirrors the library's 14-bit pointer ceiling for
// the boundary fixture's sanity check.
const maxCompressionOffsetProbe = 2 << 13

// TestTryPackPoolRetention is the retention gate: after any sequence of
// packs, nothing in the pool may still reference a message. The shim held the
// last record, the OPT copy held an option list, and the dictionary's keys
// are owner names.
func TestTryPackPoolRetention(t *testing.T) {
	for _, msg := range packCorpus(t) {
		msg.Compress = true
		_, _ = tryPackBytes(t, msg)
	}
	// A fallback that fails mid-message must release cleanly too.
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Compress = true
	m.Answer = []dns.RR{mustPackRR(t, "example.com. 300 IN A 192.0.2.1"), nil}
	if handled, _ := TryPack(m, func([]byte) error { return nil }); handled {
		t.Fatal("fixture is wrong: the nil record did not fall back")
	}

	var held []*packState
	for range 32 {
		state := packStatePool.Get().(*packState)
		if state.rr.RR != nil {
			t.Fatalf("the pool held a shim still referencing %T", state.rr.RR)
		}
		if state.rr.hdr != (dns.RR_Header{}) {
			t.Fatal("the pool held a shim with a header in it")
		}
		if state.opt.Option != nil || state.opt.Hdr.Rrtype != 0 {
			t.Fatal("the pool held an OPT copy with the caller's options")
		}
		if len(state.compression) != 0 {
			t.Fatalf("the pool held a dictionary with %d entries",
				len(state.compression))
		}
		held = append(held, state)
	}
	for _, state := range held {
		packStatePool.Put(state)
	}
}

// TestTryPackConsumerContract pins the callback semantics: the consumer's
// error is returned with handled=true (bytes may have left the process, the
// caller must not write twice), and a consumer panic still releases the
// state.
func TestTryPackConsumerContract(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = []dns.RR{mustPackRR(t, "example.com. 300 IN A 192.0.2.1")}
	msg.Compress = true

	sentinel := fmt.Errorf("transport failed")
	handled, err := TryPack(msg, func([]byte) error { return sentinel })
	if !handled || err != sentinel { //nolint:errorlint // identity is the contract
		t.Fatalf("handled=%v err=%v, want handled with the consumer's error",
			handled, err)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the consumer's panic was swallowed")
			}
		}()
		_, _ = TryPack(msg, func([]byte) error { panic("consumer") })
	}()
	// The state the panicking pack borrowed must be back and clean.
	state := packStatePool.Get().(*packState)
	if state.rr.RR != nil || len(state.compression) > maxPooledCompressionEntries {
		t.Fatal("a consumer panic leaked pack state")
	}
	packStatePool.Put(state)

	// After GC empties the pools, everything still works and still matches.
	// Twice: sync.Pool keeps a victim cache that survives one collection.
	runtime.GC()
	runtime.GC()
	want, err := libraryPack(t, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, handled := tryPackBytes(t, msg)
	if !handled || !bytes.Equal(got, want) {
		t.Fatal("bytes differ across a GC")
	}
}

// TestPackCloneFallbackDoesNotMutate pins the fallback's half of the
// immutability promise. The library's Pack writes the extended rcode into the
// caller's OPT; a message too large for the pooled buffer takes that path,
// and it must not be the one place the promise breaks — nor a data race when
// the message is shared.
func TestPackCloneFallbackDoesNotMutate(t *testing.T) {
	big := sizedMessage(t, packBufferSize+200)
	big.Rcode = dns.RcodeBadVers
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.Hdr.Ttl |= 0xAB << 24 // stale extended bits the pack would rewrite
	big.Extra = []dns.RR{opt}

	if handled, _ := TryPack(big, func([]byte) error { return nil }); handled {
		t.Fatal("fixture is wrong: the oversized message did not fall back")
	}

	before := messageFingerprint(big)
	want, err := libraryPack(t, big)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 8)
	for range 8 {
		go func() {
			for range 50 {
				got, err := PackClone(big)
				if err != nil {
					done <- err
					return
				}
				if !bytes.Equal(got, want) {
					done <- fmt.Errorf("fallback clone differs from the library")
					return
				}
			}
			done <- nil
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if after := messageFingerprint(big); after != before {
		t.Fatalf("the fallback modified the message\nbefore: %s\nafter:  %s",
			before, after)
	}
}

// TestPackCloneInvalidRcodeIsTheLibrarysError pins the validation order. The
// library checks the rcode before it goes looking for an OPT; a fallback
// that looked first would panic on a nil record in Extra where the library
// reports its error.
func TestPackCloneInvalidRcodeIsTheLibrarysError(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Rcode = 0x1000
	m.Extra = []dns.RR{nil}

	// The reference carries the same rcode without the nil: the library
	// errors before it touches Extra, which is the ordering under test.
	reference := new(dns.Msg)
	reference.SetQuestion("example.com.", dns.TypeA)
	reference.Rcode = 0x1000
	_, wantErr := reference.Pack()
	if wantErr == nil {
		t.Fatal("fixture is wrong: the library accepts rcode 0x1000")
	}
	_, err := PackClone(m)
	if err == nil || err.Error() != wantErr.Error() {
		t.Fatalf("PackClone error %v, library says %v", err, wantErr)
	}
}

// TestPackCloneOPTAliasedAcrossSections pins the fallback against an OPT
// whose pointer appears outside Extra as well. The library packs the one
// object with its rewritten TTL wherever it occurs; a fallback that copied
// only Extra would emit the stale TTL in the other sections.
func TestPackCloneOPTAliasedAcrossSections(t *testing.T) {
	big := sizedMessage(t, packBufferSize+200)
	big.Rcode = dns.RcodeBadVers
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.Hdr.Ttl |= 0xAB << 24
	big.Answer = append(big.Answer, opt)
	big.Ns = []dns.RR{opt}
	big.Extra = []dns.RR{opt}

	if handled, _ := TryPack(big, func([]byte) error { return nil }); handled {
		t.Fatal("fixture is wrong: the oversized message did not fall back")
	}

	before := messageFingerprint(big)
	want, err := libraryPack(t, big)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PackClone(big)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("an OPT aliased outside Extra packed differently from the " +
			"library; a section still carries the stale TTL")
	}
	if after := messageFingerprint(big); after != before {
		t.Fatal("the fallback modified the message")
	}
}

// TestPackClonePrivateRRKeepsLibrarySemantics pins the boundary of the
// immutability promise. A PrivateRR packs through registrant code that can
// observe anything, including the OPT the library mutates before packing it —
// exact bytes and immutability cannot both be promised there, and parity
// wins: the message keeps the library's own semantics, mutation included.
func TestPackClonePrivateRRKeepsLibrarySemantics(t *testing.T) {
	const privateType = 0xFF71
	dns.PrivateHandle("TESTPRIV2", privateType, func() dns.PrivateRdata {
		return new(testPrivateRdata)
	})
	defer dns.PrivateHandleRemove(privateType)

	build := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		// Pinned: SetQuestion draws a random ID, and this test builds the
		// message twice to compare two packs of the same thing.
		m.Id = 42
		m.Rcode = dns.RcodeBadVers
		m.Answer = []dns.RR{&dns.PrivateRR{
			Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: privateType,
				Class: dns.ClassINET, Ttl: 300,
			},
			Data: &testPrivateRdata{data: "abc"},
		}}
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(1232)
		m.Extra = []dns.RR{opt}
		return m
	}

	reference := build()
	want, err := reference.Pack()
	if err != nil {
		t.Fatalf("library: %v", err)
	}

	msg := build()
	got, err := PackClone(msg)
	if err != nil {
		t.Fatalf("PackClone: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("a PrivateRR message packed differently from the library")
	}
	// Library semantics means the library's write happened: the caller's OPT
	// carries the extended rcode, exactly as it would after msg.Pack.
	if msg.IsEdns0().Hdr.Ttl != reference.IsEdns0().Hdr.Ttl {
		t.Fatal("the OPT was not mutated the way the library mutates it")
	}
}

// TestPackClone pins the owning wrapper: exact size, caller-owned, and the
// same bytes whichever path produced them.
func TestPackClone(t *testing.T) {
	for i, msg := range packCorpus(t) {
		msg.Compress = true
		want, err := libraryPack(t, msg)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		got, err := PackClone(msg)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d: clone differs from the library", i)
		}
		if cap(got) != len(got) {
			t.Fatalf("message %d: clone has %d bytes of slack; entries keep "+
				"what they are handed", i, cap(got)-len(got))
		}
	}

	// Larger than the pooled buffer: the fallback packs it, still exact.
	big := sizedMessage(t, packBufferSize+64)
	want, err := libraryPack(t, big)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PackClone(big)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || cap(got) != len(got) {
		t.Fatalf("oversized clone: parity=%v slack=%d",
			bytes.Equal(got, want), cap(got)-len(got))
	}

	// The clone must be the caller's alone: packing other messages through
	// the same pool afterwards cannot change it.
	msg := packCorpus(t)[0]
	msg.Compress = true
	clone, err := PackClone(msg)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := append([]byte(nil), clone...)
	for _, other := range packCorpus(t) {
		other.Compress = true
		_, _ = tryPackBytes(t, other)
	}
	if !bytes.Equal(clone, snapshot) {
		t.Fatal("a clone changed after the pool was reused")
	}
}

func BenchmarkTryPack(b *testing.B) {
	sink := 0
	consume := func(body []byte) error { sink = len(body); return nil }
	for i, msg := range packCorpus(b) {
		msg.Compress = true
		name := fmt.Sprintf("message=%d", i)

		b.Run(name+"/owned", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				handled, err := TryPack(msg, consume)
				if err != nil || !handled {
					b.Fatalf("handled=%v err=%v", handled, err)
				}
			}
		})
		b.Run(name+"/library", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := msg.Pack(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	_ = sink
}

// FuzzPackMsg compares against the library over messages nobody thought to
// write down. An earlier round of this found the multi-question compression
// rule; its input is in the corpus.
func FuzzPackMsg(f *testing.F) {
	for _, msg := range packCorpus(f) {
		msg.Compress = true
		if packed, err := msg.Copy().Pack(); err == nil {
			f.Add(packed)
		}
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		var msg dns.Msg
		if err := msg.Unpack(in); err != nil {
			return
		}
		for _, compress := range []bool{false, true} {
			msg.Compress = compress
			before := messageFingerprint(&msg)

			want, wantErr := msg.Copy().Pack()

			var got []byte
			handled, err := TryPack(&msg, func(body []byte) error {
				got = append([]byte(nil), body...)
				return nil
			})
			if err != nil {
				t.Fatalf("compress=%v: consume error: %v", compress, err)
			}
			if !handled {
				// A fallback needs a reason. Everything Unpack produces is a
				// library type with an in-range rcode, so the legitimate
				// reasons are size and an input the library itself cannot
				// pack — Unpack accepts rdata that Pack refuses, an empty
				// ALPN in an SVCB for one. A packer drifting toward blanket
				// fallback fails loudly instead of passing quietly.
				if wantErr != nil {
					continue
				}
				probe := msg
				probe.Compress = false
				if probe.Len() <= packBufferSize {
					t.Fatalf("compress=%v: fell back on a handleable message",
						compress)
				}
				continue
			}
			if wantErr != nil {
				t.Fatalf("compress=%v: packed where the library errors: %v",
					compress, wantErr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("compress=%v: bytes differ from the library",
					compress)
			}
			if after := messageFingerprint(&msg); after != before {
				t.Fatalf("compress=%v: packing modified the message", compress)
			}
		}
	})
}
