package cache

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// admissionMsg builds the response shape admission actually stores: a signed
// answer with authority material and an OPT to be filtered out. No EDE and
// no glue — an entry carrying either is not byte-servable (established
// behavior: prepareWireServe wants ARCOUNT==0 and no EDE) and would get no
// stripped body, which is half of what this exercises.
func admissionMsg(tb testing.TB) *dns.Msg {
	tb.Helper()
	rr := func(s string) dns.RR {
		tb.Helper()
		r, err := dns.NewRR(s)
		if err != nil {
			tb.Fatalf("NewRR(%q): %v", s, err)
		}
		return r
	}

	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.Id = 7 // pinned: admission stores the message as handed over
	m.Response = true
	m.AuthenticatedData = true
	// Validity relative to now: a fixed expiration lapsed one day, and an
	// entry admitted with AD over a lapsed signature has the bit normalised
	// away, which is a different wire from the reference.
	now := time.Now()
	m.Answer = []dns.RR{
		rr("www.example.com. 300 IN A 192.0.2.1"),
		rr(fmt.Sprintf("www.example.com. 300 IN RRSIG A 8 3 300 %s %s 12345 example.com. AwEAAcQ8",
			dns.TimeToString(uint32(now.Add(30*24*time.Hour).Unix())),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			dns.TimeToString(uint32(now.Add(-30*24*time.Hour).Unix())), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		)),
	}
	m.Ns = []dns.RR{
		rr("example.com. 3600 IN NS ns1.example.com."),
		rr("example.com. 3600 IN NSEC z.example.com. NS RRSIG NSEC"),
	}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	m.Extra = []dns.RR{opt}
	return m
}

// TestAdmissionPacksIdentically pins that moving admission onto the pooled
// packer changed no stored byte: the entry's wire and stripped bodies must be
// exactly what the library produced for the same assembled message.
func TestAdmissionPacksIdentically(t *testing.T) {
	msg := admissionMsg(t)
	entry := NewCacheEntryWithKey(msg, time.Minute, 0, 1)
	if entry == nil {
		t.Fatal("admission refused the fixture")
	}

	// The reference is the pre-change path, assembled the same way: OPT
	// filtered from Extra, compression on, packed by the library.
	reference := new(dns.Msg)
	reference.MsgHdr = msg.MsgHdr
	reference.Question = msg.Question
	reference.Answer = msg.Answer
	reference.Ns = msg.Ns
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			reference.Extra = append(reference.Extra, rr)
		}
	}
	reference.Compress = true
	wantWire, err := reference.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry.wire, wantWire) {
		t.Fatal("the stored wire differs from a library pack of the same message")
	}
	if cap(entry.wire) != len(entry.wire) {
		t.Fatalf("the stored wire carries %d bytes of slack",
			cap(entry.wire)-len(entry.wire))
	}

	if entry.stripped == nil {
		t.Fatal("fixture is wrong: a signed answer produced no stripped body")
	}
	var strippedRef dns.Msg
	if err := strippedRef.Unpack(entry.stripped); err != nil {
		t.Fatalf("the stripped body does not unpack: %v", err)
	}
	for _, rr := range strippedRef.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			t.Fatal("the stripped body still carries a signature")
		}
	}
	if cap(entry.stripped) != len(entry.stripped) {
		t.Fatalf("the stripped body carries %d bytes of slack",
			cap(entry.stripped)-len(entry.stripped))
	}
}

// TestAdmissionOversizedFallsBackToTheLibrary pins the boundary: a response
// larger than the packer's pooled buffer must still be admitted, through the
// library, with the same exact-size retention.
func TestAdmissionOversizedFallsBackToTheLibrary(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeTXT)
	msg.Response = true
	for i := range 120 {
		rr, err := dns.NewRR(fmt.Sprintf(
			`n%03d.example.com. 300 IN TXT "%s"`, i, strings.Repeat("x", 60)))
		if err != nil {
			t.Fatal(err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	probe := *msg
	probe.Compress = false
	if probe.Len() <= 4096 {
		t.Fatalf("fixture is wrong: %d bytes fits the pooled buffer", probe.Len())
	}

	entry := NewCacheEntryWithKey(msg, time.Minute, 0, 1)
	if entry == nil {
		t.Fatal("an oversized response was refused admission")
	}
	var back dns.Msg
	if err := back.Unpack(entry.wire); err != nil {
		t.Fatalf("the stored wire does not unpack: %v", err)
	}
	if len(back.Answer) != len(msg.Answer) {
		t.Fatalf("stored %d answers, want %d", len(back.Answer), len(msg.Answer))
	}
	if cap(entry.wire) != len(entry.wire) {
		t.Fatalf("the oversized wire carries %d bytes of slack",
			cap(entry.wire)-len(entry.wire))
	}
}

// BenchmarkCacheAdmission measures a whole admission — assembly, both packs,
// the entry. This file compiles unchanged against the pre-packer tree, which
// is how the before/after comparison is taken: the same benchmark, run on
// both.
func BenchmarkCacheAdmission(b *testing.B) {
	msg := admissionMsg(b)
	b.ReportAllocs()
	for b.Loop() {
		if NewCacheEntryWithKey(msg, time.Minute, 0, 1) == nil {
			b.Fatal("admission refused")
		}
	}
}
