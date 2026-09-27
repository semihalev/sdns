package cache

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// relocTemplate is the signed cut fixture's full template: its body, where
// its authority section starts, and its relocation table.
func relocTemplate(t *testing.T) (*nxDomainCutEntry, int) {
	t.Helper()
	_, cut := clockCut(t, lease.Lease{}, lease.Lease{})
	if cut.wireFull == nil {
		t.Fatal("the fixture's cut has no wire template")
	}
	if len(cut.wireFullReloc.ptrs) == 0 {
		t.Fatal("bad fixture: the template holds no pointer to relocate")
	}
	q, ok := wire.ParseQuestion(cut.wireFull, wire.HeaderLen)
	if !ok {
		t.Fatal("template question does not parse")
	}
	return cut, q.End
}

// The authority section relocated behind a question of any length reads
// back as the records the template holds, at the stamped TTL: behind a
// longer question, the pointers move forward, and behind none at all, they
// move back.
func TestCutRelocationMovesPointersEitherWay(t *testing.T) {
	cut, authStart := relocTemplate(t)
	want := new(dns.Msg)
	if err := want.Unpack(cut.wireFull); err != nil {
		t.Fatal(err)
	}
	nscount := binary.BigEndian.Uint16(cut.wireFull[8:10])

	for _, tc := range []struct {
		name     string
		question string // "" is a message without a question
	}{
		{"no question, pointers move back", ""},
		{"the root, pointers stay", "."},
		{"a long question, pointers move forward", "a.very.long.descendant.of.the.missing.secure.example."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, wire.HeaderLen, 4096)
			qd := uint16(0)
			if tc.question != "" {
				q := new(dns.Msg)
				q.SetQuestion(tc.question, dns.TypeA)
				packed, err := q.Pack()
				if err != nil {
					t.Fatal(err)
				}
				dst = append(dst, packed[wire.HeaderLen:]...)
				qd = 1
			}
			binary.BigEndian.PutUint16(dst[4:6], qd)
			binary.BigEndian.PutUint16(dst[8:10], nscount)
			if shift := len(dst) - authStart; (tc.question == "") != (shift < 0) {
				t.Fatalf("bad fixture: shift %d", shift)
			}

			body, ok := relocateAuthority(dst, cut.wireFull, authStart, cut.wireFullReloc, 77)
			if !ok {
				t.Fatal("relocation refused")
			}
			got := new(dns.Msg)
			if err := got.Unpack(body); err != nil {
				t.Fatalf("relocated body does not unpack: %v", err)
			}
			if len(got.Ns) != len(want.Ns) {
				t.Fatalf("%d authority records, want %d", len(got.Ns), len(want.Ns))
			}
			for i := range want.Ns {
				w, g := dns.Copy(want.Ns[i]), got.Ns[i]
				w.Header().Ttl = 77
				if g.String() != w.String() {
					t.Fatalf("record %d:\n got  %v\n want %v", i, g, w)
				}
			}
		})
	}
}

// A pointer is fourteen bits: a relocation that would move one past 0x3FFF
// refuses rather than write a pointer that wraps, and one that lands exactly
// on it is written.
func TestCutRelocationRefusesPastThePointerRange(t *testing.T) {
	const authStart, target = 17, 0x3FF0
	tmpl := make([]byte, authStart+2)
	binary.BigEndian.PutUint16(tmpl[authStart:], 0xC000|target)
	r := cutRelocation{ptrs: []uint16{authStart}}

	for _, tc := range []struct {
		shift int
		ok    bool
	}{
		{0x3FFF - target, true},
		{0x3FFF - target + 1, false},
	} {
		dst := make([]byte, authStart+tc.shift, authStart+tc.shift+2)
		body, ok := relocateAuthority(dst, tmpl, authStart, r, 0)
		if ok != tc.ok {
			t.Fatalf("shift %d: ok = %v, want %v", tc.shift, ok, tc.ok)
		}
		if ok {
			if got := binary.BigEndian.Uint16(body[authStart+tc.shift:]); got != 0xC000|0x3FFF {
				t.Fatalf("shift %d: pointer %#04x, want %#04x", tc.shift, got, 0xC000|0x3FFF)
			}
		}
	}
}

// A template whose pointer reaches into its question is refused at record
// time: at serve time that question is the client's.
func TestCutRelocationRefusesAPointerIntoTheQuestion(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("missing.secure.example.", dns.TypeSOA)
	m.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: "secure.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns1.secure.example.", Mbox: "hostmaster.secure.example.", Minttl: 300,
	}}
	m.Compress = true
	body, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cutRelocationOf(body); ok {
		t.Fatal("a template pointing into its question was accepted")
	}
}

// The cut's NXDOMAIN on the byte path carries its proof compressed, as it
// was packed, and each of its names reads back.
func TestComposedCutIsNameCompressed(t *testing.T) {
	for _, do := range []bool{false, true} {
		c, _ := clockCut(t, lease.Lease{}, lease.Lease{})
		req, _ := wireTestRequest(t, "child."+nxCutDeniedName, dns.TypeA, do)
		w := &captureSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
		ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			ch.Cancel()
		})})
		before := wireCutServed.Value()
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(context.Background())
		if wireCutServed.Value() == before || w.last == nil {
			t.Fatalf("DO=%v: the cut was not composed on the byte path", do)
		}
		got := new(dns.Msg)
		if err := got.Unpack(w.last); err != nil {
			t.Fatalf("DO=%v: composed reply does not unpack: %v", do, err)
		}
		if got.Rcode != dns.RcodeNameError || len(got.Ns) == 0 {
			t.Fatalf("DO=%v: %s with %d authority records, want the proof", do, dns.RcodeToString[got.Rcode], len(got.Ns))
		}
		uncompressed := got.Copy()
		uncompressed.Compress = false
		if full := uncompressed.Len(); len(w.last) >= full {
			t.Fatalf("DO=%v: composed reply is %d bytes, the same records uncompressed are %d", do, len(w.last), full)
		}
	}
}
