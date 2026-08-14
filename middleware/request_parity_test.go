package middleware

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// FuzzParseWireMatchesLibrary is the strict parser's admission contract:
// a packet it accepts must be one the library also accepts, and the facts
// it reports must be the ones the library decodes.
//
// The direction matters. Refusing something the library would take is
// free — the request simply decodes and takes the ordinary path. Taking
// something the library would reject is not: such a packet would be
// answered from cache, or dropped silently, where the server owes the
// client a FORMERR.
func FuzzParseWireMatchesLibrary(f *testing.F) {
	seed := func(build func(m *dns.Msg)) {
		m := new(dns.Msg)
		m.SetQuestion("seed.example.", dns.TypeA)
		build(m)
		if raw, err := m.Pack(); err == nil {
			f.Add(raw)
		}
	}
	seed(func(*dns.Msg) {})
	seed(func(m *dns.Msg) { m.SetEdns0(1232, true) })
	seed(func(m *dns.Msg) { m.SetEdns0(512, false) })
	seed(func(m *dns.Msg) {
		m.SetEdns0(1232, true)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
			Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef",
		})
	})
	seed(func(m *dns.Msg) {
		m.SetEdns0(1232, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
			Address: []byte{192, 0, 2, 0},
		})
	})
	seed(func(m *dns.Msg) {
		m.SetEdns0(1232, true)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	})

	f.Fuzz(func(t *testing.T, raw []byte) {
		r := new(Request)
		if !r.ParseWire(raw, time.Now(), nil) {
			return // refused: the decoded path handles it, nothing to check
		}

		decoded := new(dns.Msg)
		if err := decoded.Unpack(raw); err != nil {
			t.Fatalf("accepted a packet the library rejects (%v): %x", err, raw)
		}
		if len(decoded.Question) != 1 {
			t.Fatalf("accepted a packet with %d questions: %x", len(decoded.Question), raw)
		}

		q := decoded.Question[0]
		if r.Qtype() != q.Qtype || r.Qclass() != q.Qclass {
			t.Fatalf("question mismatch: parsed %d/%d, decoded %d/%d",
				r.Qtype(), r.Qclass(), q.Qtype, q.Qclass)
		}
		if r.ID() != decoded.Id || r.RD() != decoded.RecursionDesired ||
			r.CD() != decoded.CheckingDisabled || r.AD() != decoded.AuthenticatedData ||
			r.Opcode() != decoded.Opcode {
			t.Fatalf("header mismatch on %x", raw)
		}

		opt := decoded.IsEdns0()
		if r.HasOPT() != (opt != nil) {
			t.Fatalf("OPT presence mismatch: parsed %v, decoded %v", r.HasOPT(), opt != nil)
		}
		if opt == nil {
			return
		}
		if r.DO() != opt.Do() || r.UDPSize() != opt.UDPSize() || r.EDNSVersion() != opt.Version() {
			t.Fatalf("OPT facts mismatch: parsed do=%v size=%d ver=%d, decoded do=%v size=%d ver=%d",
				r.DO(), r.UDPSize(), r.EDNSVersion(), opt.Do(), opt.UDPSize(), opt.Version())
		}

		var wantECS, wantNSID bool
		for _, o := range opt.Option {
			switch o.Option() {
			case dns.EDNS0SUBNET:
				wantECS = true
			case dns.EDNS0NSID:
				wantNSID = true
			}
		}
		if r.HasECS() != wantECS || r.HasNSID() != wantNSID {
			t.Fatalf("option flags mismatch: parsed ecs=%v nsid=%v, decoded ecs=%v nsid=%v",
				r.HasECS(), r.HasNSID(), wantECS, wantNSID)
		}
	})
}
