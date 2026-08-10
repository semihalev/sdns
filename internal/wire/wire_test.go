package wire

import (
	"testing"

	"github.com/miekg/dns"
)

func packed(t *testing.T, build func(*dns.Msg)) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.com.", dns.TypeA)
	msg.Response = true
	build(msg)
	msg.Compress = true
	body, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return body
}

// TestCursorsAgreeWithFullDecode is the cursors' contract: whatever they
// report about a message must match what a complete decode would say.
func TestCursorsAgreeWithFullDecode(t *testing.T) {
	body := packed(t, func(m *dns.Msg) {
		m.AuthenticatedData = true
		m.Rcode = dns.RcodeNameError
		m.Answer = append(m.Answer, mustRR(t, "www.example.com. 300 IN CNAME edge.example.net."))
		m.Ns = append(m.Ns, mustRR(t, "example.net. 120 IN NS ns1.example.net."))
	})

	decoded := new(dns.Msg)
	if err := decoded.Unpack(body); err != nil {
		t.Fatalf("unpack: %v", err)
	}

	header, ok := ParseHeader(body)
	if !ok {
		t.Fatal("header refused")
	}
	if header.Rcode() != decoded.Rcode || header.AD() != decoded.AuthenticatedData {
		t.Fatalf("header: rcode %d/%d ad %v/%v",
			header.Rcode(), decoded.Rcode, header.AD(), decoded.AuthenticatedData)
	}
	if int(header.ANCount) != len(decoded.Answer) || int(header.NSCount) != len(decoded.Ns) {
		t.Fatalf("counts: an %d/%d ns %d/%d",
			header.ANCount, len(decoded.Answer), header.NSCount, len(decoded.Ns))
	}

	question, ok := ParseQuestion(body, HeaderLen)
	if !ok {
		t.Fatal("question refused")
	}
	if question.Qtype != decoded.Question[0].Qtype || question.Qclass != decoded.Question[0].Qclass {
		t.Fatal("question fields diverged")
	}

	// Walk every record and compare types and TTLs with the decode. This
	// also exercises compression pointers, which Pack emits for the
	// repeated owner names above.
	off := question.End
	for i := range int(header.ANCount) + int(header.NSCount) {
		rr, ok := ParseRR(body, off)
		if !ok {
			t.Fatalf("record %d refused at offset %d", i, off)
		}
		want := decoded.Answer
		idx := i
		if i >= len(decoded.Answer) {
			want, idx = decoded.Ns, i-len(decoded.Answer)
		}
		if rr.Type != want[idx].Header().Rrtype {
			t.Fatalf("record %d type %d, want %d", i, rr.Type, want[idx].Header().Rrtype)
		}
		SetTTL(body, rr.TTLOff, 42)
		off = rr.End
	}
	if off != len(body) {
		t.Fatalf("walk ended at %d, body is %d bytes", off, len(body))
	}

	repatched := new(dns.Msg)
	if err := repatched.Unpack(body); err != nil {
		t.Fatalf("patched body does not decode: %v", err)
	}
	for _, rr := range append(repatched.Answer, repatched.Ns...) {
		if rr.Header().Ttl != 42 {
			t.Fatalf("TTL patch missed %s", rr.Header().Name)
		}
	}
}

// TestApplyReplyMatchesSetReply pins the header shaping against miekg's own
// SetReply plus the cache's cleared AA.
func TestApplyReplyMatchesSetReply(t *testing.T) {
	for _, tc := range []struct{ rd, cd bool }{{true, true}, {true, false}, {false, true}, {false, false}} {
		body := packed(t, func(m *dns.Msg) {
			m.Authoritative = true // must be cleared
			m.Answer = append(m.Answer, mustRR(t, "www.example.com. 300 IN A 192.0.2.1"))
		})
		ApplyReply(body, 4242, dns.OpcodeQuery, tc.rd, tc.cd)

		got := new(dns.Msg)
		if err := got.Unpack(body); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if got.Id != 4242 || !got.Response || got.Authoritative {
			t.Fatalf("id=%d qr=%v aa=%v", got.Id, got.Response, got.Authoritative)
		}
		if got.RecursionDesired != tc.rd || got.CheckingDisabled != tc.cd {
			t.Fatalf("rd=%v cd=%v, want %v/%v",
				got.RecursionDesired, got.CheckingDisabled, tc.rd, tc.cd)
		}
	}
}

// TestCursorsRefuseMalformedInput pins the parsers' boundaries: every
// truncation and every illegal label form must be refused, never read past
// the buffer.
func TestCursorsRefuseMalformedInput(t *testing.T) {
	full := packed(t, func(m *dns.Msg) {
		m.Answer = append(m.Answer, mustRR(t, "www.example.com. 300 IN A 192.0.2.1"))
	})

	for n := range len(full) {
		truncated := full[:n]
		if _, ok := ParseHeader(truncated); ok && n < HeaderLen {
			t.Fatalf("header accepted %d bytes", n)
		}
		if n >= HeaderLen {
			if q, ok := ParseQuestion(truncated, HeaderLen); ok {
				if q.End > len(truncated) {
					t.Fatalf("question End %d past the %d-byte body", q.End, len(truncated))
				}
				if rr, ok := ParseRR(truncated, q.End); ok && rr.End > len(truncated) {
					t.Fatalf("record End %d past the %d-byte body", rr.End, len(truncated))
				}
			}
		}
	}

	// A reserved label type (0b10xxxxxx) is neither a length nor a pointer.
	reserved := append([]byte(nil), full...)
	reserved[HeaderLen] = 0x80
	if off := SkipName(reserved, HeaderLen); off != -1 {
		t.Fatalf("reserved label form accepted, returned %d", off)
	}

	// A name that never terminates must be refused rather than run off.
	unterminated := make([]byte, HeaderLen+4)
	unterminated[HeaderLen] = 3
	if off := SkipName(unterminated, HeaderLen); off != -1 {
		t.Fatalf("unterminated name accepted, returned %d", off)
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}
