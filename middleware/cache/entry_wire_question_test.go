package cache

import (
	"bytes"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/wire"
)

// TestEntryQuestionMatchesPackedName pins the invariant the byte path's
// spelling shortcut rests on. serveWire skips re-encoding the question when
// the client's name equals the entry's retained question name, taking that
// as proof the packed bytes already carry the client's spelling. That holds
// only because both come from one message and neither is rewritten
// afterwards. Should a future constructor ever let the two drift, the byte
// path would echo a spelling the client never sent — so the agreement is
// asserted here rather than left as a property of the code that built it.
func TestEntryQuestionMatchesPackedName(t *testing.T) {
	names := []struct {
		name  string
		qtype uint16
	}{
		{"plain.example.com.", dns.TypeA},
		{"MiXeD.ExAmPlE.CoM.", dns.TypeA},
		{`esc\.aped.example.com.`, dns.TypeA},
		{`\255.example.com.`, dns.TypeA},
		{".", dns.TypeNS},
	}

	for _, tc := range names {
		t.Run(tc.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion(tc.name, tc.qtype)
			msg.Response = true

			entry := NewCacheEntry(msg, time.Minute, 0)
			if entry == nil {
				t.Fatal("entry not built")
			}

			if entry.question.Name != tc.name {
				t.Fatalf("retained question %q, want %q", entry.question.Name, tc.name)
			}

			question, ok := wire.ParseQuestion(entry.wire, wire.HeaderLen)
			if !ok {
				t.Fatal("stored bytes carry no parseable question")
			}
			stored := entry.wire[wire.HeaderLen : wire.HeaderLen+question.NameLen]

			var buf [255]byte
			n, err := dns.PackDomainName(entry.question.Name, buf[:], 0, nil, false)
			if err != nil {
				t.Fatalf("packing the retained name: %v", err)
			}
			if !bytes.Equal(stored, buf[:n]) {
				t.Fatalf("packed question in the stored bytes is %v, but the "+
					"retained question name encodes to %v; the byte path's "+
					"spelling shortcut would echo the wrong name",
					stored, buf[:n])
			}
		})
	}
}

// TestWireFastPathEscapedNameEcho drives an escaped name through the byte
// path end to end. The shortcut compares presentation names, so an escaped
// name that matches exactly is served without re-encoding — the reply must
// still carry the client's name unchanged.
func TestWireFastPathEscapedNameEcho(t *testing.T) {
	const qname = `esc\.aped.example.com.`
	entry := wireFastEntry(t, qname, dns.TypeA, false)
	c, e := wireFastTestPipeline(t, entry)

	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	req.Id = 11
	req.RecursionDesired = true
	req.SetEdns0(1232, true)

	servedBefore := wireFastServed.Value()
	resp := serveThrough(t, c, e, req, false)
	if wireFastServed.Value() == servedBefore {
		t.Fatal("an exactly-matching escaped name should be served as bytes")
	}
	if got := resp.Question[0].Name; got != qname {
		t.Fatalf("question echo = %q, want %q", got, qname)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("no answer returned")
	}
}
