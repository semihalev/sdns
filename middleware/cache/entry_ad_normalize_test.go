package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestEntryDropsADOverLapsedSignatures pins the defence in depth at the
// packing seam: the response writer clears AD on the message it sends after
// the stores have run, so an entry admitted with the bit set over data whose
// signatures have lapsed would hand AD back on every later hit. The storable
// view is normalised before packing, whatever path admitted it.
func TestEntryDropsADOverLapsedSignatures(t *testing.T) {
	now := time.Now()
	const name = "lapsed.example."

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.AuthenticatedData = true
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 1},
		},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeA,
			Algorithm:   8,
			Labels:      2,
			OrigTtl:     300,
			Expiration:  uint32(now.Add(-time.Hour).Unix()),     //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			KeyTag:      1,
			SignerName:  "example.",
			Signature:   "MTIzNDU2Nzg5MGFiY2RlZg==",
		},
	}

	entry := NewCacheEntryWithKey(resp, time.Minute, 0, 0)
	if entry == nil {
		t.Fatal("entry not built")
	}
	served := entry.ToMsg(req)
	if served == nil {
		t.Fatal("entry did not serve")
	}
	if served.AuthenticatedData {
		t.Fatal("the entry kept AD over data whose signature had lapsed")
	}
	if !resp.AuthenticatedData {
		t.Fatal("normalisation reached the caller's message; only the storable view may change")
	}
}
