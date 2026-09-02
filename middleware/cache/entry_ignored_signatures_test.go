package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestHitDoesNotReviveSignaturesTheEntryIgnores pins the stored view against
// the hit paths. The entry's lifetime is bounded by its usable signatures
// alone, and every hit path serves each record with the entry's remaining
// lifetime as its TTL — so a signature the lifetime ignores, if stored,
// comes back inflated: a lapsed sibling received with TTL 0 as an hour, a
// glue signature the same, and one whose inception has not arrived revived
// once it has. None of them are stored.
func TestHitDoesNotReviveSignaturesTheEntryIgnores(t *testing.T) {
	now := time.Now()
	const name = "rollover.example."
	sig := func(owner string, hdrTTL uint32, tag uint16, from, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdrTTL},
			TypeCovered: dns.TypeA,
			Algorithm:   8,
			Labels:      2,
			OrigTtl:     3600,
			KeyTag:      tag,
			SignerName:  "example.",
			Signature:   "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:   uint32(now.Add(from).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration:  uint32(now.Add(until).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	a := func(owner string) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		}
	}

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		a(name),
		sig(name, 0, 111, -2*time.Hour, -time.Hour),   // lapsed sibling, TTL 0
		sig(name, 3600, 222, -2*time.Hour, time.Hour), // the live one
		sig(name, 0, 333, time.Hour, 2*time.Hour),     // not yet valid
	}
	resp.Extra = []dns.RR{
		a("ns.example."),
		sig("ns.example.", 0, 444, -2*time.Hour, time.Hour), // live glue signature, TTL 0
	}

	entry := NewCacheEntryWithKey(resp, time.Hour, 0, 0)
	if entry == nil {
		t.Fatal("entry not built")
	}
	served := entry.ToMsg(req)
	if served == nil {
		t.Fatal("entry did not serve")
	}

	var tags []uint16
	for _, rr := range served.Answer {
		if s, ok := rr.(*dns.RRSIG); ok {
			tags = append(tags, s.KeyTag)
			if s.Header().Ttl == 0 {
				t.Errorf("signature %d served with TTL 0", s.KeyTag)
			}
		}
	}
	if len(tags) != 1 || tags[0] != 222 {
		t.Fatalf("answer signatures served: %v, want only the live 222", tags)
	}
	if len(served.Extra) != 1 {
		t.Fatalf("additional section served %d records, want the glue alone", len(served.Extra))
	}
	if _, ok := served.Extra[0].(*dns.A); !ok {
		t.Fatalf("additional section served %T, want the glue address", served.Extra[0])
	}
	if len(resp.Answer) != 4 || len(resp.Extra) != 2 {
		t.Fatal("admission edited the caller's message; only the stored view may change")
	}
}

// TestStorableRecordsPassesTheCommonShapeThrough pins the price: a response
// with nothing to drop is stored from the caller's slice, not a copy.
func TestStorableRecordsPassesTheCommonShapeThrough(t *testing.T) {
	now := time.Now()
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeA, SignerName: "example.",
			Inception:  uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		},
	}
	kept := storableRecords(records, now)
	if len(kept) != len(records) || &kept[0] != &records[0] {
		t.Fatal("a response with nothing to drop was copied")
	}
	if allocs := testing.AllocsPerRun(100, func() { storableRecords(records, now) }); allocs != 0 {
		t.Errorf("common shape allocated %v times, want none", allocs)
	}
}
