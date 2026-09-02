package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func ignoredSigFixtures(now time.Time) (sig func(owner string, hdrTTL uint32, tag uint16, from, until time.Duration) dns.RR, a func(owner string) dns.RR) {
	sig = func(owner string, hdrTTL uint32, tag uint16, from, until time.Duration) dns.RR {
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
	a = func(owner string) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		}
	}
	return sig, a
}

func serveFromEntry(t *testing.T, req, resp *dns.Msg, ttl time.Duration) *dns.Msg {
	t.Helper()
	entry := NewCacheEntryWithKey(resp, ttl, 0, 0)
	if entry == nil {
		t.Fatal("entry not built")
	}
	served := entry.ToMsg(req)
	if served == nil {
		t.Fatal("entry did not serve")
	}
	return served
}

func sigTags(records []dns.RR) []uint16 {
	var tags []uint16
	for _, rr := range records {
		if s, ok := rr.(*dns.RRSIG); ok {
			tags = append(tags, s.KeyTag)
		}
	}
	return tags
}

func hasA(records []dns.RR, owner string) bool {
	for _, rr := range records {
		if r, ok := rr.(*dns.A); ok && r.Hdr.Name == owner {
			return true
		}
	}
	return false
}

// TestHitDoesNotReviveSignaturesTheEntryIgnores pins the stored view against
// the hit paths. The entry's lifetime is bounded by its usable signatures
// alone, and every hit path serves each record with the entry's remaining
// lifetime as its TTL, so a signature the lifetime ignores, if stored,
// comes back inflated: a lapsed sibling received with TTL 0 as an hour, and
// one whose inception has not arrived revived once it has. Neither is stored.
func TestHitDoesNotReviveSignaturesTheEntryIgnores(t *testing.T) {
	now := time.Now()
	sig, a := ignoredSigFixtures(now)
	const name = "rollover.example."

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

	served := serveFromEntry(t, req, resp, time.Hour)
	for _, rr := range served.Answer {
		if s, ok := rr.(*dns.RRSIG); ok && s.Header().Ttl == 0 {
			t.Errorf("signature %d served with TTL 0", s.KeyTag)
		}
	}
	if tags := sigTags(served.Answer); len(tags) != 1 || tags[0] != 222 {
		t.Fatalf("answer signatures served: %v, want only the live 222", tags)
	}
	if len(resp.Answer) != 4 {
		t.Fatal("admission edited the caller's message; only the stored view may change")
	}
}

// TestAdditionalRRsetTravelsWithItsSignature pins the additional section: a
// signed RRset there is kept with its signature or removed with it (RFC 4035
// §3.1.1), decided by whether the entry's lifetime can honour the signature.
// The section bounds neither AD nor the lifetime, and every hit serves it at
// the lifetime's TTL, so a signature permitting less would come back
// inflated. A mail exchanger's address is the shape: signed in the zone,
// carried as additional data.
func TestAdditionalRRsetTravelsWithItsSignature(t *testing.T) {
	now := time.Now()
	sig, a := ignoredSigFixtures(now)
	const name = "mx.example."

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeMX)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}, Preference: 10, Mx: "short.example."},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeMX, Algorithm: 8, Labels: 2, OrigTtl: 3600, KeyTag: 9,
			SignerName: "example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(time.Hour).Unix()),      //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		},
	}
	resp.Extra = []dns.RR{
		// Signed, but its signature permits less than the entry's hour.
		a("short.example."),
		sig("short.example.", 30, 444, -2*time.Hour, time.Hour),
		// Signed, and its signature permits the hour, with a lapsed
		// sibling beside it that leaves alone. Its validity runs past the
		// lifetime: the entry's clock is read after this fixture's, and
		// the comparison is exact.
		a("kept.example."),
		sig("kept.example.", 3600, 555, -2*time.Hour, 2*time.Hour),
		sig("kept.example.", 0, 556, -2*time.Hour, -time.Hour),
		// Unsigned, as real delegation glue is.
		a("glue.example."),
	}

	served := serveFromEntry(t, req, resp, time.Hour)
	if hasA(served.Extra, "short.example.") {
		t.Error("an RRset whose signature could not be honoured was served without it")
	}
	if !hasA(served.Extra, "kept.example.") {
		t.Error("an RRset whose signature could be honoured was dropped")
	}
	if !hasA(served.Extra, "glue.example.") {
		t.Error("unsigned glue was dropped")
	}
	if tags := sigTags(served.Extra); len(tags) != 1 || tags[0] != 555 {
		t.Errorf("additional signatures served: %v, want only 555", tags)
	}
	for _, rr := range served.Extra {
		if rr.Header().Ttl == 0 {
			t.Errorf("%s served with TTL 0", rr.Header().Name)
		}
	}
	if len(resp.Extra) != 6 {
		t.Fatal("admission edited the caller's message; only the stored view may change")
	}
}

// TestExplicitRRSIGQuestionIsStoredWholeOrNotAtAll pins the one question
// whose answer is the signatures themselves (RFC 4035 §3.2.1). A hit may not
// return fewer of them than the first response did, so an answer the stored
// view would thin is not stored, and one it would keep whole is.
func TestExplicitRRSIGQuestionIsStoredWholeOrNotAtAll(t *testing.T) {
	now := time.Now()
	sig, _ := ignoredSigFixtures(now)
	const name = "signed.example."

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeRRSIG)
	req.SetEdns0(1232, true)
	req.CheckingDisabled = true

	t.Run("lapsed and pending signatures keep the answer out of the cache", func(t *testing.T) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{
			sig(name, 3600, 111, -2*time.Hour, -time.Hour),
			sig(name, 3600, 222, -2*time.Hour, time.Hour),
			sig(name, 3600, 333, time.Hour, 2*time.Hour),
		}
		if entry := NewCacheEntryWithKey(resp, time.Hour, 0, 0); entry != nil {
			t.Fatal("an RRSIG answer the stored view would thin was cached")
		}
	})

	t.Run("an answer of live signatures is cached whole", func(t *testing.T) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{
			sig(name, 3600, 222, -2*time.Hour, time.Hour),
			sig(name, 3600, 223, -2*time.Hour, 2*time.Hour),
		}
		served := serveFromEntry(t, req, resp, time.Hour)
		if tags := sigTags(served.Answer); len(tags) != 2 {
			t.Fatalf("served %v, want both signatures", tags)
		}
	})
}

// TestStorableRecordsPassesTheCommonShapeThrough pins the price: a response
// with nothing to drop is stored from the caller's slice, not a copy.
func TestStorableRecordsPassesTheCommonShapeThrough(t *testing.T) {
	now := time.Now()
	sig, a := ignoredSigFixtures(now)
	records := []dns.RR{a("x.example."), sig("x.example.", 300, 1, -time.Hour, time.Hour)}
	kept := storableRecords(records, now)
	if len(kept) != len(records) || &kept[0] != &records[0] {
		t.Fatal("a response with nothing to drop was copied")
	}
	if allocs := testing.AllocsPerRun(100, func() { storableRecords(records, now) }); allocs != 0 {
		t.Errorf("common shape allocated %v times, want none", allocs)
	}
}

// TestZeroLifetimeSignatureIsNeverKept pins the tolerance's floor: a
// signature permitting nothing, a header TTL of zero, or an Original TTL of
// zero, is RFC 4035 §5.3.3's ceiling exactly, and a one-second entry may
// not serve it as one. Each field separately.
func TestZeroLifetimeSignatureIsNeverKept(t *testing.T) {
	now := time.Now()
	_, a := ignoredSigFixtures(now)
	const name = "mx.example."

	for _, tc := range []struct {
		name            string
		hdrTTL, origTTL uint32
	}{
		{"header TTL zero", 0, 3600},
		{"original TTL zero", 3600, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(name, dns.TypeMX)
			req.SetEdns0(1232, true)
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = []dns.RR{
				&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 1}, Preference: 10, Mx: "target.example."},
			}
			resp.Extra = []dns.RR{
				a("target.example."),
				&dns.RRSIG{
					Hdr:         dns.RR_Header{Name: "target.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: tc.hdrTTL},
					TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTtl: tc.origTTL, KeyTag: 7,
					SignerName: "example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
					Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
					Expiration: uint32(now.Add(time.Hour).Unix()),      //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
				},
			}

			served := serveFromEntry(t, req, resp, time.Second)
			if tags := sigTags(served.Extra); len(tags) != 0 {
				t.Errorf("a signature permitting nothing was served: %v", tags)
			}
			if hasA(served.Extra, "target.example.") {
				t.Error("the RRset was served without the signature it arrived with")
			}
		})
	}
}

// TestDOZeroHitCarriesNoAdditionalSignature pins the DO=0 body on the wire
// path: the entry keeps a signed additional RRset with its signature, and a
// client that did not set DO must not receive that signature (RFC 4035
// §3.2.1), on the wire path as on the Msg path. Both shapes: an entry
// signed in the answer as well, and one whose only signature is additional.
func TestDOZeroHitCarriesNoAdditionalSignature(t *testing.T) {
	now := time.Now()
	sig, a := ignoredSigFixtures(now)
	const name = "mx.example."

	build := func(signedAnswer bool) *CacheEntry {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeMX)
		req.SetEdns0(1232, true)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{
			&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}, Preference: 10, Mx: "target.example."},
		}
		if signedAnswer {
			resp.Answer = append(resp.Answer, &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
				TypeCovered: dns.TypeMX, Algorithm: 8, Labels: 2, OrigTtl: 3600, KeyTag: 9,
				SignerName: "example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
				Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
				Expiration: uint32(now.Add(time.Hour).Unix()),      //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			})
		}
		resp.Extra = []dns.RR{a("target.example."), sig("target.example.", 3600, 600, -2*time.Hour, 2*time.Hour)}
		entry := NewCacheEntryWithKey(resp, time.Hour, 0, 0)
		if entry == nil {
			t.Fatal("entry not built")
		}
		return entry
	}

	for _, tc := range []struct {
		name         string
		signedAnswer bool
	}{
		{"signed in the answer too", true},
		{"signed only in the additional section", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := build(tc.signedAnswer)
			if entry.wireServe&wireHasDNSSEC == 0 {
				t.Fatal("the additional signature did not mark the body as carrying DNSSEC")
			}
			body, _ := entry.wireBodyFor(false)
			if body == nil {
				t.Fatal("no DO=0 body")
			}
			var served dns.Msg
			if err := served.Unpack(body); err != nil {
				t.Fatal(err)
			}
			if tags := sigTags(served.Extra); len(tags) != 0 {
				t.Errorf("DO=0 body carries additional signatures %v", tags)
			}
			if tags := sigTags(served.Answer); len(tags) != 0 {
				t.Errorf("DO=0 body carries answer signatures %v", tags)
			}
			if !hasA(served.Extra, "target.example.") {
				t.Error("DO=0 body lost the additional address itself")
			}
			if do, _ := entry.wireBodyFor(true); len(sigTags(mustUnpack(t, do).Extra)) != 1 {
				t.Error("DO=1 body lost the additional signature")
			}
		})
	}
}

func mustUnpack(t *testing.T, body []byte) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestDOZeroBodyKeepsOnlyTheTypeAskedFor pins the wire path's DNSSEC verdict
// to ClearDNSSEC's exception. A question for NSEC is answered with NSEC for
// any DO, and the signatures over it go for DO=0; a question for RRSIG keeps
// its signatures for any DO, and an NSEC that came along as a proof goes for
// DO=0; a question for RRSIG answered with signatures alone has nothing to
// strip and serves the stored body to both.
func TestDOZeroBodyKeepsOnlyTheTypeAskedFor(t *testing.T) {
	now := time.Now()
	sig, _ := ignoredSigFixtures(now)
	const name = "proof.example."
	nsec := func() dns.RR {
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
			NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		}
	}
	nsecSig := func() dns.RR {
		s := sig(name, 3600, 700, -2*time.Hour, time.Hour).(*dns.RRSIG)
		s.TypeCovered = dns.TypeNSEC
		return s
	}
	build := func(qtype uint16, answer []dns.RR) *CacheEntry {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		req.SetEdns0(1232, true)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = answer
		entry := NewCacheEntryWithKey(resp, time.Hour, 0, 0)
		if entry == nil {
			t.Fatal("entry not built")
		}
		return entry
	}
	types := func(records []dns.RR) map[uint16]int {
		got := map[uint16]int{}
		for _, rr := range records {
			got[rr.Header().Rrtype]++
		}
		return got
	}

	t.Run("NSEC asked for: the NSEC stays, its signature goes", func(t *testing.T) {
		entry := build(dns.TypeNSEC, []dns.RR{nsec(), nsecSig()})
		if entry.wireServe&wireHasDNSSEC == 0 {
			t.Fatal("the signature did not mark the body as carrying DNSSEC")
		}
		body, _ := entry.wireBodyFor(false)
		if body == nil {
			t.Fatal("no DO=0 body")
		}
		if got := types(mustUnpack(t, body).Answer); got[dns.TypeNSEC] != 1 || got[dns.TypeRRSIG] != 0 {
			t.Errorf("DO=0 answer types %v, want the NSEC alone", got)
		}
		do, _ := entry.wireBodyFor(true)
		if got := types(mustUnpack(t, do).Answer); got[dns.TypeNSEC] != 1 || got[dns.TypeRRSIG] != 1 {
			t.Errorf("DO=1 answer types %v, want the NSEC and its signature", got)
		}
	})

	t.Run("RRSIG asked for: the signatures stay, the proof goes", func(t *testing.T) {
		entry := build(dns.TypeRRSIG, []dns.RR{
			sig(name, 3600, 701, -2*time.Hour, time.Hour),
			sig(name, 3600, 702, -2*time.Hour, 2*time.Hour),
			nsec(),
		})
		if entry.wireServe&wireHasDNSSEC == 0 {
			t.Fatal("the NSEC did not mark the body as carrying DNSSEC")
		}
		body, _ := entry.wireBodyFor(false)
		if body == nil {
			t.Fatal("no DO=0 body")
		}
		if got := types(mustUnpack(t, body).Answer); got[dns.TypeRRSIG] != 2 || got[dns.TypeNSEC] != 0 {
			t.Errorf("DO=0 answer types %v, want both signatures and no NSEC", got)
		}
	})

	t.Run("RRSIG asked for and answered with signatures alone: nothing to strip", func(t *testing.T) {
		entry := build(dns.TypeRRSIG, []dns.RR{
			sig(name, 3600, 701, -2*time.Hour, time.Hour),
			sig(name, 3600, 702, -2*time.Hour, 2*time.Hour),
		})
		if entry.wireServe&wireHasDNSSEC != 0 {
			t.Fatal("an answer of nothing but the signatures asked for was marked as carrying DNSSEC to strip")
		}
		body, _ := entry.wireBodyFor(false)
		if got := types(mustUnpack(t, body).Answer); got[dns.TypeRRSIG] != 2 {
			t.Errorf("DO=0 answer types %v, want both signatures", got)
		}
	})
}

// TestAdditionalSignatureIsJudgedOnTheEntrysClock pins the admission clock.
// The lifetime, the entry's stored instant and the verdict on each
// additional signature read the same now, so the comparison is exact: a
// signature permitting one second is not carried by a two-second entry, // the tolerance that let it through served it a whole second past its
// ceiling, and one sharing the answer's own validity window, which trailed
// a lifetime measured a moment earlier by that moment, is carried.
func TestAdditionalSignatureIsJudgedOnTheEntrysClock(t *testing.T) {
	now := time.Now()
	_, a := ignoredSigFixtures(now)
	const name = "mx.example."
	rrsig := func(owner string, covered uint16, hdrTTL uint32, expires time.Time) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdrTTL},
			TypeCovered: covered, Algorithm: 8, Labels: 2, OrigTtl: hdrTTL, KeyTag: 9,
			SignerName: "example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(expires.Unix()),                 //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	mx := func(ttl uint32) dns.RR {
		return &dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl}, Preference: 10, Mx: "target.example."}
	}

	t.Run("a one-second signature is not carried by a two-second entry", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeMX)
		req.SetEdns0(1232, true)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{mx(2)}
		resp.Extra = []dns.RR{a("target.example."), rrsig("target.example.", dns.TypeA, 1, now.Add(time.Hour))}

		entry := newCacheEntryAt(resp, 2*time.Second, 0, 0, now)
		if entry == nil {
			t.Fatal("entry not built")
		}
		served := entry.ToMsg(req)
		if served == nil {
			t.Fatal("entry did not serve")
		}
		if tags := sigTags(served.Extra); len(tags) != 0 {
			t.Errorf("a one-second signature was carried by a two-second entry: %v", tags)
		}
		if hasA(served.Extra, "target.example.") {
			t.Error("the RRset was served without the signature it arrived with")
		}
	})

	t.Run("a signature sharing the answer's validity window is carried", func(t *testing.T) {
		// The answer's own signature sets the lifetime to the window's end;
		// the additional signature ends at the same instant. Through the
		// store, which measures the lifetime and anchors the entry at one
		// now, a second reading in between made this signature fall short
		// by microseconds every time. The window ends under the test
		// store's one-minute cap, so the two signatures really do set the
		// same boundary and nothing else clamps it.
		expires := now.Add(30 * time.Second)
		s := newTestStore(t)
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeMX)
		req.SetEdns0(1232, true)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{mx(3600), rrsig(name, dns.TypeMX, 3600, expires)}
		resp.Extra = []dns.RR{a("target.example."), rrsig("target.example.", dns.TypeA, 3600, expires)}
		s.SetFromResponse(resp, false, time.Time{})

		entry, ok := s.LookupByKey(CacheKey{Question: req.Question[0], CD: false}.Hash())
		if !ok {
			t.Fatal("the answer was not cached")
		}
		served := entry.ToMsg(req)
		if served == nil {
			t.Fatal("entry did not serve")
		}
		if tags := sigTags(served.Extra); len(tags) != 1 {
			t.Errorf("a signature ending with the answer's own was dropped: %v", tags)
		}
		if !hasA(served.Extra, "target.example.") {
			t.Error("the additional address was dropped")
		}
	})
}

// TestAdditionalMixedSignersGoWhole pins the delegation boundary in the
// additional section: the parent's NSEC over the child's name and the
// child's apex NSEC share owner, class and type, so on the wire they are
// one RRset whose records cannot be told apart by signer. A live child
// signature must not carry the parent's lapsed records with it (RFC 4035
// §5.3.2); the tuple goes whole. A single-signer tuple beside it is judged
// as before.
func TestAdditionalMixedSignersGoWhole(t *testing.T) {
	now := time.Now()
	_, a := ignoredSigFixtures(now)
	const name = "mx.example."
	nsec := func(owner string) dns.RR {
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
			NextDomain: "z." + owner, TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		}
	}
	rrsig := func(owner, signer string, covered uint16, tag uint16, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: covered, Algorithm: 8, Labels: 2, OrigTtl: 3600, KeyTag: tag,
			SignerName: signer, Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(until).Unix()),          //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeMX)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}, Preference: 10, Mx: "target.example."},
	}
	resp.Extra = []dns.RR{
		// The boundary: two NSEC records under one owner, the parent's
		// signature lapsed, the child's live.
		nsec("child.example."),
		nsec("child.example."),
		rrsig("child.example.", "example.", dns.TypeNSEC, 1, -time.Hour),
		rrsig("child.example.", "child.example.", dns.TypeNSEC, 2, 2*time.Hour),
		// A single-signer tuple, live: carried.
		a("target.example."),
		rrsig("target.example.", "example.", dns.TypeA, 3, 2*time.Hour),
	}

	served := serveFromEntry(t, req, resp, time.Hour)
	for _, rr := range served.Extra {
		if rr.Header().Name == "child.example." {
			t.Errorf("a mixed-signer tuple was carried: %s", rr.Header().String())
		}
	}
	if !hasA(served.Extra, "target.example.") {
		t.Error("the single-signer RRset was dropped")
	}
	if tags := sigTags(served.Extra); len(tags) != 1 || tags[0] != 3 {
		t.Errorf("additional signatures served: %v, want only the single-signer 3", tags)
	}
}

// TestAdditionalRRsetKeepsItsReceivedTTL pins RFC 4035 §5.3.3's other
// ceiling on the additional section: a signed RRset's lifetime may not
// exceed the TTL it was received with. An unsigned answer takes the
// positive floor, so an additional address received with a one-second TTL
// and a long-lived signature was lifted to the floor, kept, and served at
// it, with its signature. The tuple goes whole; one received with enough
// TTL stays.
func TestAdditionalRRsetKeepsItsReceivedTTL(t *testing.T) {
	now := time.Now()
	const name = "mx.example."
	rrsig := func(owner string) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 3600, KeyTag: 9,
			SignerName: "example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(2 * time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	addr := func(owner string, ttl uint32) dns.RR {
		return &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: []byte{192, 0, 2, 1}}
	}

	for _, tc := range []struct {
		name string
		ttl  uint32
		kept bool
	}{
		{"received with one second, lifted to the floor: dropped with its signature", 1, false},
		{"received with an hour: kept with its signature", 3600, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			req := new(dns.Msg)
			req.SetQuestion(name, dns.TypeMX)
			req.SetEdns0(1232, true)
			resp := new(dns.Msg)
			resp.SetReply(req)
			// Unsigned answer: the entry takes the positive floor.
			resp.Answer = []dns.RR{
				&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}, Preference: 10, Mx: "target.example."},
			}
			resp.Extra = []dns.RR{addr("target.example.", tc.ttl), rrsig("target.example.")}
			s.SetFromResponse(resp, false, time.Time{})

			entry, ok := s.LookupByKey(CacheKey{Question: req.Question[0], CD: false}.Hash())
			if !ok {
				t.Fatal("the answer was not cached")
			}
			served := entry.ToMsg(req)
			if served == nil {
				t.Fatal("entry did not serve")
			}
			if got := hasA(served.Extra, "target.example."); got != tc.kept {
				t.Errorf("address carried = %v, want %v", got, tc.kept)
			}
			if got := len(sigTags(served.Extra)) == 1; got != tc.kept {
				t.Errorf("signature carried = %v, want %v", got, tc.kept)
			}
			for _, rr := range served.Extra {
				if h := rr.Header(); h.Ttl > tc.ttl {
					t.Errorf("%s served at TTL %d, received with %d", h.Name, h.Ttl, tc.ttl)
				}
			}
		})
	}
}

// TestAdditionalRRsetIsMatchedAsADNSName pins name matching in the
// additional section to DNS-name equality: an owner spelled with an escaped
// octet packs to the same wire name as its plain spelling, and a fold of the
// presentation text did not see that, so a one-second address under one
// spelling slipped past the received-TTL check made against its signature
// under the other and was served past its TTL.
func TestAdditionalRRsetIsMatchedAsADNSName(t *testing.T) {
	now := time.Now()
	const name = "mx.example."
	s := newTestStore(t)
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeMX)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	// Unsigned answer: the entry takes the positive floor.
	resp.Answer = []dns.RR{
		&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}, Preference: 10, Mx: "target.example."},
	}
	resp.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: `t\097rget.example.`, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: []byte{192, 0, 2, 1}},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "target.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 3600, KeyTag: 9,
			SignerName: "example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(2 * time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		},
	}
	s.SetFromResponse(resp, false, time.Time{})

	entry, ok := s.LookupByKey(CacheKey{Question: req.Question[0], CD: false}.Hash())
	if !ok {
		t.Fatal("the answer was not cached")
	}
	served := entry.ToMsg(req)
	if served == nil {
		t.Fatal("entry did not serve")
	}
	if len(served.Extra) != 0 {
		t.Fatalf("a one-second signed address under an escaped spelling was carried: %v", served.Extra)
	}
}
