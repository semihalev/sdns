package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestAdmissionGroupsSiblingsByWireName carries the canonical-identity
// matrix through admission to what a client sees: an RRset whose expired
// signature is covered by a live sibling under another spelling of the
// same wire name is admitted, served with AD and at the live signature's
// lifetime; a Kelvin sign is another name, its RRset is uncovered, and the
// answer is not admitted at all. Owner and signer both.
func TestAdmissionGroupsSiblingsByWireName(t *testing.T) {
	now := time.Now()
	sig := func(owner, signer string, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 3600, KeyTag: 1,
			SignerName: signer, Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(until).Unix()),          //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	a := func(owner string) dns.RR {
		return &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{192, 0, 2, 1}}
	}

	for _, tc := range []struct {
		name                      string
		question, owner, live     string
		signerExpired, signerLive string
		admitted                  bool
	}{
		{"owner: escaped and plain", "target.example.", "target.example.", `t\097rget.example.`, "example.", "example.", true},
		{"owner: ASCII case", "k.example.", "K.EXAMPLE.", "k.example.", "example.", "example.", true},
		{"owner: Kelvin sign and k", "k.example.", "k.example.", "K.example.", "example.", "example.", false},
		{"signer: ASCII case", "k.example.", "k.example.", "k.example.", "EXAMPLE.", "example.", true},
		{"signer: Kelvin sign and k", "k.example.", "k.example.", "k.example.", "Keep.example.", "keep.example.", false},
	} {
		for _, order := range []string{"expired first", "live first"} {
			t.Run(tc.name+", "+order, func(t *testing.T) {
				s := newTestStore(t)
				req := new(dns.Msg)
				req.SetQuestion(tc.question, dns.TypeA)
				req.SetEdns0(1232, true)
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.AuthenticatedData = true
				expired := sig(tc.owner, tc.signerExpired, -time.Hour)
				live := sig(tc.live, tc.signerLive, time.Hour)
				resp.Answer = []dns.RR{a(tc.owner), expired, live}
				if order == "live first" {
					resp.Answer = []dns.RR{a(tc.owner), live, expired}
				}
				s.SetFromResponse(resp, false, time.Time{})

				entry, ok := s.LookupByKey(CacheKey{Question: req.Question[0], CD: false}.Hash())
				if ok != tc.admitted {
					t.Fatalf("admitted = %v, want %v", ok, tc.admitted)
				}
				if !tc.admitted {
					return
				}
				served := entry.ToMsg(req)
				if served == nil {
					t.Fatal("entry did not serve")
				}
				if !served.AuthenticatedData {
					t.Error("AD withdrawn from an answer whose every RRset is covered")
				}
				tags := 0
				for _, rr := range served.Answer {
					if s, ok := rr.(*dns.RRSIG); ok {
						tags++
						if s.Header().Ttl < 55 {
							t.Errorf("served TTL %d, want the live signature's lifetime (store-capped at a minute)", s.Header().Ttl)
						}
					}
				}
				if tags != 1 {
					t.Errorf("%d signatures served, want the live one alone", tags)
				}
			})
		}
	}
}

// TestCacheableAnswerMatchesTheQuestionAsAWireName pins the answer filter:
// a record whose owner is the question's under another spelling is the
// answer; one whose owner merely folds to it in Unicode is not.
func TestCacheableAnswerMatchesTheQuestionAsAWireName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner string
		kept  bool
	}{
		{"ASCII case", "K.EXAMPLE.", true},
		{"escaped", `\107.example.`, true},
		{"Kelvin sign", "K.example.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := new(dns.Msg)
			res.SetQuestion("k.example.", dns.TypeA)
			res.Answer = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: tc.owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
			}
			if got := len(filterCacheableAnswer(res).Answer) == 1; got != tc.kept {
				t.Errorf("record kept = %v, want %v", got, tc.kept)
			}
		})
	}
}
