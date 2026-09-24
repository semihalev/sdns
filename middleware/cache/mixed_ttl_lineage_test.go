package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestMixedTTLRecordsServeTheAnswersOwnHorizon exercises the TTL lineage
// with every record class carrying a different TTL: the A RRset at 3600, its
// RRSIG at 1800 (validity weeks away), a consulted DNSKEY entry with only 30
// seconds left, and a delegation cut of its own. The first query serves the
// records as resolved; the second serves the cached entry, whose horizon must
// be min(A, RRSIG), the admission rule, and not the remaining life of
// whatever the resolver consulted on the way. The delegation cut is the one
// outside bound that still applies.
func TestMixedTTLRecordsServeTheAnswersOwnHorizon(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	now := time.Now()
	signedAnswer := func(name string) []dns.RR {
		return []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   []byte{192, 0, 2, 7},
			},
			&dns.RRSIG{
				Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 1800},
				TypeCovered: dns.TypeA,
				Algorithm:   8,
				Labels:      2,
				OrigTtl:     3600,
				Expiration:  uint32(now.Add(14 * 24 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
				Inception:   uint32(now.Add(-time.Hour).Unix()),          //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
				KeyTag:      12345,
				SignerName:  "example.",
				Signature:   "MTIzNDU2Nzg5MGFiY2RlZg==",
			},
		}
	}

	query := func(name string, handlers ...middleware.Handler) *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		req.RecursionDesired = true
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(append([]middleware.Handler{c}, handlers...))
		ch.Reset(w, req)
		ch.Next(context.Background())
		if !w.Written() {
			t.Fatal("no response written")
		}
		return w.Msg()
	}

	entryFor := func(name string) *CacheEntry {
		t.Helper()
		q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		entry, ok := c.store.LookupByKey(CacheKey{Question: q, CD: false}.Hash())
		if !ok {
			t.Fatal("the answer was not cached")
		}
		return entry
	}

	answerTTL := func(msg *dns.Msg) uint32 {
		t.Helper()
		if len(msg.Answer) == 0 {
			t.Fatal("empty answer")
		}
		return msg.Answer[0].Header().Ttl
	}

	t.Run("a short-lived DNSKEY consult does not cap the answer", func(t *testing.T) {
		// A DNSKEY entry with 30 seconds left, as after a long-lived key
		// has almost aged out of the cache.
		keyReq := new(dns.Msg)
		keyReq.SetQuestion("example.", dns.TypeDNSKEY)
		keyResp := new(dns.Msg)
		keyResp.SetReply(keyReq)
		keyResp.Answer = []dns.RR{&dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 30},
			Flags:     256,
			Protocol:  3,
			Algorithm: 8,
			PublicKey: "MTIzNDU2Nzg5MGFiY2RlZg==",
		}}
		c.store.SetFromResponse(keyResp, false, time.Time{})

		const name = "signed.mixed.example."
		first := query(name, middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			// The validation consult, on the request's own context,
			// exactly how subQuery reads keys mid-resolution.
			if _, ok := c.store.GetWithContext(ctx, keyReq); !ok {
				t.Error("the DNSKEY consult missed")
			}
			resp := new(dns.Msg)
			resp.SetReply(ch.Request.Msg())
			resp.Answer = signedAnswer(name)
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
		}))
		second := query(name, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			t.Error("second query missed the cache")
			ch.Cancel()
		}))

		// Both queries: the entry's own horizon, min(A 3600, RRSIG 1800), and
		// not the consulted key's 30 seconds.
		//
		// The first used to get the A record's bare 3600 while every later one
		// got 1800, two different promises about the same records, and the
		// client that asked first was invited to hold the answer for half an
		// hour past the signature bounding it. RFC 4035 §5.3.3 does not leave
		// that to the resolver's discretion.
		if got := answerTTL(first); got < 1700 || got > 1800 {
			t.Fatalf("first query A TTL = %d, want ~1800, the signature's horizon", got)
		}
		if got := answerTTL(second); got < 1700 || got > 1800 {
			t.Fatalf("second query A TTL = %d, want ~1800, not the key's 30", got)
		}
		if entry := entryFor(name); !entry.cutUntil.IsZero() {
			t.Fatalf("the DNSKEY consult stamped cutUntil %v onto the answer", entry.cutUntil)
		}
	})

	t.Run("the delegation cut bounds every response, the first included", func(t *testing.T) {
		const name = "signed.cut.example."
		cut := time.Now().Add(45 * time.Second)
		first := query(name, middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			// The walk's noteCut: the delegation this answer came
			// through expires before the records do.
			middleware.ResponseMetaFrom(ctx).BoundCutFor(cut, 0x77)
			resp := new(dns.Msg)
			resp.SetReply(ch.Request.Msg())
			resp.Answer = signedAnswer(name)
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
		}))
		second := query(name, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			t.Error("second query missed the cache")
			ch.Cancel()
		}))

		// The ghost bound (GHSA-mqfw-f48p-2vc8) reaches the client on both
		// responses: a downstream cache must never be invited to keep the
		// answer past the parent-granted lease, and the uncached response
		// must make the same promise the hits do.
		if got := answerTTL(first); got > 45 || got < 40 {
			t.Fatalf("first query A TTL = %d, want the 45s delegation lease", got)
		}
		if got := answerTTL(second); got > 45 || got < 30 {
			t.Fatalf("second query A TTL = %d, want the 45s delegation lease", got)
		}
		if entry := entryFor(name); entry.cutUntil.IsZero() {
			t.Fatal("the delegation cut did not reach the entry")
		}
	})
}
