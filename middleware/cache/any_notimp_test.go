package cache

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestANYPassesThroughTheCache pins the cache's part in the ANY policy: it
// has none. Whatever the cache holds for a name, a zone in failure backoff
// or a subtree cut here, answers the other question types and never ANY,
// which always reaches the policy behind the cache. And the policy answer
// goes out with the writer unwrapped: it is not stored, not recorded as a
// failure, and not taken as the recovery that resets a zone's backoff. A
// zone in backoff used to answer ANY with SERVFAIL, and, once the answer
// did get through, its NOTIMP was classified a failure and cached, so the
// second ANY was SERVFAIL again.
func TestANYPassesThroughTheCache(t *testing.T) {
	t.Run("a zone in failure backoff", func(t *testing.T) {
		c := New(&config.Config{CacheSize: 1024})
		defer c.Stop()

		policy, reached := 0, 0
		downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			reached++
			q := ch.Request.Msg().Question[0]
			rcode := dns.RcodeServerFailure
			if q.Qtype == dns.TypeANY {
				policy++
				rcode = dns.RcodeNotImplemented
			}
			m := new(dns.Msg)
			m.SetRcode(ch.Request.Msg(), rcode)
			_ = ch.Writer.WriteMsg(m)
			ch.Cancel()
		})
		ask := func(qtype uint16) *dns.Msg {
			t.Helper()
			req := new(dns.Msg)
			req.SetQuestion("host.dead.example.", qtype)
			req.RecursionDesired = true
			w := mock.NewWriter("udp", "127.0.0.1:0")
			chain := middleware.NewChain([]middleware.Handler{c, downstream})
			chain.Reset(w, req)
			chain.Next(context.Background())
			if !w.Written() {
				t.Fatal("no response written")
			}
			return w.Msg()
		}
		failureOn := func(name string) bool {
			req := new(dns.Msg)
			req.SetQuestion(name, dns.TypeA)
			_, ok := c.store.LookupFailure(req, netip.Prefix{})
			return ok
		}

		c.store.RecordZoneFailure(dns.Question{Name: "seed.dead.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, "dead.example.")
		if !failureOn("host.dead.example.") {
			t.Fatal("fixture: the zone is not in backoff")
		}

		// An ordinary question is answered from the backoff, downstream untouched.
		if got := ask(dns.TypeA); got.Rcode != dns.RcodeServerFailure || reached != 0 {
			t.Fatalf("A under a zone in backoff: %s, downstream reached %d times; want SERVFAIL from the cache", dns.RcodeToString[got.Rcode], reached)
		}
		// ANY reaches the policy, twice, and neither answer is remembered.
		for i := 1; i <= 2; i++ {
			if got := ask(dns.TypeANY); got.Rcode != dns.RcodeNotImplemented {
				t.Fatalf("ANY %d: %s, want NOTIMP from the policy", i, dns.RcodeToString[got.Rcode])
			}
		}
		if policy != 2 {
			t.Fatalf("the policy answered %d times, want 2", policy)
		}
		if c.store.positive.Len() != 0 {
			t.Fatal("a NOTIMP answer was stored")
		}
		// The backoff stands: a NOTIMP is not the recovery that resets it.
		if !failureOn("host.dead.example.") {
			t.Fatal("the ANY answer reset the zone's failure backoff")
		}
	})

	t.Run("a subtree cut", func(t *testing.T) {
		c := New(&config.Config{CacheSize: 1024, Expire: 600})
		defer c.Stop()

		sig := func(owner string, covered uint16) dns.RR {
			return &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: covered, Algorithm: dns.RSASHA256, Labels: 2, OrigTtl: 300, KeyTag: 4242,
				SignerName: "zone.test.", Signature: "Tm90QVJlYWxTaWduYXR1cmVCdXRWYWxpZEJhc2U2NA==",
				Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test fixture
				Inception:  uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test fixture
			}
		}
		proof := new(dns.Msg)
		proof.SetQuestion("gone.zone.test.", dns.TypeA)
		proof.Rcode = dns.RcodeNameError
		proof.Ns = []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{Name: "zone.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns.zone.test.", Mbox: "hostmaster.zone.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
			},
			sig("zone.test.", dns.TypeSOA),
			&dns.NSEC{
				Hdr:        dns.RR_Header{Name: "glib.zone.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "help.zone.test.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
			},
			sig("glib.zone.test.", dns.TypeNSEC),
		}
		if !c.store.RecordNXDomainCut(proof, "gone.zone.test.", "zone.test.", time.Time{}) {
			t.Fatal("cut refused")
		}

		reached := 0
		policy := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			reached++
			m := new(dns.Msg)
			m.SetRcode(ch.Request.Msg(), dns.RcodeNotImplemented)
			_ = ch.Writer.WriteMsg(m)
			ch.Cancel()
		})
		ask := func(qtype uint16) *dns.Msg {
			t.Helper()
			req := new(dns.Msg)
			req.SetQuestion("sub.gone.zone.test.", qtype)
			req.RecursionDesired = true
			w := mock.NewWriter("udp", "127.0.0.1:0")
			chain := middleware.NewChain([]middleware.Handler{c, policy})
			chain.Reset(w, req)
			chain.Next(context.Background())
			if !w.Written() {
				t.Fatal("no response written")
			}
			return w.Msg()
		}
		if got := ask(dns.TypeA); got.Rcode != dns.RcodeNameError || reached != 0 {
			t.Fatalf("A under a cut: %s, policy reached %d times; want NXDOMAIN from the cut", dns.RcodeToString[got.Rcode], reached)
		}
		if got := ask(dns.TypeANY); got.Rcode != dns.RcodeNotImplemented || reached != 1 {
			t.Fatalf("ANY under a cut: %s, policy reached %d times; want NOTIMP from the policy", dns.RcodeToString[got.Rcode], reached)
		}
	})
}
