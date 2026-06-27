package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// ednsPrefetchQueryer is a faithful stand-in for the real prefetch
// sub-pipeline: it runs the refresh request through the actual edns
// middleware (which the real prefetchSub includes — edns is not
// ClientOnly) over a terminal handler that emits a signed answer. edns
// strips RRSIGs and clears AD whenever the request lacks DO, exactly as
// it does in production, so this exercises the real downgrade path.
type ednsPrefetchQueryer struct {
	e *edns.EDNS
}

func (q *ednsPrefetchQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// Terminal handler: the "resolver" returns a DNSSEC-signed,
	// authenticated answer (A + its covering RRSIG, AD=1).
	terminal := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.AuthenticatedData = true
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "secure.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 10},
			},
			&dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "secure.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: dns.TypeA,
				Algorithm:   13,
				Labels:      2,
				OrigTtl:     300,
				Expiration:  4102444800, // 2100-01-01, fixed; edns never verifies the sig
				Inception:   1577836800, // 2020-01-01
				KeyTag:      12345,
				SignerName:  "example.",
				Signature:   "dummysig",
			},
		}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{q.e, terminal})
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(w, req)
	ch.Next(ctx)
	return w.Msg(), nil
}

// TestPrefetchKeepsDNSSECForDO0Trigger proves a DO=0 client triggering a
// prefetch must not downgrade a signed entry. The cache is keyed on CD
// (not DO) and stores the COMPLETE answer, stripping DNSSEC per-client at
// serve time. The prefetch sub-pipeline runs edns, so unless the worker
// forces DO=1 a DO=0 trigger would refresh through edns, strip the RRSIG,
// clear AD, and overwrite the entry — every later DO=1 client then loses
// AD until expiry. With the DO=1 fix the refreshed entry keeps RRSIG+AD.
func TestPrefetchKeepsDNSSECForDO0Trigger(t *testing.T) {
	c := New(&config.Config{
		CacheSize: 1024,
		Expire:    60,
		Prefetch:  50,
	})
	defer c.Stop()

	c.SetPrefetchQueryer(&ednsPrefetchQueryer{e: edns.New(&config.Config{})})

	// The triggering client query carries DO=0 (no EDNS DO bit) — a plain
	// stub/forwarder, the common case that races prefetch on a hot name.
	trigger := new(dns.Msg)
	trigger.SetQuestion("secure.example.", dns.TypeA)

	// A hot CD=0 entry already in cache (about to be refreshed).
	old := new(dns.Msg)
	old.SetReply(trigger)
	old.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "secure.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   []byte{192, 0, 2, 1},
	}}
	key := CacheKey{Question: trigger.Question[0], CD: false}.Hash()
	entry := NewCacheEntryWithKey(old, 5*time.Second, 0, key)
	c.positive.Set(key, entry)

	if !c.prefetchQueue.Add(PrefetchRequest{
		Request: trigger.Copy(),
		Key:     key,
		Cache:   c,
		Entry:   entry,
	}) {
		t.Fatal("Add returned false; queue rejected the request")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, ok := c.positive.Get(key)
		if ok && got != entry {
			// Refreshed. The stored answer must still carry the RRSIG
			// and the AD bit — proving the DO=0 trigger did not strip
			// DNSSEC via the prefetch sub-pipeline's edns layer.
			hasRRSIG := false
			for _, rr := range got.msg.Answer {
				if _, ok := rr.(*dns.RRSIG); ok {
					hasRRSIG = true
				}
			}
			if !hasRRSIG {
				t.Fatalf("prefetch dropped the RRSIG: a DO=0 trigger downgraded the signed entry")
			}
			if !got.msg.AuthenticatedData {
				t.Fatalf("prefetch cleared the AD bit: a DO=0 trigger downgraded the signed entry")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("prefetch worker did not replace the cache entry")
}
