package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// signalingPrefetchQueryer returns a canned response and fires a
// channel so the test can wait for the worker to run before
// asserting outcomes.
type signalingPrefetchQueryer struct {
	resp *dns.Msg
	fire chan struct{}
}

func (q *signalingPrefetchQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	defer func() {
		select {
		case q.fire <- struct{}{}:
		default:
		}
	}()
	return q.resp, nil
}

// TestPrefetchWorkerStoresRefresh exercises processPrefetch end-to-
// end: a queued request, an installed prefetchQueryer stub, and
// verification that the refreshed response lands in the store via
// SetFromResponseWithKey.
func TestPrefetchWorkerStoresRefresh(t *testing.T) {
	c := New(&config.Config{
		CacheSize: 1024,
		Expire:    60,
		Prefetch:  50,
	})
	defer c.Stop()

	// A fresh response the prefetch worker will dispatch through
	// its queryer and write back to the store.
	refreshed := new(dns.Msg)
	refreshed.SetQuestion("prefetch.example.", dns.TypeA)
	refreshed.Rcode = dns.RcodeSuccess
	refreshed.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "prefetch.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 7},
	}}

	fired := make(chan struct{}, 1)
	c.SetPrefetchQueryer(&signalingPrefetchQueryer{resp: refreshed, fire: fired})

	// Install an existing "hot" entry — that's what the prefetch
	// refresh replaces.
	req := new(dns.Msg)
	req.SetQuestion("prefetch.example.", dns.TypeA)
	old := new(dns.Msg)
	old.SetReply(req)
	old.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "prefetch.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   []byte{192, 0, 2, 1},
	}}
	key := CacheKey{Question: req.Question[0], CD: false}.Hash()
	entry := NewCacheEntryWithKey(old, 5*time.Second, 0, key)
	c.positive.Set(key, entry)

	// Drop a PrefetchRequest directly on the worker queue.
	pr := PrefetchRequest{
		Request: req.Copy(),
		Key:     key,
		Cache:   c,
		Entry:   entry,
	}
	if !c.prefetchQueue.Add(pr) {
		t.Fatal("Add returned false; queue rejected the request")
	}

	// Wait for the worker to fire our stub Queryer.
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("prefetch worker did not run within 2s")
	}

	// The worker writes through store.SetFromResponseWithKey. Give
	// it a beat to finish the post-Query work (deferred claim
	// release + store write) then observe the replaced entry.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, ok := c.positive.Get(key)
		if ok && got != entry {
			// Replaced — worker finished.
			if len(got.msg.Answer) != 1 {
				t.Fatalf("refreshed entry answer count = %d, want 1", len(got.msg.Answer))
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("prefetch worker did not replace the cache entry")
}

// TestPrefetchWorkerReleasesClaimOnError exercises the error-return
// arm of processPrefetch — when the queryer fails, the deferred
// releasePrefetchClaim must still flip the entry's prefetch flag
// off so future requests can trigger another refresh attempt.
func TestPrefetchWorkerReleasesClaimOnError(t *testing.T) {
	c := New(&config.Config{
		CacheSize: 1024,
		Expire:    60,
		Prefetch:  50,
	})
	defer c.Stop()

	// No prefetchQueryer installed → prefetchExchange returns
	// errQueryerNotWired → worker bails via the err != nil return.

	req := new(dns.Msg)
	req.SetQuestion("err.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "err.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   []byte{127, 0, 0, 1},
	}}
	key := CacheKey{Question: req.Question[0], CD: false}.Hash()
	entry := NewCacheEntryWithKey(resp, 5*time.Second, 0, key)
	entry.prefetch.Store(true) // simulate the CAS-claimed state
	c.positive.Set(key, entry)

	c.prefetchQueue.Add(PrefetchRequest{
		Request: req.Copy(),
		Key:     key,
		Cache:   c,
		Entry:   entry,
	})

	// Wait (bounded) for the worker's defer to release the claim.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !entry.prefetch.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("prefetch claim was not released after worker error")
}
