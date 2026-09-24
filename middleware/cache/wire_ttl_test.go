package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestWireFastPathTTLDecays pins the one client-visible behaviour of the
// byte path that the equivalence suite cannot see: the remaining TTL is
// stamped onto every record on the way out.
//
// The equivalence tests zero TTLs before comparing, because the two paths
// compute their remaining TTL a moment apart. That tolerance is necessary,
// but it means removing the TTL walk entirely leaves the whole suite green
// while every byte-served hit returns the record's original TTL forever,
// downstream caches would then never expire it. So the decay is asserted
// here directly, against the value the entry itself reports.
func TestWireFastPathTTLDecays(t *testing.T) {
	const (
		qname   = "ttl.example.com."
		storedT = 300
		aged    = 100 * time.Second
	)

	entryMsg := wireFastEntry(t, qname, dns.TypeA, false)
	c, e := wireFastTestPipeline(t, entryMsg)

	key := CacheKey{Question: entryMsg.Question[0], CD: entryMsg.CheckingDisabled}.Hash()
	entry, ok := c.store.LookupByKey(key)
	if !ok {
		t.Fatal("entry not stored")
	}

	// Age the entry rather than sleeping: the serve path derives the TTL
	// from stored+ttl, so moving stored back is exactly equivalent.
	entry.stored = entry.stored.Add(-aged)

	want := uint32(entry.remaining(time.Now()).Seconds()) //nolint:gosec // bounded by the entry TTL
	if want == 0 || want >= storedT {
		t.Fatalf("test setup: expected an aged TTL below %d, got %d", storedT, want)
	}

	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	req.Id = 21
	req.RecursionDesired = true
	req.SetEdns0(1232, true)

	servedBefore := wireFastServed.Value()
	resp := serveThrough(t, c, e, req, false)
	if wireFastServed.Value() == servedBefore {
		t.Fatal("this case must exercise the byte path")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("no answer returned")
	}

	for _, rr := range resp.Answer {
		ttl := rr.Header().Ttl
		if ttl >= storedT {
			t.Fatalf("answer TTL %d was served unchanged from the stored %d; "+
				"the byte path is not stamping the remaining TTL", ttl, storedT)
		}
		// One second of slack: the serve path reads the clock again.
		if ttl+1 < want || ttl > want+1 {
			t.Fatalf("answer TTL %d, want ~%d (the entry's remaining TTL)", ttl, want)
		}
	}
}

// TestWireFastPathTTLMatchesMsgPath pins that both paths age a record the
// same way, which the TTL-zeroing equivalence comparison cannot check.
func TestWireFastPathTTLMatchesMsgPath(t *testing.T) {
	const qname = "ttlpair.example.com."

	serve := func(t *testing.T, forceMsgPath bool) uint32 {
		t.Helper()
		entryMsg := wireFastEntry(t, qname, dns.TypeA, false)
		c, e := wireFastTestPipeline(t, entryMsg)

		key := CacheKey{Question: entryMsg.Question[0], CD: entryMsg.CheckingDisabled}.Hash()
		entry, ok := c.store.LookupByKey(key)
		if !ok {
			t.Fatal("entry not stored")
		}
		entry.stored = entry.stored.Add(-90 * time.Second)

		req := new(dns.Msg)
		req.SetQuestion(qname, dns.TypeA)
		req.Id = 22
		req.RecursionDesired = true
		req.SetEdns0(1232, true)

		resp := serveThrough(t, c, e, req, forceMsgPath)
		if len(resp.Answer) == 0 {
			t.Fatal("no answer returned")
		}
		return resp.Answer[0].Header().Ttl
	}

	viaWire := serve(t, false)
	viaMsg := serve(t, true)

	if viaWire+1 < viaMsg || viaWire > viaMsg+1 {
		t.Fatalf("byte path served TTL %d but the message path served %d",
			viaWire, viaMsg)
	}
}
