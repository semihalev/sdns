package authority

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The ranking runs on every cache miss, over every delegation's address
// set, and it decides which upstream gets the query. These are the four
// properties it is being changed for.

func measured(addr string, rtt time.Duration) *Server {
	s := NewServer(addr, IPv4)
	s.Observe(rtt)
	return s
}

func addrsOf(list []*Server) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.Addr
	}
	return out
}

// A server nothing is known about must not outrank one measured fast.
// "No data" was worth zero, which is not slow but instant, so the head of
// the list went to whichever address had never answered — and with the
// resolver starting its top two in parallel, that is one of every miss's
// two queries spent on the one server whose speed nobody has established.
func TestUnmeasuredDoesNotOutrankMeasured(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	unknown := NewServer("192.0.2.2:53", IPv4)

	list := []*Server{unknown, fast}
	Sort(list)

	if list[0] != fast {
		t.Fatalf("ranking put the unmeasured server first: %v", addrsOf(list))
	}
	// And it is priced as a guess worth trying, not as a server to avoid.
	if got := unknown.Score(); got != time.Duration(rttUnknownSeed)+1 {
		t.Fatalf("an unmeasured server is priced at %v, want the seed", got)
	}
}

// Degradation has to be visible immediately. A running average over every
// sample ever taken needed dozens of them to notice an authority going
// bad, and kept sending queries into it in the meantime; the blend is half
// and half so one bad sample lands in the ranking at once.
func TestDegradationSinksOnOneSlowAnswer(t *testing.T) {
	degrading := measured("192.0.2.1:53", 10*time.Millisecond)
	steady := measured("192.0.2.2:53", 50*time.Millisecond)

	list := []*Server{degrading, steady}
	Sort(list)
	if list[0] != degrading {
		t.Fatal("the fast server should lead before it degrades")
	}

	degrading.Observe(2 * time.Second)
	Sort(list)
	if list[0] != steady {
		t.Fatalf("a degraded server still leads after a slow answer: %v", addrsOf(list))
	}
}

// The ranking must survive a long run. The old shape cleared every
// server's statistics every thousandth sort, which is not aging but
// amnesia: for the sorts that followed, the whole set read as unmeasured
// — the state it ranked first — so the fastest server lost the lead
// periodically for no reason anyone could see from the outside.
func TestRankingSurvivesLongRuns(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	slow := measured("192.0.2.2:53", 200*time.Millisecond)
	list := []*Server{fast, slow}

	for i := 1; i <= 2500; i++ {
		fast.Observe(10 * time.Millisecond)
		slow.Observe(200 * time.Millisecond)
		Sort(list)

		if list[0] != fast {
			t.Fatalf("ranking lost the faster server at call %d: %v", i, addrsOf(list))
		}
	}
}

// Evidence expires. A server measured fast an hour ago drifts back toward
// a guess rather than holding the lead on a path that may no longer
// exist — per server, as its own measurement ages, which is what replaced
// wiping the whole set at once.
func TestStaleEvidenceDrifts(t *testing.T) {
	s := measured("192.0.2.1:53", 10*time.Millisecond)
	fresh := s.Score()

	atomic.StoreInt64(&s.lastNs, time.Now().Add(-time.Hour).UnixNano())
	stale := s.Score()

	if stale <= fresh {
		t.Fatalf("an hour-old measurement did not age: %v -> %v", fresh, stale)
	}
	if stale >= time.Duration(rttUnknownSeed) {
		t.Fatalf("aging threw the evidence away entirely: %v", stale)
	}
}

// withRand pins the ranking's randomness so a test can state an order.
func withRand(t *testing.T, f func(int) int) {
	t.Helper()
	old := randN
	randN = f
	t.Cleanup(func() { randN = old })
}

// The leader answers the query; the slot behind it goes to whichever
// server is level with the runner-up, and the sort's stability meant that
// was the same address on every lookup, forever. It matters most where
// the tie is widest: a delegation's unmeasured addresses all carry the
// same price, so one of them was queried on every cache miss and the
// other seventeen were never tried at all.
func TestTheSecondSlotRotatesAmongEquals(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	list := []*Server{fast}
	for i := range 8 {
		list = append(list, NewServer(fmt.Sprintf("192.0.2.9:%d", i+1), IPv4))
	}

	seen := map[string]int{}
	for range 2000 {
		Sort(list)
		if list[0] != fast {
			t.Fatalf("the leader lost its slot to a guess: %v", addrsOf(list))
		}
		seen[list[1].Addr]++
	}

	if len(seen) != 8 {
		t.Fatalf("the second slot reached %d of 8 unmeasured addresses: %v", len(seen), seen)
	}
}

// Rotation may not touch the leader, and may not reach past the servers
// that are actually level with the runner-up.
func TestRotationLeavesTheOrderedServersAlone(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	mid := measured("192.0.2.2:53", 50*time.Millisecond)
	slow := measured("192.0.2.3:53", 90*time.Millisecond)
	list := []*Server{slow, fast, mid}

	// A source that would swap the furthest thing it is offered.
	withRand(t, func(n int) int { return n - 1 })
	Sort(list)

	if got := addrsOf(list); got[0] != fast.Addr || got[1] != mid.Addr || got[2] != slow.Addr {
		t.Fatalf("distinct scores were reordered: %v", got)
	}
}

// The ranking runs once per cache miss, so an allocation here is an
// allocation per miss on the path that already carries the resolver's
// heaviest work. sort.Slice cost two, for the reflection it needs.
func TestSortDoesNotAllocate(t *testing.T) {
	list := benchServers(13)
	if allocs := testing.AllocsPerRun(200, func() { Sort(list) }); allocs != 0 {
		t.Fatalf("Sort allocated %.0f objects per call", allocs)
	}
}

// One server is sampled by several lookups at once — a root address is in
// flight from most of them, most of the time. Read, halve, write as
// separate steps keeps only whichever store landed last, which is how an
// estimate drifts away from what the network is doing under exactly the
// load that makes ranking matter. Identical samples make the expectation
// exact: each one halves the distance to its own value, so eight of them
// must land within a two-hundred-and-fifty-sixth of it however they
// interleave.
func TestConcurrentSamplesAreNotLost(t *testing.T) {
	const rounds, writers = 200, 8
	const start, sample = 2 * time.Second, 10 * time.Millisecond
	worst := int64(sample) + int64(start)/(1<<writers)

	for range rounds {
		s := measured("192.0.2.1:53", start)

		var gate, done sync.WaitGroup
		gate.Add(1)
		for range writers {
			done.Add(1)
			go func() {
				defer done.Done()
				gate.Wait()
				s.Observe(sample)
			}()
		}
		gate.Done()
		done.Wait()

		if got := s.SmoothedRTT(); int64(got) > worst {
			t.Fatalf("estimate settled at %v after %d identical samples, want %v or better — samples were dropped",
				got, writers, time.Duration(worst))
		}
	}
}

// benchServers builds a deterministic address set shaped like a root or
// TLD set: a few fast, a few far, one never measured. The port carries the
// identity because past 254 a last-octet address stops being an address.
func benchServers(n int) []*Server {
	list := make([]*Server, 0, n)
	for i := range n {
		s := NewServer(fmt.Sprintf("192.0.2.1:%d", i+1), IPv4)
		if i%7 != 0 {
			s.Observe(time.Duration(10+i*7) * time.Millisecond)
		}
		list = append(list, s)
	}
	return list
}

// Every lookup hands over a fresh copy of the delegation, so this is a
// sort of an arbitrary order rather than a re-sort of the last ranking.
func benchmarkSort(b *testing.B, n int) {
	src := benchServers(n)
	list := make([]*Server, n)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(list, src) // restore the unordered set; copying pointers allocates nothing
		Sort(list)
	}
}

// A delegation the resolver has just read is entirely unmeasured, so
// every address ties and the rotation has the widest set to scan and pick
// from. This is that shape, against benchmarkSort's mostly-distinct one.
func BenchmarkSortAllUnmeasured(b *testing.B) {
	const n = 13
	src := make([]*Server, 0, n)
	for i := range n {
		src = append(src, NewServer(fmt.Sprintf("192.0.2.9:%d", i+1), IPv4))
	}
	list := make([]*Server, n)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(list, src)
		Sort(list)
	}
}

func BenchmarkSort2(b *testing.B)  { benchmarkSort(b, 2) }
func BenchmarkSort8(b *testing.B)  { benchmarkSort(b, 8) }
func BenchmarkSort13(b *testing.B) { benchmarkSort(b, 13) }
func BenchmarkSort26(b *testing.B) { benchmarkSort(b, 26) }

// The record path runs once per upstream attempt, so it is priced too.
func BenchmarkObserve(b *testing.B) {
	s := NewServer("192.0.2.1:53", IPv4)
	b.ReportAllocs()
	for range b.N {
		s.Observe(12 * time.Millisecond)
	}
}
