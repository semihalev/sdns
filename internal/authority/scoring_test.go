package authority

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The server ranking is the resolver's hottest decision: it runs on every
// cache miss, over every delegation's address set, and it decides which
// upstream gets the query. These tests pin the properties that decision
// must have — and the benchmarks price the ranking itself, because a sort
// that allocates is a sort that allocates once per miss.

// measured builds a server that has answered, through the same call the
// resolver makes — a fixture that hand-writes the fields tests the shape
// of the fields rather than the behaviour of the model.
func measured(addr string, rtt time.Duration) *Server {
	s := NewServer(addr, IPv4)
	s.Observe(rtt)
	return s
}

// unmeasured builds a server nothing is known about — the state every
// server starts in, and the state a server that never wins a race stays in.
func unmeasured(addr string) *Server {
	return NewServer(addr, IPv4)
}

func addrsOf(list []*Server) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.Addr
	}
	return out
}

// A server nothing is known about must not outrank one measured fast.
// "No data" is not "instant": ranking it first hands it the head of the
// list, and with the resolver starting its top two in parallel, that is a
// guaranteed query to the one server whose speed nobody has established.
func TestUnmeasuredDoesNotOutrankMeasured(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	unknown := unmeasured("192.0.2.2:53")

	list := []*Server{unknown, fast}
	Sort(list)

	if list[0] != fast {
		t.Fatalf("ranking put the unmeasured server first: %v", addrsOf(list))
	}
}

// Degradation must be visible within a couple of samples. This is the
// property the scoring was built around — a smoothed average that needed
// a dozen samples to notice an authority going bad would keep sending
// queries into it — so it is pinned here against future softening.
func TestDegradationSinksWithinTwoSamples(t *testing.T) {
	degrading := measured("192.0.2.1:53", 10*time.Millisecond)
	steady := measured("192.0.2.2:53", 50*time.Millisecond)

	list := []*Server{degrading, steady}
	Sort(list)
	if list[0] != degrading {
		t.Fatal("the fast server should lead before it degrades")
	}

	// One slow answer is enough: the blend is half and half, so the new
	// sample outweighs everything before it on the spot.
	degrading.Observe(2 * time.Second)
	Sort(list)

	if list[0] != steady {
		t.Fatalf("degraded server still leads after a slow answer: %v", addrsOf(list))
	}
}

// Ranking must survive. The scoring already forgets quickly — each sort
// halves the weight of everything before it — so a periodic wipe adds no
// aging that the average does not already do, while it does throw every
// server back to "unmeasured" at once.
func TestRankingSurvivesLongRuns(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	slow := measured("192.0.2.2:53", 200*time.Millisecond)
	list := []*Server{fast, slow}

	for i := 1; i <= 2500; i++ {
		// Both keep answering at their established speeds.
		fast.Observe(10 * time.Millisecond)
		slow.Observe(200 * time.Millisecond)
		Sort(list)

		if list[0] != fast {
			t.Fatalf("ranking lost the faster server at call %d: %v", i, addrsOf(list))
		}
	}
}

// An address that keeps losing the race is never measured by the ordinary
// path; the lower-bound observation is what closes that loop. Observing
// "did not answer within d" must be able to move a server down, and must
// never make one look better than it has proven to be.
func TestLowerBoundObservationRanksTheLoser(t *testing.T) {
	winner := measured("192.0.2.1:53", 10*time.Millisecond)
	loser := unmeasured("192.0.2.2:53")

	list := []*Server{loser, winner}
	for range 3 {
		// The resolver cancels the loser after the winner answers; all it
		// knows is that the loser was still silent at that point. A floor
		// past the seed is a floor that says something.
		loser.ObserveAtLeast(400 * time.Millisecond)
		withRandValue(0, func() { Sort(list) })
	}

	if list[0] != winner {
		t.Fatalf("the perpetual loser still leads: %v", addrsOf(list))
	}
	if got := loser.Score(); got <= time.Duration(rttUnknownSeed) {
		t.Fatalf("the floor taught the ranking nothing: %v", got)
	}
	// A lower bound must not improve a server's standing either.
	before := winner.Rtt
	winner.ObserveAtLeast(time.Microsecond)
	if winner.Rtt < before {
		t.Fatal("a lower-bound observation improved a measured server's score")
	}
}

// Equal scores are common right after a delegation is first read. Prefer
// the server something is known about, so the parallel head of the list is
// not two guesses.
func TestTieBreakPrefersMeasured(t *testing.T) {
	known := measured("192.0.2.1:53", time.Duration(rttUnknownSeed))
	unknown := unmeasured("192.0.2.2:53")

	list := []*Server{unknown, known}
	Sort(list)

	if list[0] != known {
		t.Fatalf("tie went to the unmeasured server: %v", addrsOf(list))
	}
}

// The ranking runs on every cache miss, so it may not allocate: one
// allocation here is one allocation per miss, on the path that already
// carries the resolver's heaviest work.
func TestSortDoesNotAllocate(t *testing.T) {
	list := benchServers(13)
	if allocs := testing.AllocsPerRun(200, func() { Sort(list) }); allocs != 0 {
		t.Fatalf("Sort allocated %.0f objects per call", allocs)
	}
}

// benchServers builds a deterministic address set with spread-out speeds,
// shaped like a root or TLD set: a few fast, a few far, one never measured.
func benchServers(n int) []*Server {
	list := make([]*Server, 0, n)
	for i := range n {
		s := NewServer(fmt.Sprintf("192.0.2.%d:53", i+1), IPv4)
		if i%7 != 0 {
			s.Observe(time.Duration(10+i*7) * time.Millisecond)
		}
		list = append(list, s)
	}
	return list
}

// The production shape: the list was sorted on the previous lookup and the
// scores have barely moved, so what is measured is a re-sort of a nearly
// ordered set — once per cache miss, per delegation step.
func benchmarkSort(b *testing.B, n int, shuffle bool) {
	src := benchServers(n)
	list := make([]*Server, n)
	copy(list, src)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if shuffle {
			copy(list, src) // restore the unordered set; copying pointers allocates nothing
		}
		Sort(list)
	}
}

func BenchmarkSortNearlyOrdered2(b *testing.B)  { benchmarkSort(b, 2, false) }
func BenchmarkSortNearlyOrdered8(b *testing.B)  { benchmarkSort(b, 8, false) }
func BenchmarkSortNearlyOrdered13(b *testing.B) { benchmarkSort(b, 13, false) }
func BenchmarkSortNearlyOrdered26(b *testing.B) { benchmarkSort(b, 26, false) }
func BenchmarkSortUnordered13(b *testing.B)     { benchmarkSort(b, 13, true) }
func BenchmarkSortUnordered26(b *testing.B)     { benchmarkSort(b, 26, true) }

// withRand pins the ranking's randomness so a test can state an order.
func withRand(t *testing.T, f func(int) int) {
	t.Helper()
	old := randN
	randN = f
	t.Cleanup(func() { randN = old })
}

// A failure is not a slow answer. One timeout must push a server behind
// healthy peers immediately — the penalty does that, where the blended
// latency alone would still rank it ahead — and a success must lift the
// penalty in one step, so a recovered authority is not serving a sentence.
func TestFailurePenaltyAndRecovery(t *testing.T) {
	flaky := measured("192.0.2.1:53", 10*time.Millisecond)
	steady := measured("192.0.2.2:53", 50*time.Millisecond)
	list := []*Server{flaky, steady}

	flaky.ObserveFailure(2 * time.Second)
	Sort(list)
	if list[0] != steady {
		t.Fatalf("a failing server still leads: %v", addrsOf(list))
	}

	penalised := flaky.Score()
	flaky.Observe(10 * time.Millisecond)
	if lifted := flaky.Score(); penalised-lifted < time.Second {
		t.Fatalf("a success did not lift the failure penalty: %v -> %v", penalised, lifted)
	}

	// And the latency itself recovers with the samples that prove it.
	for range 6 {
		flaky.Observe(10 * time.Millisecond)
	}
	Sort(list)
	if list[0] != flaky {
		t.Fatalf("a recovered server never regained the lead: %v", addrsOf(list))
	}
}

// Evidence expires. A server measured fast an hour ago must drift back
// toward "unknown" rather than hold the lead on a path that may no longer
// exist — this is what replaced wiping every server's statistics at once.
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

// The leader answers the query; the slot behind it is the hedge. Spending
// that slot on the same peer every time hedges against nothing, so inside
// the band it moves — while the fastest server keeps leading.
func TestHedgeSpreadsAcrossTheBand(t *testing.T) {
	list := []*Server{
		measured("192.0.2.1:53", 10*time.Millisecond),
		measured("192.0.2.2:53", 12*time.Millisecond),
		measured("192.0.2.3:53", 15*time.Millisecond),
		measured("192.0.2.4:53", 900*time.Millisecond),
	}
	best := list[0]

	seen := map[string]bool{}
	for pick := range 3 {
		withRandValue(pick, func() { Sort(list) })
		if list[0] != best {
			t.Fatalf("the hedge displaced the leader: %v", addrsOf(list))
		}
		seen[list[1].Addr] = true
	}
	if len(seen) < 2 {
		t.Fatalf("the hedge never moved: %v", seen)
	}
	if seen["192.0.2.4:53"] {
		t.Fatal("the hedge reached outside the band")
	}
}

// An unmeasured server sits outside the band of a fast delegation, so
// without deliberate exploration it is never sampled and never ranks
// honestly. The hedge spends one lookup in thirty-two proving it.
func TestHedgeExploresUnmeasured(t *testing.T) {
	fast := measured("192.0.2.1:53", 10*time.Millisecond)
	second := measured("192.0.2.2:53", 12*time.Millisecond)
	unknown := unmeasured("192.0.2.9:53")
	list := []*Server{fast, second, unknown}

	withRand(t, func(int) int { return 0 }) // the explore roll hits
	Sort(list)

	if list[0] != fast {
		t.Fatalf("exploration displaced the leader: %v", addrsOf(list))
	}
	if list[1] != unknown {
		t.Fatalf("exploration did not reach the unmeasured server: %v", addrsOf(list))
	}
}

// withRandValue runs f with a randomness source that answers a fixed
// value, without the explore roll firing.
func withRandValue(v int, f func()) {
	old := randN
	randN = func(n int) int {
		if n == exploreOdds {
			return 1 // never explore
		}
		return v % n
	}
	defer func() { randN = old }()
	f()
}

// A cancellation arrives when the peer that won was fast, so the floor it
// leaves behind is usually a small number. Reading that as a measurement
// let a server which has answered nothing look quicker than the servers
// that have — the exact inversion this ranking exists to prevent.
func TestLowerBoundCannotMakeAGuessLookFast(t *testing.T) {
	fast := measured("192.0.2.1:53", 12*time.Millisecond)
	unknown := unmeasured("192.0.2.9:53")
	list := []*Server{unknown, fast}

	// The peer answered in 10ms; the unknown was cancelled at that point
	// having said nothing at all.
	unknown.ObserveAtLeast(10 * time.Millisecond)

	if got := unknown.Score(); got < time.Duration(rttUnknownSeed) {
		t.Fatalf("a cancelled attempt improved an unmeasured server to %v", got)
	}
	withRandValue(0, func() { Sort(list) })
	if list[0] != fast {
		t.Fatalf("the guess took the lead: %v", addrsOf(list))
	}
}

// The seed prices a guess at 300ms, which is the right expectation to rank
// on — but the query itself should not be an experiment while a server
// that has actually answered is available, however slowly. The guess
// belongs in the hedge slot, which is where it gets probed.
func TestUnmeasuredIsHedgedNeverLed(t *testing.T) {
	slow := measured("192.0.2.1:53", 400*time.Millisecond) // worse than the seed
	unknown := unmeasured("192.0.2.9:53")
	list := []*Server{unknown, slow}

	withRandValue(0, func() { Sort(list) })

	if list[0] != slow {
		t.Fatalf("an unmeasured server took the query: %v", addrsOf(list))
	}
	if list[1] != unknown {
		t.Fatalf("the guess was not hedged: %v", addrsOf(list))
	}
}

// A floor is not an answer. A cancelled attempt can prove a server is at
// least 400ms slow, which is worse than the seed and belongs in its score
// — but it still has not answered anything, and a server that has answered
// slower than that is the one the query should go to.
func TestFloorIsNotAnAnswer(t *testing.T) {
	// Known and honest about it: answered at 800ms, then at 400ms.
	known := measured("192.0.2.1:53", 800*time.Millisecond)
	known.Observe(400 * time.Millisecond) // blended: 600ms

	// Never answered; cancelled at 400ms, which only proves a floor.
	silent := unmeasured("192.0.2.9:53")
	silent.ObserveAtLeast(400 * time.Millisecond)

	if silent.Count != 0 {
		t.Fatalf("a floor counted as an answer: Count = %d", silent.Count)
	}
	if got := silent.Score(); got <= 400*time.Millisecond {
		t.Fatalf("the floor did not reach the score: %v", got)
	}

	list := []*Server{silent, known}
	withRandValue(0, func() { Sort(list) })
	if list[0] != known {
		t.Fatalf("a server that never answered took the query: %v", addrsOf(list))
	}
	if list[1] != silent {
		t.Fatalf("the silent server was not hedged: %v", addrsOf(list))
	}
}

// Raising only has to hold when two lookups cancel attempts on the same
// server at the same moment. A read followed by a write does not: both
// see the same estimate and the weaker floor lands last, leaving the
// server looking better than the stronger floor had already proven. The
// race detector cannot see it — every individual access is atomic — so
// the contract is checked by outcome, over enough rounds that a lost
// update cannot hide.
func TestConcurrentFloorsKeepTheStrongest(t *testing.T) {
	const rounds, writers = 200, 8

	for range rounds {
		s := unmeasured("192.0.2.9:53")

		var start sync.WaitGroup
		var done sync.WaitGroup
		start.Add(1)
		want := int64(0)
		for w := range writers {
			// Descending samples: the first goroutine carries the
			// strongest floor, the last the weakest.
			sample := time.Duration(rttUnknownSeed) + time.Duration(writers-w)*time.Millisecond
			if int64(sample) > want {
				want = int64(sample)
			}
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				s.ObserveAtLeast(sample)
			}()
		}
		start.Done()
		done.Wait()

		if got := atomic.LoadInt64(&s.Rtt); got != want {
			t.Fatalf("concurrent floors settled at %v, want the strongest at %v",
				time.Duration(got), time.Duration(want))
		}
		if s.Count != 0 {
			t.Fatalf("a floor counted as an answer under contention: Count = %d", s.Count)
		}
	}
}

// The record path runs once per upstream attempt, so it is priced too.
func BenchmarkObserve(b *testing.B) {
	s := NewServer("192.0.2.1:53", IPv4)
	b.ReportAllocs()
	for range b.N {
		s.Observe(12 * time.Millisecond)
	}
}
