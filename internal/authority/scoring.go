package authority

import (
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// How an upstream is chosen.
//
// Every cache miss ends here: the resolver ranks a delegation's addresses,
// starts the top two in parallel, and walks down the rest on adaptive
// timeouts. So this file decides both how fast a miss resolves and how
// much upstream traffic a miss costs — the second query of the parallel
// head is a duplicate by design, and it is only worth its cost if it goes
// somewhere useful.
//
// The model is four facts per server, kept as atomics because the ranking
// runs on the serving path and the servers are shared across concurrent
// lookups. Torn reads across those four are tolerated on purpose: this is
// a heuristic ranking, and a lock here would be paid on every miss to
// avoid an error the next sample corrects.
//
//   - Rtt is a smoothed latency, blended half-and-half with each new
//     sample. The half-life is the point: one bad sample is visible in the
//     ranking immediately, which is what a resolver needs when an
//     authority starts to fail. A gentler average would keep sending
//     queries into a server that has already gone bad.
//   - Count separates "measured" from "never answered". Zero is not a
//     latency; a server nobody has timed is scored at rttUnknownSeed, so
//     it is tryable but never preferred over a server measured faster.
//   - fails counts consecutive failures. A timeout is not a slow answer,
//     it is an absence, and an average cannot express that: the penalty
//     grows per failure and one success clears it, so a server drops out
//     fast and comes back the moment it works again.
//   - lastNs ages the evidence. The path to an authority changes without
//     telling us, so a score nobody has refreshed drifts back toward
//     "unknown" instead of pinning a server on an hour-old measurement.
//
// Ranking is not the same as choosing. The fastest server always leads,
// but the hedge slot behind it is picked at random from the peers that are
// just as good, and occasionally spent probing a server nobody has
// measured. Without that, a delegation's slower-but-fine addresses are
// never sampled and the ranking narrows onto whatever answered first, in
// the beginning, forever.

const (
	// rttUnknownSeed is what "no data" is worth. Zero — the value a fresh
	// Server carries — ranked no-data as instant, which handed the head of
	// the list to whichever address had never answered, and the parallel
	// head then spent one of its two queries there on every single miss.
	// The seed sits above any healthy authority and below a sick one: an
	// unmeasured server is worth trying, never worth preferring.
	rttUnknownSeed = int64(300 * time.Millisecond)

	// failurePenaltyStep is added per consecutive failure, capped: enough
	// to push a failing server behind healthy peers on the first failure,
	// bounded so the penalty cannot grow past the point where it matters.
	failurePenaltyStep = int64(time.Second)
	failurePenaltyMax  = int64(8 * time.Second)

	// staleAfter is when a measurement stops counting as evidence. It
	// replaces a periodic wipe of every server's statistics, which aged
	// the whole set at once and, worse, returned every server to the
	// unmeasured state that the ranking treated as fastest.
	staleAfter = int64(5 * time.Minute)

	// selectionBand is how close two servers must be to count as
	// interchangeable for the hedge slot. Inside the band the second
	// parallel query is spread at random: the authorities of a zone expect
	// to share its traffic, and a hedge that always lands on the same peer
	// hedges against nothing.
	selectionBand = int64(30 * time.Millisecond)

	// exploreOdds is the reciprocal probability of spending the hedge slot
	// on a server nothing is known about. A fast delegation's unmeasured
	// members sit outside the band and would otherwise never be sampled,
	// leaving the ranking built on whichever subset happened to answer
	// first. One in thirty-two lookups is enough to measure them within a
	// handful of misses, and it costs nothing that the hedge was not
	// already spending.
	exploreOdds = 32

	// sortStackServers is the largest address set ranked without touching
	// the heap. A delegation past this is rare enough to pay for a slice;
	// the ordinary root or TLD set is a fraction of it.
	sortStackServers = 32
)

// randN is the ranking's only source of randomness, replaceable so tests
// can pin an order rather than chase one.
var randN = rand.IntN

// Observe records a completed exchange: the server answered, and this is
// how long it took.
func (s *Server) Observe(d time.Duration) {
	s.blend(int64(d))
	atomic.StoreInt32(&s.fails, 0)
}

// ObserveFailure records an attempt the authority owns — a timeout, a
// refusal, a referral the resolver had to reject. The duration still
// blends into the latency (a timeout is genuinely slow), and the failure
// counter carries what the latency cannot: that there was no answer.
func (s *Server) ObserveFailure(d time.Duration) {
	s.blend(int64(d))
	atomic.AddInt32(&s.fails, 1)
}

// ObserveAtLeast records what a cancelled attempt proves. When a peer
// answers first the resolver cancels the rest, and the cancelled server's
// elapsed time is not its latency — but its silence up to that point is a
// lower bound, and discarding it entirely is what let a server that never
// wins a race stay unmeasured, and therefore ranked first, forever.
//
// It only ever moves a server down: a cancellation is not evidence that an
// authority is fast, and it is never counted as a failure.
func (s *Server) ObserveAtLeast(d time.Duration) {
	sample := int64(d)
	if atomic.LoadInt64(&s.Count) > 0 && sample <= atomic.LoadInt64(&s.Rtt) {
		return
	}
	s.blend(sample)
}

// blend folds a sample into the smoothed latency. The first sample
// replaces the seedless zero outright; later ones are averaged with what
// is already known, which halves the weight of every older sample.
func (s *Server) blend(sample int64) {
	if atomic.LoadInt64(&s.Count) == 0 {
		atomic.StoreInt64(&s.Rtt, sample)
	} else {
		atomic.StoreInt64(&s.Rtt, (atomic.LoadInt64(&s.Rtt)+sample)/2)
	}
	atomic.AddInt64(&s.Count, 1)
	atomic.StoreInt64(&s.lastNs, time.Now().UnixNano())
}

// Fails is the consecutive-failure count behind a server's penalty. It is
// what an operator reads to tell "slow" from "not answering", and what a
// test asserts when the difference is the point.
func (s *Server) Fails() int32 { return atomic.LoadInt32(&s.fails) }

// SmoothedRTT is the measured latency, or zero when the server has never
// answered. The adaptive per-server timeout reads this rather than the
// ranking score: a timeout should follow how fast the server is, not how
// far the ranking has pushed it down.
func (s *Server) SmoothedRTT() time.Duration {
	if atomic.LoadInt64(&s.Count) == 0 {
		return 0
	}
	return time.Duration(atomic.LoadInt64(&s.Rtt))
}

// Score is what the ranking sorts on, at this instant.
func (s *Server) Score() time.Duration {
	return time.Duration(s.score(time.Now().UnixNano()))
}

// score is Score against a clock the caller already read — the ranking
// reads it once for a whole list rather than once per server.
func (s *Server) score(nowNs int64) int64 {
	base := atomic.LoadInt64(&s.Rtt)
	if atomic.LoadInt64(&s.Count) == 0 {
		// The extra nanosecond is the tie-break: a server measured at
		// exactly the seed is still a measurement, and a guess must not
		// share the front of the list with it.
		base = rttUnknownSeed + 1
	}
	if f := int64(atomic.LoadInt32(&s.fails)); f > 0 {
		penalty := f * failurePenaltyStep
		if penalty > failurePenaltyMax {
			penalty = failurePenaltyMax
		}
		base += penalty
	}
	if last := atomic.LoadInt64(&s.lastNs); last != 0 && nowNs-last > staleAfter {
		// Halfway back to "unknown": old evidence is weakened, not
		// thrown away, so a server that was fast an hour ago still
		// outranks one that was slow an hour ago.
		base = (base + rttUnknownSeed) / 2
	}
	return base
}

// Sort ranks a delegation's addresses in place: fastest first, then the
// hedge slot, then the rest. It allocates nothing for the sets a resolver
// actually meets.
//
// The sort is insertion, not a general one, because of the shape of the
// input: this list was ranked on the previous lookup and the scores have
// barely moved since, so it arrives nearly ordered and leaves after a
// handful of swaps. Insertion is also stable, which keeps a ranking from
// churning between equal servers for no reason.
func Sort(list []*Server) {
	n := len(list)
	if n < 2 {
		return
	}
	now := time.Now().UnixNano()
	if n <= sortStackServers {
		var scores [sortStackServers]int64
		rank(list, scores[:n], now)
		return
	}
	rank(list, make([]int64, n), now)
}

func rank(list []*Server, scores []int64, now int64) {
	for i, s := range list {
		scores[i] = s.score(now)
	}
	for i := 1; i < len(list); i++ {
		score, server := scores[i], list[i]
		j := i - 1
		for j >= 0 && scores[j] > score {
			scores[j+1], list[j+1] = scores[j], list[j]
			j--
		}
		scores[j+1], list[j+1] = score, server
	}
	hedge(list, scores)
}

// hedge chooses what the second parallel query is spent on. The leader is
// left alone — the fastest server answers the query — and the slot behind
// it either probes something unmeasured or spreads across the peers that
// are just as fast.
func hedge(list []*Server, scores []int64) {
	n := len(list)
	if n < 2 {
		return
	}
	if randN(exploreOdds) == 0 {
		for i := 1; i < n; i++ {
			if atomic.LoadInt64(&list[i].Count) == 0 {
				list[1], list[i] = list[i], list[1]
				return
			}
		}
	}
	band := scores[0] + selectionBand
	k := 1
	for k < n && scores[k] <= band {
		k++
	}
	if k > 2 {
		j := 1 + randN(k-1)
		list[1], list[j] = list[j], list[1]
	}
}
