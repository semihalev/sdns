package authority

import (
	"cmp"
	"math/rand/v2"
	"slices"
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
// The model is a handful of facts per server, kept as atomics because the
// ranking runs on the serving path and the servers are shared across
// concurrent lookups. What one observation says is held in a single word
// so it lands as one fact; the rest is read alongside it and a torn read
// there is tolerated on purpose, because this is a heuristic ranking and a
// lock would be paid on every miss to avoid an error the next sample
// corrects.
//
//   - The estimate is a smoothed latency, blended half-and-half with each
//     new sample. The half-life is the point: one bad sample is visible in
//     the ranking immediately, which is what a resolver needs when an
//     authority starts to fail. A gentler average would keep sending
//     queries into a server that has already gone bad.
//   - The evidence bit separates a measurement from a guess: unset means
//     nothing has ever answered, and such a server is priced at
//     rttUnknownSeed (or worse, if a cancelled attempt has proven a floor
//     above it) and may be hedged but never led with. A floor raises the
//     estimate without ever setting it.
//   - The failure run counts consecutive failures. A timeout is not a slow
//     answer, it is an absence, and an average cannot express that: the
//     penalty grows per failure and one success clears it, so a server
//     drops out fast and comes back the moment it works again.
//   - lastNs ages the evidence. The path to an authority changes without
//     telling us, so a score nobody has refreshed drifts back toward
//     "unknown" instead of pinning a server on an hour-old measurement.
//   - samples counts completed exchanges, for operators. Nothing is
//     decided on it.
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

	// sortInsertionMax is where the insertion pass stops being the cheaper
	// way to rank. Its comparison is two int64s in a slice the ranking has
	// just filled, which is fast enough that quadratic still wins well past
	// the size the exponent suggests: measured against a general sort of
	// the same set, insertion is ahead at 256 addresses (2.1µs against
	// 3.3µs), level around four hundred, and behind at 1024 (34µs against
	// 14µs). The threshold sits at the last size insertion wins outright,
	// which caps what the quadratic term can cost at a couple of
	// microseconds — everything above scales as n log n, and how large a
	// delegation's address set gets is not ours to choose.
	sortInsertionMax = 256
)

// randN is the ranking's only source of randomness, replaceable so tests
// can pin an order rather than chase one.
var randN = rand.IntN

// What one server's state weighs, and why it is one word.
//
// An observation is three facts at once: how long it took, whether
// anything came back, and whether that was an answer or a failure. Held in
// separate words they are three writes, and the order they land in is not
// the order they happened: a failure that wins the estimate and then
// pauses can have its failure count applied after a later success has
// already cleared it, leaving a server marked failing whose most recent
// exchange succeeded. Every round of review found another arrangement of
// that same shape, so the state is one 64-bit word and an observation is
// one compare-and-swap.
//
//	[ estimate ns : 55 ][ consecutive failures : 8 ][ evidence : 1 ]
//
// The estimate keeps the top fifty-five bits and is clamped to
// fifty-four of them, so a wild sample cannot shift into the sign bit and
// come back as a negative latency. Fifty-four bits of nanoseconds is two
// hundred days, against estimates that live in milliseconds; the failure
// count saturates at 255, long past where the penalty stops growing.
const (
	stateEvidence  = 1
	stateFailShift = 1
	stateFailMax   = 1<<8 - 1
	stateFailMask  = int64(stateFailMax) << stateFailShift
	stateRTTShift  = 9
	// stateRTTMax keeps a wild sample from shifting into the sign bit. A
	// duration this large is not a latency, it is a bug somewhere else,
	// and the ranking should record "very slow" rather than a negative.
	stateRTTMax = int64(1)<<54 - 1
)

// estimate unpacks the whole state: the latency, the consecutive failures
// behind it, and whether anything has come back from this server at all.
// Every decision in this file is taken on one read of it, so no decision
// can be made against a server that is half-updated.
func (s *Server) estimate() (rtt int64, fails int64, evidence bool) {
	w := atomic.LoadInt64(&s.state)
	return w >> stateRTTShift, (w & stateFailMask) >> stateFailShift, w&stateEvidence == 1
}

func packState(rtt, fails int64, evidence bool) int64 {
	if rtt > stateRTTMax {
		rtt = stateRTTMax
	}
	if rtt < 0 {
		rtt = 0
	}
	if fails > stateFailMax {
		fails = stateFailMax
	}
	w := rtt<<stateRTTShift | fails<<stateFailShift
	if evidence {
		w |= stateEvidence
	}
	return w
}

// Samples is how many exchanges with this server have completed —
// answers and failures alike. Nothing is decided on it.
func (s *Server) Samples() int64 { return atomic.LoadInt64(&s.samples) }

// Observe records a completed exchange: the server answered, and this is
// how long it took. The answer clears the failure run in the same write
// that folds in the latency — a success and the failures it supersedes are
// one fact about one exchange, and splitting them let them land out of
// order.
func (s *Server) Observe(d time.Duration) { s.record(int64(d), false) }

// ObserveFailure records an attempt the authority owns — a timeout, a
// refusal, a referral the resolver had to reject. The duration still
// blends into the latency (a timeout is genuinely slow), and the failure
// count carries what the latency cannot: that there was no answer.
func (s *Server) ObserveFailure(d time.Duration) { s.record(int64(d), true) }

// ObserveAtLeast records what a cancelled attempt proves. When a peer
// answers first the resolver cancels the rest, and the cancelled server's
// elapsed time is not its latency — it is a floor under it: the server had
// not answered by then.
//
// A floor may only ever move a server down. That is the whole contract,
// and it has a sharp edge: the cancellation usually arrives fast, because
// the peer that won was fast, so treating that short interval as a
// measurement would let a server which has never answered anything look
// quicker than the servers that have. A floor below what is already
// assumed teaches nothing, so it is dropped.
func (s *Server) ObserveAtLeast(d time.Duration) {
	sample := int64(d)
	for {
		w := atomic.LoadInt64(&s.state)
		current, fails, evidence := w>>stateRTTShift, (w&stateFailMask)>>stateFailShift, w&stateEvidence == 1

		var next int64
		switch {
		case evidence:
			// Something has answered, so there is an estimate to raise
			// rather than replace.
			if sample <= current {
				return
			}
			next = (current + sample) / 2
		default:
			// Nothing has answered: the standing assumption is the seed,
			// and only a floor past it says anything at all.
			if sample <= rttUnknownSeed || sample <= current {
				return
			}
			next = sample
		}

		// The evidence bit and the failure run are carried through
		// unchanged — a floor is not an answer and not a failure, and
		// writing the word whole is what keeps it from becoming either
		// under a concurrent update.
		if atomic.CompareAndSwapInt64(&s.state, w, packState(next, fails, evidence)) {
			atomic.StoreInt64(&s.lastNs, time.Now().UnixNano())
			return
		}
	}
}

// record folds a completed exchange into the estimate. The first one
// replaces whatever assumption was standing — a seedless zero, or a floor
// left by a cancelled attempt, neither of which is a measurement — and
// every one after is averaged with what is known, which halves the weight
// of each older sample.
//
// The loop exists because a server is sampled by many lookups at once: a
// root address is in flight from several of them most of the time. Read,
// decide, write as separate steps kept only whichever store landed last,
// and inside the same window a second sample could read the server as
// never-measured and replace a measurement instead of folding into it.
// The compare-and-swap carries the estimate, the failure run and the
// evidence bit together, so an exchange lands as one fact: the sample that
// moved the estimate is the sample whose outcome the failure count shows.
func (s *Server) record(sample int64, failed bool) {
	for {
		w := atomic.LoadInt64(&s.state)
		current, fails, evidence := w>>stateRTTShift, (w&stateFailMask)>>stateFailShift, w&stateEvidence == 1
		next := sample
		if evidence {
			next = (current + sample) / 2
		}
		if failed {
			fails++
		} else {
			fails = 0
		}
		if atomic.CompareAndSwapInt64(&s.state, w, packState(next, fails, true)) {
			break
		}
		// Another sample or a floor landed first; fold into what it left.
	}
	atomic.AddInt64(&s.samples, 1)
	atomic.StoreInt64(&s.lastNs, time.Now().UnixNano())
}

// Fails is the consecutive-failure count behind a server's penalty. It is
// what an operator reads to tell "slow" from "not answering", and what a
// test asserts when the difference is the point.
func (s *Server) Fails() int64 {
	_, fails, _ := s.estimate()
	return fails
}

// SmoothedRTT is the measured latency, or zero when the server has never
// answered. The adaptive per-server timeout reads this rather than the
// ranking score: a timeout should follow how fast the server is, not how
// far the ranking has pushed it down.
func (s *Server) SmoothedRTT() time.Duration {
	rtt, _, evidence := s.estimate()
	if !evidence {
		return 0
	}
	return time.Duration(rtt)
}

// Score is what the ranking sorts on, at this instant.
func (s *Server) Score() time.Duration {
	return time.Duration(s.score(time.Now().UnixNano()))
}

// score is Score against a clock the caller already read — the ranking
// reads it once for a whole list rather than once per server.
func (s *Server) score(nowNs int64) int64 {
	base, fails, evidence := s.estimate()
	if !evidence {
		// Nothing answered: the seed is what a guess is worth, unless a
		// floor from a cancelled attempt has already proven it is worse
		// than that. The extra nanosecond is the tie-break — a server
		// measured at exactly this price is still a measurement, and a
		// guess must not share the front of the list with it.
		if base < rttUnknownSeed {
			base = rttUnknownSeed
		}
		base++
	}
	if fails > 0 {
		penalty := fails * failurePenaltyStep
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
// The caller hands over a fresh copy of the delegation each lookup, so
// this is a sort of an arbitrary order rather than a re-sort of the last
// ranking. Insertion still wins it at these sizes — the comparison is two
// int64s in a slice the ranking has just filled — and up to
// sortStackServers it runs entirely on the stack. Insertion is quadratic
// though, and the size of a delegation is not ours to choose: an address
// set is written by whoever runs the zone. Past sortInsertionMax the
// ranking hands the set to a general sort, which is what keeps an
// oversized referral from costing more than it should.
func Sort(list []*Server) {
	n := len(list)
	if n < 2 {
		return
	}
	now := time.Now().UnixNano()
	switch {
	case n <= sortStackServers:
		var scores [sortStackServers]int64
		rankInsertion(list, scores[:n], now)
	case n <= sortInsertionMax:
		rankInsertion(list, make([]int64, n), now)
	default:
		rankSorted(list, now)
	}
}

func rankInsertion(list []*Server, scores []int64, now int64) {
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

// rankSorted is the same ranking for a set too big to insertion-sort. Each
// score is read once and carried next to its server, so the comparator
// never re-reads an atomic mid-sort: a concurrent observation would
// otherwise change the order underneath the sort that is using it.
func rankSorted(list []*Server, now int64) {
	type ranked struct {
		score  int64
		server *Server
	}
	pairs := make([]ranked, len(list))
	for i, s := range list {
		pairs[i] = ranked{score: s.score(now), server: s}
	}
	slices.SortStableFunc(pairs, func(a, b ranked) int { return cmp.Compare(a.score, b.score) })
	scores := make([]int64, len(list))
	for i, p := range pairs {
		scores[i], list[i] = p.score, p.server
	}
	hedge(list, scores)
}

// leadable reports whether a server has earned the query itself: an
// exchange completed and the last one was not a failure. A first attempt
// that timed out completes an exchange without answering anything, and it
// must not be promoted over a server nobody has tried — the failure is
// what we know about it, and it is worse than not knowing.
func leadable(s *Server) bool {
	_, fails, evidence := s.estimate()
	return evidence && fails == 0
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
	// The seed prices a guess at 300ms, which is the right expectation to
	// rank on — but it also means a guess outranks an authority measured
	// slower than that, and the query itself should not be an experiment.
	// A server that has earned the query takes it; the guess moves to the
	// hedge slot, which is where unknowns are meant to be probed.
	if !leadable(list[0]) {
		for i := 1; i < n; i++ {
			if leadable(list[i]) {
				list[0], list[i] = list[i], list[0]
				scores[0], scores[i] = scores[i], scores[0]
				break
			}
		}
	}
	if randN(exploreOdds) == 0 {
		// Any of them, not the first of them. The unmeasured all carry
		// the same score, the sort is stable, and a floor below the seed
		// changes nothing — so taking the first would probe one address
		// forever and leave the rest of a delegation permanently unknown.
		candidates := 0
		for i := 1; i < n; i++ {
			if _, _, evidence := list[i].estimate(); !evidence {
				candidates++
			}
		}
		if candidates > 0 {
			pick := randN(candidates)
			for i := 1; i < n; i++ {
				if _, _, evidence := list[i].estimate(); evidence {
					continue
				}
				if pick == 0 {
					list[1], list[i] = list[i], list[1]
					return
				}
				pick--
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
