package authority

import (
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Server type.
type Server struct {
	// place atomic members at the start to fix alignment for ARM32
	//
	// state is what one exchange says about this server, in one word:
	// [estimate ns : 62][answered : 1][measured : 1]. They are packed
	// because they have to change together — a sample that lands between
	// reading one and writing the other could otherwise replace a
	// measurement instead of folding into it.
	state int64
	// lastNs is when state was last refreshed, in Unix nanoseconds. It is
	// what ages a measurement per server, replacing a periodic wipe that
	// aged the whole set at once.
	lastNs    int64
	Addr      string
	IPVersion IPVersion

	// canonical records that Addr was printed from a decoded address and is
	// therefore already the identity spelling — what duplicate suppression
	// compares and what the retry guard keys on. Deriving that identity by
	// parsing Addr and printing it back produced a string per server per
	// lookup, for a string this constructor had just built.
	//
	// It sits next to IPVersion so it lands in the padding those two share,
	// and knowing this costs the Server nothing. False only when Addr was
	// never an IP:port literal, where the spelling is not the identity and
	// callers must normalize.
	canonical bool

	// UDPAddr is Addr pre-parsed as *net.UDPAddr so the upstream
	// exchange path can use net.DialUDP directly instead of going
	// through Dialer.DialContext's string-parsing + dialParallel
	// machinery. Nil only if Addr failed to parse — callers fall
	// back to the string path in that case.
	UDPAddr *net.UDPAddr
}

// CanonicalAddr returns Addr together with whether it is already in the
// canonical spelling. A caller that keys on the endpoint can use the string
// as-is when this reports true, and must normalize it otherwise.
func (a *Server) CanonicalAddr() (string, bool) {
	if a == nil {
		return "", false
	}
	return a.Addr, a.canonical
}

// IPVersion type.
type IPVersion byte

const (
	// IPv4 mode.
	IPv4 IPVersion = 0x1

	// IPv6 mode.
	IPv6 IPVersion = 0x2
)

// NewServer return a new server. addr is expected to be an
// "IP:port" pair — the IP is parsed once here so upstream exchanges
// can skip Go's DialContext address-resolution path.
//
// Addr is stored in canonical netip form (lowercase, compressed,
// 4-in-6 unmapped). Every producer builds addr from an IP literal
// (glue A/AAAA String, configured roots), so the canonical form is
// what comparison sites and map keys already see; deriving it here
// keeps one string per server instead of the parse chain's residue.
func NewServer(addr string, ipVersion IPVersion) *Server {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return NewServerFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	s := &Server{
		Addr:      addr,
		IPVersion: ipVersion,
	}
	if ua, err := net.ResolveUDPAddr("udp", addr); err == nil {
		// Non-literal input (tests, exotic callers): keep the historical
		// resolution fallback.
		s.UDPAddr = ua
	}
	return s
}

// NewServerFromAddrPort builds a Server straight from a decoded address —
// the netip-native producer path (glue records, NS-address lookups) that
// never materializes an intermediate "IP:port" string. The IP family is
// derived from the address itself, and the canonical string is created
// exactly once here for the key/log surfaces that need it.
func NewServerFromAddrPort(ap netip.AddrPort) *Server {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	version := IPv4
	if !ap.Addr().Is4() {
		version = IPv6
	}
	return &Server{
		Addr:      ap.String(),
		IPVersion: version,
		UDPAddr:   net.UDPAddrFromAddrPort(ap),
		// The zero AddrPort prints as "invalid AddrPort", which is a
		// spelling and not an address. No producer hands one over, but the
		// marker is a promise about Addr and must not be made about that.
		canonical: ap.IsValid(),
	}
}

func (v IPVersion) String() string {
	switch v {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

func (a *Server) String() string {
	measured := a.SmoothedRTT()

	// FAILING comes before POOR because it says something the latency
	// cannot: a server that does not reply is charged a timeout, and a
	// timeout is also what a very slow server costs, so priced alone the
	// two are indistinguishable to whoever is reading this.
	var health string
	switch {
	case measured == 0:
		health = "UNKNOWN"
	case !a.Answering():
		health = "FAILING"
	case measured >= time.Second:
		health = "POOR"
	default:
		health = "GOOD"
	}

	rtt := "unknown"
	if measured != 0 {
		rtt = measured.Round(time.Millisecond).String()
	}

	// The score is what the ranking actually sorts on, and it is not the
	// latency: an unmeasured server is priced at the seed, and an old
	// measurement drifts back toward it. Printing both is what makes the
	// order this reports explicable.
	return a.IPVersion.String() + ":" + a.Addr + " rtt:" + rtt +
		" rank:" + a.Score().Round(time.Millisecond).String() +
		" health:[" + health + "]"
}

// fpEntry caches a Fingerprint() result along with the generation
// number it was computed against. Publishing the pair atomically via
// atomic.Pointer closes the race where a writer mutated List between
// a reader's snapshot and its cache-store: the reader checks the
// generation at publish time and drops its result if it no longer
// matches, so a stale hash cannot be resurrected as valid.
type fpEntry struct {
	gen uint64
	fp  uint64
}

// Servers type.
type Servers struct {
	sync.RWMutex
	// place atomic members at the start to fix alignment for ARM32
	ErrorCount uint32

	// gen is bumped on every List mutation by InvalidateFingerprint.
	// fpCache holds the last Fingerprint() result paired with the gen
	// it was computed against; a reader only trusts the cache when
	// fpCache.gen == gen. Storing them together through atomic.Pointer
	// ensures readers never see a (gen, fp) pair that was constructed
	// from different snapshots.
	gen     atomic.Uint64
	fpCache atomic.Pointer[fpEntry]

	Zone string

	List  []*Server
	Hosts []string

	CheckingDisable bool
	Checked         bool
}

// Fingerprint returns a stable identifier for the current List.Addr
// set. Callers must not hold the Servers lock.
func (a *Servers) Fingerprint() uint64 {
	// Fast path: cached entry whose generation matches the current
	// mutation counter.
	gen := a.gen.Load()
	if e := a.fpCache.Load(); e != nil && e.gen == gen {
		return e.fp
	}

	// Slow path: snapshot under RLock, read the generation inside the
	// lock so it corresponds to the List state we sampled, compute the
	// hash outside the lock, and only publish if the generation still
	// matches at store time. If a writer bumped gen while we were
	// hashing, the result corresponds to an outdated state and must
	// not replace any newer cached entry.
	a.RLock()
	gen = a.gen.Load()
	addrs := make([]string, 0, len(a.List))
	for _, s := range a.List {
		addrs = append(addrs, s.Addr)
	}
	a.RUnlock()
	sort.Strings(addrs)
	h := fnv.New64a()
	for _, s := range addrs {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	fp := h.Sum64()
	if a.gen.Load() == gen {
		a.fpCache.Store(&fpEntry{gen: gen, fp: fp})
	}
	return fp
}

// InvalidateFingerprint must be called whenever List is mutated. It has
// to run *before* the mutator releases the Servers write lock so
// readers can't observe the mutated List with a still-valid cached
// hash. A single atomic increment is cheap enough to keep inside the
// critical section.
func (a *Servers) InvalidateFingerprint() {
	a.gen.Add(1)
}

const (
	// rttUnknownSeed is what "no data" is worth. Zero — the value a fresh
	// Server carries — ranked no-data as instant, which handed the head of
	// the list to whichever address had never answered; with the resolver
	// starting its top two in parallel, that spent one of every miss's two
	// queries on the one server whose speed nobody had established. The
	// seed sits above a healthy authority and below a sick one: an
	// unmeasured server is worth trying, never worth preferring.
	rttUnknownSeed = int64(300 * time.Millisecond)

	// staleAfter is when a measurement stops counting as fresh evidence.
	// It replaces clearing every server's statistics every thousandth
	// sort, which aged the whole set at once and returned all of them to
	// the unmeasured state the ranking treated as fastest.
	staleAfter = int64(5 * time.Minute)

	// sortStackServers is the largest address set ranked without touching
	// the heap. The root names thirteen; a delegation past this is rare
	// enough to pay for a slice.
	sortStackServers = 32
)

// The state word: [ estimate ns : 62 ][ answered : 1 ][ measured : 1 ].
//
// measured says an exchange has completed, which is what separates an
// estimate from the seed. answered says the last one came back with an
// answer, and nothing is decided on it — it is there so an operator
// reading the delegation can tell a slow authority from one that is not
// replying at all. Priced by the ranking the two look alike, because a
// server that does not answer is charged a timeout, and a timeout is
// also what a very slow server costs.
const (
	stateMeasured = 1
	stateAnswered = 2
	stateRTTShift = 2
)

// Observe records a completed exchange: how long this server took to
// answer. The estimate is blended half and half with each new sample, so
// one bad sample is visible in the ranking immediately — which is what a
// resolver needs when an authority starts to degrade. A running average
// over every sample ever taken needed dozens of them to notice.
func (s *Server) Observe(d time.Duration) { s.record(d, true) }

// ObserveNoAnswer records an exchange that came back with no answer — a
// timeout, a transport error, a refusal. The caller prices it, and prices
// it as a timeout; this only adds that the authority did not reply.
func (s *Server) ObserveNoAnswer(d time.Duration) { s.record(d, false) }

// record folds a sample into the estimate.
//
// The loop is there because a root address is in flight from several
// lookups at once. Read, decide, write as separate steps kept only
// whichever store landed last; the compare-and-swap carries the estimate
// and both its bits together, so a sample that is counted is a sample
// that moved the estimate.
func (s *Server) record(d time.Duration, answered bool) {
	// A completed exchange took some time, whatever the clock managed to
	// see. Recording a zero would make it unreadable: the estimate and
	// "nothing has answered" are told apart by the estimate being zero, so
	// a sample of zero is a measurement that reports itself as the absence
	// of one — priced at the seed, explored forever, and never allowed to
	// lead however fast it actually is. Windows' coarse timer produces it
	// for a loopback exchange; a LAN authority on any platform is one
	// clock granularity away from it.
	sample := int64(d)
	if sample < 1 {
		sample = 1
	}
	for {
		w := atomic.LoadInt64(&s.state)
		next := sample
		if w&stateMeasured != 0 {
			next = (w>>stateRTTShift + sample) / 2
		}
		packed := next<<stateRTTShift | stateMeasured
		if answered {
			packed |= stateAnswered
		}
		if atomic.CompareAndSwapInt64(&s.state, w, packed) {
			break
		}
	}
	atomic.StoreInt64(&s.lastNs, time.Now().UnixNano())
}

// Answering reports whether the last completed exchange came back with an
// answer. Unmeasured servers report true: nothing has failed yet.
func (s *Server) Answering() bool {
	w := atomic.LoadInt64(&s.state)
	return w&stateMeasured == 0 || w&stateAnswered != 0
}

// SmoothedRTT is the measured latency, or zero when nothing has answered.
// The adaptive per-server timeout reads this rather than the ranking
// score: a timeout should follow how fast the server is, not how far the
// ranking has priced it down.
func (s *Server) SmoothedRTT() time.Duration {
	w := atomic.LoadInt64(&s.state)
	if w&stateMeasured == 0 {
		return 0
	}
	return time.Duration(w >> stateRTTShift)
}

// Score is what the ranking sorts on, at this instant.
func (s *Server) Score() time.Duration {
	score, _ := s.score(time.Now().UnixNano())
	return time.Duration(score)
}

// score also reports whether what is known about this server is out of
// date — nothing has answered, or what did answer is old enough that it
// no longer describes the path. It comes back from here because the
// scoring pass has already paid for both loads, and the ranking needs the
// count to decide how much of the hedge to spend on finding out.
func (s *Server) score(nowNs int64) (int64, bool) {
	w := atomic.LoadInt64(&s.state)
	base := w >> stateRTTShift
	if w&stateMeasured == 0 {
		// Nothing has answered: a guess is priced at the seed. The extra
		// nanosecond is the tie-break, so a server measured at exactly
		// that price still outranks the guess.
		return rttUnknownSeed + 1, true
	}
	if last := atomic.LoadInt64(&s.lastNs); last != 0 && nowNs-last > staleAfter {
		// Halfway back toward a guess: old evidence is weakened, not
		// discarded, so a server that was fast an hour ago still outranks
		// one that was slow an hour ago.
		//
		// And it is worth asking about again. A first impression can be
		// very wrong — an address that timed out once while the resolver
		// was walking a cold delegation carries that timeout for a long
		// time, and it is priced below the guesses, so nothing would ever
		// query it again. Measured on a production resolver: five of com.'s
		// addresses sitting at 535ms, all of them answering in under 60ms
		// when finally asked.
		return (base + rttUnknownSeed) / 2, true
	}
	return base, false
}

// Sort ranks a delegation's addresses in place, fastest first. It runs on
// every cache miss, so it allocates nothing for the sets a resolver
// actually meets: the scores are read once into a small array and the
// pass over them is insertion, which is the cheapest thing for a handful
// of addresses and does not need a closure the way sort.Slice does.
//
// It returns the server the second slot is spending on an exploration
// probe, or nil when that slot is an ordinary hedge. The caller has to
// treat the two differently: a hedge is a spare answer, worth nothing
// once the leader has answered, and cancelling it is right. A probe is
// worth only the measurement it brings back, and cancelling it brings
// none — which is what happens by default, every time, because the leader
// is by construction the fastest server in the list.
func Sort(serversList []*Server) *Server {
	n := len(serversList)
	if n < 2 {
		return nil
	}
	now := time.Now().UnixNano()
	if n <= sortStackServers {
		var scores [sortStackServers]int64
		return rank(serversList, scores[:n], now)
	}
	return rank(serversList, make([]int64, n), now)
}

func rank(list []*Server, scores []int64, now int64) *Server {
	// How much of this delegation is out of date falls out of the scoring
	// pass, which has already read what it takes to know. The count is
	// what sets the exploration rate: how much of the hedge is worth
	// spending on finding out is exactly how much there is left to find
	// out.
	stale := 0
	for i, s := range list {
		var old bool
		scores[i], old = s.score(now)
		if old {
			stale++
		}
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
	return hedge(list, scores, now, stale)
}

// randN is the ranking's only source of randomness, replaceable so a test
// can pin an order rather than chase one.
var randN = rand.IntN

// hedge decides which of the servers tied for second place takes the
// second slot. The leader is left alone — the fastest server answers the
// query — but everything level with the runner-up is, by definition,
// something the ranking has no reason to choose between.
//
// Leaving that to the sort's stability meant the same address took the
// slot on every single lookup, forever. That matters most where the tie
// is widest: a delegation's unmeasured addresses all carry the same
// price, so one of them was queried on every cache miss and the rest were
// never tried at all — and since the query is cancelled the moment the
// leader answers, the one that was tried never came back measured
// either. Eighteen unmeasured addresses, one of them getting all of the
// chances and none of them getting measured.
//
// Rotating the slot does not make a server slower than the leader
// measurable — only an attempt that outlives the winner can do that — but
// it does give every tied candidate its turn at the one thing that can
// measure it, which is winning the race outright.
// A delegation settles on two measured addresses and stops there without
// this. The parallel head is two, so two addresses get measured and rank
// ahead of the seed; from then on nothing else is level with the second
// slot, rotation has nothing to rotate, and the remaining ten or eleven
// addresses of a TLD are never contacted again. Measured on a production
// resolver: two of thirteen in use for com., net. and org. alike.
//
// So the slot goes to an address whose worth is out of date, which is the
// only way one can stop being out of date. It costs nothing the hedge was
// not already spending: the second query goes out either way, and this
// only decides where.
//
// How often is set by how much there is left to learn — the share of the
// delegation that is unmeasured or stale. A zone the resolver has just
// met explores on most lookups, because most of what it could know it
// does not; a settled one barely explores at all, because there is
// nothing to find. A fixed rate cannot be both: one in thirty-two took
// five hundred misses to reach a given address of com., which on a real
// delegation is hours, while the same rate on a zone with one unknown
// left would spend every thirty-second hedge on that one address forever.
func hedge(list []*Server, scores []int64, now int64, stale int) *Server {
	n := len(list)
	if n < 3 {
		return nil
	}

	if stale > 0 && randN(n) < stale {
		// Any of them, not the first of them: the unmeasured all carry the
		// same price, so taking the first would probe one address forever
		// and leave the rest of the delegation permanently unknown — which
		// is the shape this exists to break.
		candidates := 0
		for i := 1; i < n; i++ {
			if _, old := list[i].score(now); old {
				candidates++
			}
		}
		if candidates > 0 {
			pick := randN(candidates)
			for i := 1; i < n; i++ {
				if _, old := list[i].score(now); !old {
					continue
				}
				if pick == 0 {
					// Moved into the slot, not traded for it. A swap would
					// fling the genuine runner-up down to wherever the
					// guess came from, and the order behind the first two
					// is not decoration: it is what the resolver walks when
					// the leader does not answer, waiting out an adaptive
					// timeout at each step. Trading a known-good second for
					// a guess would put every other guess in the delegation
					// ahead of it, which on a twenty-six address zone is
					// seconds of waiting before reaching a server already
					// known to be fast.
					probe, score := list[i], scores[i]
					copy(list[2:i+1], list[1:i])
					copy(scores[2:i+1], scores[1:i])
					list[1], scores[1] = probe, score
					return probe
				}
				pick--
			}
		}
	}

	k := 2
	for k < n && scores[k] == scores[1] {
		k++
	}
	if k > 2 {
		j := 1 + randN(k-1)
		list[1], list[j] = list[j], list[1]
	}
	return nil
}
