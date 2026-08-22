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
	// state is the smoothed latency and the fact that an exchange has
	// completed, in one word: [estimate ns : 63][measured : 1]. They are
	// packed because they have to change together — a sample that lands
	// between reading one and writing the other could otherwise replace a
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

	var health string
	switch {
	case measured == 0:
		health = "UNKNOWN"
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
	Called     uint64
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

// Observe records a completed exchange: how long this server took to
// answer. The estimate is blended half and half with each new sample, so
// one bad sample is visible in the ranking immediately — which is what a
// resolver needs when an authority starts to degrade. A running average
// over every sample ever taken needed dozens of them to notice.
//
// The loop is there because a root address is in flight from several
// lookups at once. Read, decide, write as separate steps kept only
// whichever store landed last; the compare-and-swap carries the estimate
// and its measured bit together, so a sample that is counted is a sample
// that moved the estimate.
func (s *Server) Observe(d time.Duration) {
	sample := int64(d)
	if sample < 0 {
		sample = 0
	}
	for {
		w := atomic.LoadInt64(&s.state)
		next := sample
		if w&1 == 1 {
			next = (w>>1 + sample) / 2
		}
		if atomic.CompareAndSwapInt64(&s.state, w, next<<1|1) {
			break
		}
	}
	atomic.StoreInt64(&s.lastNs, time.Now().UnixNano())
}

// SmoothedRTT is the measured latency, or zero when nothing has answered.
// The adaptive per-server timeout reads this rather than the ranking
// score: a timeout should follow how fast the server is, not how far the
// ranking has priced it down.
func (s *Server) SmoothedRTT() time.Duration {
	w := atomic.LoadInt64(&s.state)
	if w&1 == 0 {
		return 0
	}
	return time.Duration(w >> 1)
}

// Score is what the ranking sorts on, at this instant.
func (s *Server) Score() time.Duration { return time.Duration(s.score(time.Now().UnixNano())) }

func (s *Server) score(nowNs int64) int64 {
	w := atomic.LoadInt64(&s.state)
	base := w >> 1
	if w&1 == 0 {
		// Nothing has answered: a guess is priced at the seed. The extra
		// nanosecond is the tie-break, so a server measured at exactly
		// that price still outranks the guess.
		base = rttUnknownSeed + 1
	} else if last := atomic.LoadInt64(&s.lastNs); last != 0 && nowNs-last > staleAfter {
		// Halfway back toward a guess: old evidence is weakened, not
		// discarded, so a server that was fast an hour ago still outranks
		// one that was slow an hour ago.
		base = (base + rttUnknownSeed) / 2
	}
	return base
}

// Sort ranks a delegation's addresses in place, fastest first. It runs on
// every cache miss, so it allocates nothing for the sets a resolver
// actually meets: the scores are read once into a small array and the
// pass over them is insertion, which is the cheapest thing for a handful
// of addresses and does not need a closure the way sort.Slice does.
func Sort(serversList []*Server) {
	n := len(serversList)
	if n < 2 {
		return
	}
	now := time.Now().UnixNano()
	if n <= sortStackServers {
		var scores [sortStackServers]int64
		rank(serversList, scores[:n], now)
		return
	}
	rank(serversList, make([]int64, n), now)
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
func hedge(list []*Server, scores []int64) {
	n := len(list)
	if n < 3 {
		return
	}
	k := 2
	for k < n && scores[k] == scores[1] {
		k++
	}
	if k > 2 {
		j := 1 + randN(k-1)
		list[1], list[j] = list[j], list[1]
	}
}
