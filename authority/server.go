package authority

import (
	"hash/fnv"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Server type.
type Server struct {
	// place atomic members at the start to fix alignment for ARM32
	Rtt       int64
	Count     int64
	Addr      string
	IPVersion IPVersion

	// UDPAddr is Addr pre-parsed as *net.UDPAddr so the upstream
	// exchange path can use net.DialUDP directly instead of going
	// through Dialer.DialContext's string-parsing + dialParallel
	// machinery. Nil only if Addr failed to parse — callers fall
	// back to the string path in that case.
	UDPAddr *net.UDPAddr
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
func NewServer(addr string, ipVersion IPVersion) *Server {
	s := &Server{
		Addr:      addr,
		IPVersion: ipVersion,
	}
	if ua, err := net.ResolveUDPAddr("udp", addr); err == nil {
		s.UDPAddr = ua
	}
	return s
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
	count := atomic.LoadInt64(&a.Count)
	rn := atomic.LoadInt64(&a.Rtt)

	if count == 0 {
		count = 1
	}

	var health string
	switch {
	case rn >= int64(time.Second):
		health = "POOR"
	case rn > 0:
		health = "GOOD"
	default:
		health = "UNKNOWN"
	}

	rtt := (time.Duration(rn) / time.Duration(count)).Round(time.Millisecond)

	return a.IPVersion.String() + ":" + a.Addr + " rtt:" + rtt.String() + " health:[" + health + "]"
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

// Sort sort servers by rtt.
func Sort(serversList []*Server, called uint64) {
	for _, s := range serversList {
		// clear stats and re-start again
		if called%1e3 == 0 {
			atomic.StoreInt64(&s.Rtt, 0)
			atomic.StoreInt64(&s.Count, 0)

			continue
		}

		rtt := atomic.LoadInt64(&s.Rtt)
		count := atomic.LoadInt64(&s.Count)

		if count > 0 {
			// average rtt
			atomic.StoreInt64(&s.Rtt, rtt/count)
			atomic.StoreInt64(&s.Count, 1)
		}
	}
	sort.Slice(serversList, func(i, j int) bool {
		return atomic.LoadInt64(&serversList[i].Rtt) < atomic.LoadInt64(&serversList[j].Rtt)
	})
}
