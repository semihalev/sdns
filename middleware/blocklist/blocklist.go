package blocklist

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
)

// blocklistHits counts queries that matched a blocklist entry and
// were synthesised away from the resolver chain. Operators use this
// to monitor block effectiveness vs the legitimate query rate.
var blocklistHits = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_blocklist_hits_total",
	Help: "Total DNS queries blocked by the blocklist middleware",
})

// BlockList type
//
// Matching semantics:
//   - A bare domain (e.g. "example.com") blocks that exact name AND every
//     subdomain ("sub.example.com", "a.b.example.com", ...). This mirrors
//     how Pi-hole/AdGuard/dnsmasq treat a blocked domain and makes the
//     popular plain-domain lists (e.g. hagezi *-onlydomains) work as users
//     expect.
//   - A "*.example.com" wildcard blocks subdomains only, not the apex.
type BlockList struct {
	mu sync.RWMutex

	// saveMu serializes persistence to local disk. It is taken
	// independently of mu so the disk write happens *outside* the
	// map lock — every DNS query goes through ServeDNS which takes
	// mu.RLock(), so any code path that holds mu while doing I/O
	// stalls every concurrent query for the duration of the write.
	saveMu sync.Mutex

	nullroute  net.IP
	null6route net.IP

	m    map[string]bool // blocked domains; match the name itself and any subdomain
	wild map[string]bool // wildcard domains suffix -> true (e.g., "example.com." from "*.example.com."); subdomains only
	w    map[string]bool // whitelist

	cfg *config.Config
}

// blockSnapshot is a point-in-time copy of the BlockList's mutable
// maps, taken under mu and then written to disk without holding mu.
type blockSnapshot struct {
	exact []string
	wild  []string
}

// New returns a new BlockList.
//
// Configured whitelist/blocklist entries and existing local
// blocklist files are loaded synchronously so filtering is
// active as soon as New returns. Remote blocklist refresh
// runs asynchronously — a slow or unreachable source used to
// leave ServeDNS with empty maps for the entire HTTP timeout
// window even when local files were available.
func New(cfg *config.Config) *BlockList {
	b := &BlockList{
		nullroute:  net.ParseIP(cfg.Nullroute),
		null6route: net.ParseIP(cfg.Nullroutev6),

		m:    make(map[string]bool),
		wild: make(map[string]bool),
		w:    make(map[string]bool),

		cfg: cfg,
	}

	b.loadInitial()
	go b.refreshRemote()

	return b
}

// (*BlockList).Name name return middleware name.
func (b *BlockList) Name() string { return name }

// (*BlockList).ServeDNS serveDNS implements the Handle interface.
func (b *BlockList) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	// Fast path: skip if no blocklist entries
	b.mu.RLock()
	hasEntries := len(b.m) > 0 || len(b.wild) > 0
	b.mu.RUnlock()

	if !hasEntries {
		ch.Next(ctx)
		return
	}

	w, req := ch.Writer, ch.Request

	q := req.Question[0]

	if !b.Exists(q.Name) {
		ch.Next(ctx)
		return
	}

	blocklistHits.Inc()

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative, msg.RecursionAvailable = true, true

	switch q.Qtype {
	case dns.TypeA:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		a := &dns.A{Hdr: rrHeader, A: b.nullroute}
		msg.Answer = append(msg.Answer, a)
	case dns.TypeAAAA:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		a := &dns.AAAA{Hdr: rrHeader, AAAA: b.null6route}
		msg.Answer = append(msg.Answer, a)
	default:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    86400,
		}
		soa := &dns.SOA{
			Hdr:     rrHeader,
			Ns:      q.Name,
			Mbox:    ".",
			Serial:  0,
			Refresh: 28800,
			Retry:   7200,
			Expire:  604800,
			Minttl:  86400,
		}
		msg.Ns = append(msg.Ns, soa)
	}

	_ = w.WriteMsg(msg)

	ch.Cancel()
}

// (*BlockList).Get get returns the entry for a key or an error.
func (b *BlockList) Get(key string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	key = dns.CanonicalName(key)
	val, ok := b.m[key]

	if !ok {
		return false, errors.New("block not found")
	}

	return val, nil
}

// (*BlockList).Remove removes an entry from the blocklist.
//
// The disk write happens outside b.mu so concurrent DNS queries
// (which take mu.RLock in ServeDNS) are not blocked during I/O.
func (b *BlockList) Remove(key string) bool {
	b.mu.Lock()
	ok := b.removeLocked(key)
	if !ok {
		b.mu.Unlock()
		return false
	}
	snap := b.snapshotLocked()
	b.mu.Unlock()

	b.persist(snap)
	return true
}

// removeLocked is the in-memory mutation; caller must hold b.mu.
func (b *BlockList) removeLocked(key string) bool {
	key = dns.CanonicalName(key)

	if _, ok := b.m[key]; ok {
		delete(b.m, key)
		return true
	}

	if strings.HasPrefix(key, "*.") {
		suffix := key[2:]
		if _, ok := b.wild[suffix]; ok {
			delete(b.wild, suffix)
			return true
		}
	}

	return false
}

// (*BlockList).Set sets a value in the BlockList.
//
// The disk write happens outside b.mu so concurrent DNS queries
// (which take mu.RLock in ServeDNS) are not blocked during I/O.
func (b *BlockList) Set(key string) bool {
	b.mu.Lock()
	ok := b.setLocked(key)
	if !ok {
		b.mu.Unlock()
		return false
	}
	snap := b.snapshotLocked()
	b.mu.Unlock()

	b.persist(snap)
	return true
}

// (*BlockList).SetBatch adds multiple entries in a single mutation
// and a single disk write. Whitelisted keys are skipped. Returns
// the number actually added (excluding duplicates and whitelisted
// entries).
func (b *BlockList) SetBatch(keys []string) int {
	if len(keys) == 0 {
		return 0
	}
	added := 0
	b.mu.Lock()
	for _, key := range keys {
		if b.setLocked(key) {
			added++
		}
	}
	if added == 0 {
		b.mu.Unlock()
		return 0
	}
	snap := b.snapshotLocked()
	b.mu.Unlock()

	b.persist(snap)
	return added
}

// (*BlockList).RemoveBatch removes multiple entries in a single
// mutation and a single disk write. Returns the number actually
// removed (excluding entries that weren't present).
func (b *BlockList) RemoveBatch(keys []string) int {
	if len(keys) == 0 {
		return 0
	}
	removed := 0
	b.mu.Lock()
	for _, key := range keys {
		if b.removeLocked(key) {
			removed++
		}
	}
	if removed == 0 {
		b.mu.Unlock()
		return 0
	}
	snap := b.snapshotLocked()
	b.mu.Unlock()

	b.persist(snap)
	return removed
}

// setLocked applies a single Set in memory. Caller must hold b.mu.
// Returns false if the key is whitelisted (caller should not save).
func (b *BlockList) setLocked(key string) bool {
	key = dns.CanonicalName(key)

	if b.w[key] {
		return false
	}

	if strings.HasPrefix(key, "*.") {
		b.wild[key[2:]] = true
	} else {
		b.m[key] = true
	}
	return true
}

// set is the no-persist variant used by loadInitial and the remote
// refresh path; it does not write to disk.
func (b *BlockList) set(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.setLocked(key)
}

// (*BlockList).Exists exists returns whether or not a key exists in the cache.
func (b *BlockList) Exists(key string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	key = dns.CanonicalName(key)

	// Whitelist overrides every block (exact, parent, or wildcard). It is
	// matched across the full hierarchy — exact name plus every parent —
	// so it stays symmetric with the block walk below: just as blocking
	// "example.com." covers "sub.example.com.", whitelisting "example.com."
	// now exempts "sub.example.com." too. (Previously the whitelist matched
	// the exact name only, so a parent whitelist silently failed to protect
	// its subdomains from a parent/wildcard block.) This only ever exempts,
	// so it can never introduce a new block that breaks resolution.
	if matchHierarchy(key, b.w) {
		return false
	}

	// Direct match - fastest path (exact name)
	if b.m[key] {
		return true
	}

	// Nothing that could match as a parent suffix.
	if len(b.m) == 0 && len(b.wild) == 0 {
		return false
	}

	// Walk up the domain hierarchy. For "sub.example.com." check
	// "example.com." then "com." against both maps: a bare domain in
	// b.m covers all its subdomains, and a "*.domain" entry in b.wild
	// covers subdomains only.
	offset := 0
	for {
		idx := strings.IndexByte(key[offset:], '.')
		if idx == -1 {
			break
		}
		offset += idx + 1 // Move past the dot

		if offset < len(key) {
			suffix := key[offset:]
			if b.m[suffix] || b.wild[suffix] {
				return true
			}
		}
	}

	return false
}

// matchHierarchy reports whether name or any of its parent suffixes is a
// key in m. Names are expected in canonical (lowercase, trailing-dot) form.
func matchHierarchy(name string, m map[string]bool) bool {
	if len(m) == 0 {
		return false
	}
	if m[name] {
		return true
	}
	offset := 0
	for {
		idx := strings.IndexByte(name[offset:], '.')
		if idx == -1 {
			return false
		}
		offset += idx + 1
		if offset < len(name) && m[name[offset:]] {
			return true
		}
	}
}

// (*BlockList).Length length returns the caches length.
func (b *BlockList) Length() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.m) + len(b.wild)
}

// snapshotLocked copies the mutable maps into a slice-backed
// snapshot so the disk write can run without holding b.mu. Caller
// must hold b.mu (read or write is fine).
func (b *BlockList) snapshotLocked() blockSnapshot {
	s := blockSnapshot{
		exact: make([]string, 0, len(b.m)),
		wild:  make([]string, 0, len(b.wild)),
	}
	for d := range b.m {
		s.exact = append(s.exact, d)
	}
	for suffix := range b.wild {
		s.wild = append(s.wild, suffix)
	}
	return s
}

// persist writes the snapshot to <BlockListDir>/local via a
// temp-file + atomic rename. saveMu serializes concurrent writers
// so the rename is the linearisation point — the on-disk file
// always matches *some* in-memory state, never a half-written
// intermediate. Errors are logged-but-ignored to preserve the
// previous best-effort save() behaviour: a transient I/O failure
// must not knock a working blocklist out of memory.
func (b *BlockList) persist(s blockSnapshot) {
	b.saveMu.Lock()
	defer b.saveMu.Unlock()

	path := filepath.Join(b.cfg.BlockListDir, "local")
	tmp, err := os.CreateTemp(b.cfg.BlockListDir, "local.tmp.*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()

	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.WriteString("# The file generated by auto. DO NOT EDIT\n"); err != nil {
		_ = tmp.Close()
		cleanup()
		return
	}
	for _, d := range s.exact {
		if _, err := tmp.WriteString(d + "\n"); err != nil {
			_ = tmp.Close()
			cleanup()
			return
		}
	}
	for _, suffix := range s.wild {
		if _, err := tmp.WriteString("*." + suffix + "\n"); err != nil {
			_ = tmp.Close()
			cleanup()
			return
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return
	}
	_ = os.Rename(tmpName, path)
}

const name = "blocklist"
