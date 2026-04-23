// Package hostsfile implements a high-performance hosts file resolver
// with advanced features like wildcard support and automatic reloading
package hostsfile

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

// HostsDB is an in-memory database for hosts entries
// Unlike traditional implementations, we support wildcards and aliases.
type HostsDB struct {
	// Read-write lock for concurrent access
	mu sync.RWMutex

	// Forward lookups: hostname -> IPs
	hosts map[string]*HostEntry

	// Reverse lookups: IP -> hostnames
	reverse map[string][]string

	// Pre-built PTR answers keyed by the canonical reverse IP returned
	// by util.IPFromReverseName. Share-safe across queries: the RRs are
	// read-only after load.
	ptrs map[string][]dns.RR

	// Wildcard entries for pattern matching
	wildcards []*WildcardEntry

	// Statistics
	stats struct {
		entries   int64
		wildcards int64
		lookups   uint64
		hits      uint64
	}
}

// HostEntry represents a single host with multiple IPs and metadata.
// The a/aaaa/cname fields hold pre-built RR slices so lookups can
// return them without allocating on the hot path.
type HostEntry struct {
	Name      string
	IPv4      []net.IP
	IPv6      []net.IP
	Aliases   []string
	Comment   string
	LineNo    int
	Timestamp time.Time

	// Pre-built, read-only answer slices. aRRs has the A records,
	// aaaaRRs has the AAAA records, cnameRR points at the primary
	// name for aliases. Nil means no records of that type.
	aRRs    []dns.RR
	aaaaRRs []dns.RR
	cnameRR dns.RR
}

// WildcardEntry represents a wildcard pattern.
type WildcardEntry struct {
	Pattern   string
	IPv4      []net.IP
	IPv6      []net.IP
	Timestamp time.Time
}

// Hostsfile middleware provides local name resolution.
type Hostsfile struct {
	path       string
	db         atomic.Value // *HostsDB
	watcher    *fsnotify.Watcher
	reloadTime time.Time
	ttl        uint32
}

// New creates a new Hostsfile middleware.
func New(cfg *config.Config) *Hostsfile {
	if cfg.HostsFile == "" {
		return nil
	}

	h := &Hostsfile{
		path: cfg.HostsFile,
		ttl:  600, // 10 minutes default TTL
	}

	// Initial load
	if err := h.load(); err != nil {
		zlog.Error("Failed to load hosts file", "path", h.path, "error", err)
		return nil
	}

	// Setup file watcher
	if err := h.setupWatcher(); err != nil {
		zlog.Warn("Failed to setup hosts file watcher", "error", err)
	}

	return h
}

// (*Hostsfile).Name name returns the middleware name.
func (h *Hostsfile) Name() string {
	return name
}

// (*Hostsfile).ServeDNS serveDNS handles DNS queries using the hosts database.
func (h *Hostsfile) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	// Safety check for nil receiver
	if h == nil {
		ch.Next(ctx)
		return
	}

	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 {
		ch.Next(ctx)
		return
	}

	q := req.Question[0]
	db := h.getDB()

	// Increment lookup counter
	atomic.AddUint64(&db.stats.lookups, 1)

	// Handle different query types
	var answer []dns.RR
	var found bool

	switch q.Qtype {
	case dns.TypeA:
		answer, found = h.lookupA(db, q.Name)
	case dns.TypeAAAA:
		answer, found = h.lookupAAAA(db, q.Name)
	case dns.TypePTR:
		answer, found = h.lookupPTR(db, q.Name)
	case dns.TypeCNAME:
		answer, found = h.lookupCNAME(db, q.Name)
	default:
		// For other types, check if host exists to return NODATA
		if h.hostExists(db, q.Name) {
			found = true
		}
	}

	if !found {
		ch.Next(ctx)
		return
	}

	// Increment hit counter
	atomic.AddUint64(&db.stats.hits, 1)

	// Build response. Bypass SetReply so we don't allocate a new
	// Question slice: miekg/dns's SetReply copies req.Question; ours
	// aliases it, which is safe because the hosts file chain cancels
	// before any downstream middleware can mutate the request.
	//
	// Header fields mirror SetReply for OpcodeQuery: id, opcode,
	// response + RD + CD copied from request, Authoritative and RA
	// set by us. CD is wire-visible and used in cache keying
	// elsewhere in the project, so it must round-trip.
	resp := new(dns.Msg)
	resp.MsgHdr = dns.MsgHdr{
		Id:                 req.Id,
		Response:           true,
		Opcode:             req.Opcode,
		Authoritative:      true,
		RecursionDesired:   req.RecursionDesired,
		RecursionAvailable: true,
		CheckingDisabled:   req.CheckingDisabled,
	}
	resp.Question = req.Question
	resp.Answer = answer

	_ = w.WriteMsg(resp)
	ch.Cancel()
}

// lookupA finds A records for a hostname.
func (h *Hostsfile) lookupA(db *HostsDB, name string) ([]dns.RR, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := lookupKey(name)

	// Direct lookup — return the pre-built shared slice.
	if entry, ok := db.hosts[key]; ok && len(entry.aRRs) > 0 {
		return entry.aRRs, true
	}

	// Wildcard fallback still builds RRs at query time because the
	// owner name depends on the query. Wildcards are uncommon in
	// practice, so the allocation here is acceptable.
	for _, wc := range db.wildcards {
		if matchWildcard(wc.Pattern, key) && len(wc.IPv4) > 0 {
			return buildARRs(key, wc.IPv4, h.ttl), true
		}
	}
	return nil, false
}

// lookupAAAA finds AAAA records for a hostname.
func (h *Hostsfile) lookupAAAA(db *HostsDB, name string) ([]dns.RR, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := lookupKey(name)

	if entry, ok := db.hosts[key]; ok && len(entry.aaaaRRs) > 0 {
		return entry.aaaaRRs, true
	}

	for _, wc := range db.wildcards {
		if matchWildcard(wc.Pattern, key) && len(wc.IPv6) > 0 {
			return buildAAAARRs(key, wc.IPv6, h.ttl), true
		}
	}
	return nil, false
}

// lookupPTR finds PTR records for an IP address.
func (h *Hostsfile) lookupPTR(db *HostsDB, name string) ([]dns.RR, bool) {
	ip := util.IPFromReverseName(name)
	if ip == "" {
		return nil, false
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	// PTRs are indexed by the reverse-IP key used at load time, so
	// we return the pre-built slice if present.
	if rrs, ok := db.ptrs[ip]; ok && len(rrs) > 0 {
		return rrs, true
	}
	return nil, false
}

// lookupCNAME finds CNAME records (aliases).
func (h *Hostsfile) lookupCNAME(db *HostsDB, name string) ([]dns.RR, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := lookupKey(name)

	if entry, ok := db.hosts[key]; ok && entry.cnameRR != nil {
		return []dns.RR{entry.cnameRR}, true
	}
	return nil, false
}

// hostExists checks if a hostname exists in the database.
func (h *Hostsfile) hostExists(db *HostsDB, name string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := lookupKey(name)
	if _, ok := db.hosts[key]; ok {
		return true
	}
	for _, wc := range db.wildcards {
		if matchWildcard(wc.Pattern, key) {
			return true
		}
	}
	return false
}

// load reads and parses the hosts file.
func (h *Hostsfile) load() error {
	file, err := os.Open(h.path)
	if err != nil {
		return err
	}
	defer file.Close()

	db := &HostsDB{
		hosts:   make(map[string]*HostEntry),
		reverse: make(map[string][]string),
		ptrs:    make(map[string][]dns.RR),
	}

	scanner := bufio.NewScanner(file)
	lineNo := 0
	now := time.Now()

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		ip, hostnames, comment := parseLine(line)
		if ip == nil || len(hostnames) == 0 {
			continue
		}

		// Check all hostnames for wildcards
		hasWildcard := false
		wildcardHostname := ""
		for _, h := range hostnames {
			if strings.Contains(h, "*") {
				hasWildcard = true
				wildcardHostname = h
				break
			}
		}

		// Handle wildcard entries
		if hasWildcard {
			wc := &WildcardEntry{
				Pattern:   wildcardHostname,
				Timestamp: now,
			}
			if ip.To4() != nil {
				wc.IPv4 = []net.IP{ip}
			} else {
				wc.IPv6 = []net.IP{ip}
			}
			db.wildcards = append(db.wildcards, wc)
			atomic.AddInt64(&db.stats.wildcards, 1)
			continue
		}

		primaryName := strings.ToLower(hostnames[0])

		entry, exists := db.hosts[primaryName]
		if !exists {
			entry = &HostEntry{
				Name:      primaryName,
				LineNo:    lineNo,
				Comment:   comment,
				Timestamp: now,
			}
			db.hosts[primaryName] = entry
			atomic.AddInt64(&db.stats.entries, 1)
		}

		if ip.To4() != nil {
			entry.IPv4 = append(entry.IPv4, ip)
		} else {
			entry.IPv6 = append(entry.IPv6, ip)
		}

		ipStr := ip.String()
		db.reverse[ipStr] = append(db.reverse[ipStr], primaryName)

		// Alias entries each get their own HostEntry + their own
		// pre-built A/AAAA/CNAME answers.
		for i := 1; i < len(hostnames); i++ {
			alias := strings.ToLower(hostnames[i])
			entry.Aliases = append(entry.Aliases, alias)

			aliasEntry := &HostEntry{
				Name:      alias,
				LineNo:    lineNo,
				Timestamp: now,
			}
			if ip.To4() != nil {
				aliasEntry.IPv4 = []net.IP{ip}
			} else {
				aliasEntry.IPv6 = []net.IP{ip}
			}
			// CNAME: alias → primary
			aliasEntry.cnameRR = &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   alias + ".",
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    h.ttl,
				},
				Target: primaryName + ".",
			}
			db.hosts[alias] = aliasEntry
			atomic.AddInt64(&db.stats.entries, 1)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Second pass: pre-build the A / AAAA / PTR answer slices now
	// that every entry knows its full IP list. Building here keeps
	// the query path allocation-free.
	for _, entry := range db.hosts {
		if len(entry.IPv4) > 0 {
			entry.aRRs = buildARRs(entry.Name, entry.IPv4, h.ttl)
		}
		if len(entry.IPv6) > 0 {
			entry.aaaaRRs = buildAAAARRs(entry.Name, entry.IPv6, h.ttl)
		}
	}
	for ipStr, names := range db.reverse {
		db.ptrs[ipStr] = buildPTRs(ipStr, names, h.ttl)
	}

	h.db.Store(db)
	h.reloadTime = time.Now()

	zlog.Info("Loaded hosts file",
		"path", h.path,
		"entries", atomic.LoadInt64(&db.stats.entries),
		"wildcards", atomic.LoadInt64(&db.stats.wildcards),
	)

	return nil
}

// setupWatcher creates a file watcher for auto-reload.
func (h *Hostsfile) setupWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	h.watcher = watcher

	// Watch the directory, not the file (handles editors that replace files)
	dir := filepath.Dir(h.path)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close() //nolint:gosec // G104 - closing on error path
		return err
	}

	go h.watchLoop()

	return nil
}

// watchLoop handles file change events.
func (h *Hostsfile) watchLoop() {
	defer h.watcher.Close()

	// Debounce timer to avoid multiple reloads
	var debounceTimer *time.Timer

	for {
		select {
		case event, ok := <-h.watcher.Events:
			if !ok {
				return
			}

			// Check if it's our file
			if filepath.Base(event.Name) != filepath.Base(h.path) {
				continue
			}

			// Debounce events
			if debounceTimer != nil {
				debounceTimer.Stop()
			}

			debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
				if err := h.load(); err != nil {
					zlog.Error("Failed to reload hosts file", "error", err)
				}
			})

		case err, ok := <-h.watcher.Errors:
			if !ok {
				return
			}
			zlog.Error("Hosts file watcher error", "error", err)
		}
	}
}

// getDB returns the current hosts database.
func (h *Hostsfile) getDB() *HostsDB {
	return h.db.Load().(*HostsDB)
}

// (*Hostsfile).Stats stats returns usage statistics.
func (h *Hostsfile) Stats() map[string]any {
	db := h.getDB()

	return map[string]any{
		"entries":     atomic.LoadInt64(&db.stats.entries),
		"wildcards":   atomic.LoadInt64(&db.stats.wildcards),
		"lookups":     atomic.LoadUint64(&db.stats.lookups),
		"hits":        atomic.LoadUint64(&db.stats.hits),
		"reload_time": h.reloadTime.Format(time.RFC3339),
	}
}

// parseLine parses a single hosts file line.
func parseLine(line string) (net.IP, []string, string) {
	// Remove comments
	comment := ""
	if idx := strings.Index(line, "#"); idx >= 0 {
		comment = strings.TrimSpace(line[idx+1:])
		line = line[:idx]
	}

	// Split fields
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, nil, ""
	}

	// Parse IP - handle IPv6 zone identifiers
	ipStr := fields[0]
	if i := strings.Index(ipStr, "%"); i >= 0 {
		ipStr = ipStr[:i]
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, ""
	}

	return ip, fields[1:], comment
}

// matchWildcard checks if a name matches a wildcard pattern.
//
// For "*.example.com" this must match the apex "example.com"
// and any subdomain like "foo.example.com" — but NOT a sibling
// like "badexample.com". The earlier HasSuffix(name, suffix)
// check would accept the sibling because the dot boundary
// wasn't enforced.
func matchWildcard(pattern, name string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if name == suffix {
			return true
		}
		return strings.HasSuffix(name, "."+suffix)
	}

	// TODO: Implement more complex wildcard patterns if needed
	return false
}

// buildARRs pre-builds the shared []dns.RR slice for an A record set.
// The returned slice is immutable and may be returned directly from
// lookupA across concurrent queries.
func buildARRs(name string, ips []net.IP, ttl uint32) []dns.RR {
	out := make([]dns.RR, 0, len(ips))
	fqdn := name + "."
	for _, ip := range ips {
		out = append(out, &dns.A{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: ip,
		})
	}
	return out
}

func buildAAAARRs(name string, ips []net.IP, ttl uint32) []dns.RR {
	out := make([]dns.RR, 0, len(ips))
	fqdn := name + "."
	for _, ip := range ips {
		out = append(out, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			AAAA: ip,
		})
	}
	return out
}

// buildPTRs pre-builds PTR answers keyed by reverse-IP. Note that the
// owner name in each RR is the reverse-name form; util.IPFromReverseName
// does not tell us what the original reverse name looked like, so we
// reconstruct it from the IP via a canonical form.
func buildPTRs(ip string, names []string, ttl uint32) []dns.RR {
	rname := reverseName(ip)
	if rname == "" {
		return nil
	}
	out := make([]dns.RR, 0, len(names))
	for _, hostname := range names {
		out = append(out, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   rname,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Ptr: hostname + ".",
		})
	}
	return out
}

// reverseName converts an IP string to its canonical reverse-DNS name.
// IPv4 "192.0.2.1" → "1.2.0.192.in-addr.arpa.", IPv6 → ".ip6.arpa." form.
// Returns empty string on unparseable input.
func reverseName(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	name, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}
	return name
}

// lookupKey normalises a DNS query name into the lowercase, no-trailing-dot
// form used by the hosts map. Allocates only when the name contains
// uppercase bytes; for the common dnsperf / production case where names
// arrive already lowercase, the returned string shares backing memory
// with the input and the call is alloc-free.
func lookupKey(name string) string {
	n := len(name)
	if n == 0 {
		return name
	}
	if name[n-1] == '.' {
		name = name[:n-1]
		n--
	}
	for i := 0; i < n; i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			// Uppercase found — fall through to the allocating path.
			b := make([]byte, n)
			copy(b, name)
			for j := i; j < n; j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return name
}

const name = "hostsfile"
