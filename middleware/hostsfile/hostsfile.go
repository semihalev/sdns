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
	"github.com/semihalev/zlog"
)

// HostsDB is an in-memory database for hosts entries
// Unlike traditional implementations, we support wildcards and aliases
type HostsDB struct {
	// Read-write lock for concurrent access
	mu sync.RWMutex

	// Forward lookups: hostname -> IPs
	hosts map[string]*HostEntry

	// Reverse lookups: IP -> hostnames
	reverse map[string][]string

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

// HostEntry represents a single host with multiple IPs and metadata
type HostEntry struct {
	Name      string
	IPv4      []net.IP
	IPv6      []net.IP
	Aliases   []string
	Comment   string
	LineNo    int
	Timestamp time.Time
}

// WildcardEntry represents a wildcard pattern
type WildcardEntry struct {
	Pattern   string
	IPv4      []net.IP
	IPv6      []net.IP
	Timestamp time.Time
}

// Hostsfile middleware provides local name resolution
type Hostsfile struct {
	path       string
	db         atomic.Value // *HostsDB
	watcher    *fsnotify.Watcher
	reloadTime time.Time
	ttl        uint32
}

// New creates a new Hostsfile middleware
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

// Name returns the middleware name
func (h *Hostsfile) Name() string {
	return name
}

// ServeDNS handles DNS queries using the hosts database
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

	// Build response
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Answer = answer

	_ = w.WriteMsg(resp)
	ch.Cancel()
}

// lookupA finds A records for a hostname
func (h *Hostsfile) lookupA(db *HostsDB, name string) ([]dns.RR, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Direct lookup
	if entry, ok := db.hosts[name]; ok && len(entry.IPv4) > 0 {
		answer := make([]dns.RR, 0, len(entry.IPv4))
		for _, ip := range entry.IPv4 {
			answer = append(answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name + ".",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    h.ttl,
				},
				A: ip,
			})
		}
		return answer, true
	}

	// Check wildcards
	for _, wc := range db.wildcards {
		if matchWildcard(wc.Pattern, name) && len(wc.IPv4) > 0 {
			answer := make([]dns.RR, 0, len(wc.IPv4))
			for _, ip := range wc.IPv4 {
				answer = append(answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   name + ".",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    h.ttl,
					},
					A: ip,
				})
			}
			return answer, true
		}
	}

	return nil, false
}

// lookupAAAA finds AAAA records for a hostname
func (h *Hostsfile) lookupAAAA(db *HostsDB, name string) ([]dns.RR, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Direct lookup
	if entry, ok := db.hosts[name]; ok && len(entry.IPv6) > 0 {
		answer := make([]dns.RR, 0, len(entry.IPv6))
		for _, ip := range entry.IPv6 {
			answer = append(answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name + ".",
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    h.ttl,
				},
				AAAA: ip,
			})
		}
		return answer, true
	}

	// Check wildcards
	for _, wc := range db.wildcards {
		if matchWildcard(wc.Pattern, name) && len(wc.IPv6) > 0 {
			answer := make([]dns.RR, 0, len(wc.IPv6))
			for _, ip := range wc.IPv6 {
				answer = append(answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   name + ".",
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    h.ttl,
					},
					AAAA: ip,
				})
			}
			return answer, true
		}
	}

	return nil, false
}

// lookupPTR finds PTR records for an IP address
func (h *Hostsfile) lookupPTR(db *HostsDB, name string) ([]dns.RR, bool) {
	ip := util.IPFromReverseName(name)
	if ip == "" {
		return nil, false
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	if names, ok := db.reverse[ip]; ok && len(names) > 0 {
		answer := make([]dns.RR, 0, len(names))
		for _, hostname := range names {
			answer = append(answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    h.ttl,
				},
				Ptr: hostname + ".",
			})
		}
		return answer, true
	}

	return nil, false
}

// lookupCNAME finds CNAME records (aliases)
func (h *Hostsfile) lookupCNAME(db *HostsDB, name string) ([]dns.RR, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Check if this is an alias
	for _, entry := range db.hosts {
		for _, alias := range entry.Aliases {
			if alias == name {
				return []dns.RR{&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   name + ".",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    h.ttl,
					},
					Target: entry.Name + ".",
				}}, true
			}
		}
	}

	return nil, false
}

// hostExists checks if a hostname exists in the database
func (h *Hostsfile) hostExists(db *HostsDB, name string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Check direct entries
	if _, ok := db.hosts[name]; ok {
		return true
	}

	// Check aliases
	for _, entry := range db.hosts {
		for _, alias := range entry.Aliases {
			if alias == name {
				return true
			}
		}
	}

	// Check wildcards
	for _, wc := range db.wildcards {
		if matchWildcard(wc.Pattern, name) {
			return true
		}
	}

	return false
}

// load reads and parses the hosts file
func (h *Hostsfile) load() error {
	file, err := os.Open(h.path)
	if err != nil {
		return err
	}
	defer file.Close()

	db := &HostsDB{
		hosts:   make(map[string]*HostEntry),
		reverse: make(map[string][]string),
	}

	scanner := bufio.NewScanner(file)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		// Parse the line
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
				Timestamp: time.Now(),
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

		// Regular entries
		primaryName := strings.ToLower(hostnames[0])

		entry, exists := db.hosts[primaryName]
		if !exists {
			entry = &HostEntry{
				Name:      primaryName,
				LineNo:    lineNo,
				Comment:   comment,
				Timestamp: time.Now(),
			}
			db.hosts[primaryName] = entry
			atomic.AddInt64(&db.stats.entries, 1)
		}

		// Add IP
		if ip.To4() != nil {
			entry.IPv4 = append(entry.IPv4, ip)
		} else {
			entry.IPv6 = append(entry.IPv6, ip)
		}

		// Add reverse mapping
		ipStr := ip.String()
		db.reverse[ipStr] = append(db.reverse[ipStr], primaryName)

		// Process aliases
		for i := 1; i < len(hostnames); i++ {
			alias := strings.ToLower(hostnames[i])
			entry.Aliases = append(entry.Aliases, alias)

			// Also create direct entries for aliases
			aliasEntry := &HostEntry{
				Name:      alias,
				LineNo:    lineNo,
				Timestamp: time.Now(),
			}

			if ip.To4() != nil {
				aliasEntry.IPv4 = []net.IP{ip}
			} else {
				aliasEntry.IPv6 = []net.IP{ip}
			}

			db.hosts[alias] = aliasEntry
			atomic.AddInt64(&db.stats.entries, 1)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
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

// setupWatcher creates a file watcher for auto-reload
func (h *Hostsfile) setupWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	h.watcher = watcher

	// Watch the directory, not the file (handles editors that replace files)
	dir := filepath.Dir(h.path)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return err
	}

	go h.watchLoop()

	return nil
}

// watchLoop handles file change events
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

// getDB returns the current hosts database
func (h *Hostsfile) getDB() *HostsDB {
	return h.db.Load().(*HostsDB)
}

// Stats returns usage statistics
func (h *Hostsfile) Stats() map[string]interface{} {
	db := h.getDB()

	return map[string]interface{}{
		"entries":     atomic.LoadInt64(&db.stats.entries),
		"wildcards":   atomic.LoadInt64(&db.stats.wildcards),
		"lookups":     atomic.LoadUint64(&db.stats.lookups),
		"hits":        atomic.LoadUint64(&db.stats.hits),
		"reload_time": h.reloadTime.Format(time.RFC3339),
	}
}

// parseLine parses a single hosts file line
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

// matchWildcard checks if a name matches a wildcard pattern
func matchWildcard(pattern, name string) bool {
	// Simple wildcard matching (e.g., *.example.com)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(name, suffix) || name == suffix[1:]
	}

	// TODO: Implement more complex wildcard patterns if needed
	return false
}

const name = "hostsfile"
