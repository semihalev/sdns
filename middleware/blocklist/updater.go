package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

// hostCounter tracks download counts for each host in a type-safe way.
type hostCounter struct {
	mu     sync.RWMutex
	counts map[string]*atomic.Int64
}

func newHostCounter() *hostCounter {
	return &hostCounter{
		counts: make(map[string]*atomic.Int64),
	}
}

func (h *hostCounter) increment(host string) int64 {
	h.mu.RLock()
	counter, exists := h.counts[host]
	h.mu.RUnlock()

	if exists {
		return counter.Add(1)
	}

	// Need to create new counter
	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check after acquiring write lock
	if counter, exists := h.counts[host]; exists {
		return counter.Add(1)
	}

	// Create new counter starting at 1
	counter = &atomic.Int64{}
	counter.Store(1)
	h.counts[host] = counter
	return 1
}

var (
	timesSeen = newHostCounter()

	// httpClient is a shared HTTP client with reasonable timeout.
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
)

// maxBlocklistBytes caps the size of a single downloaded blocklist.
// 200 MiB is well above the largest real-world aggregated blocklists
// (Steven Black ~5 MiB, OISD ~15 MiB, URLhaus full ~30 MiB) while
// stopping a runaway or hostile remote from filling disk.
const maxBlocklistBytes = 200 << 20

// loadInitial applies configured whitelist/blocklist entries and
// reads any existing local blocklist files. Runs synchronously
// from New so filtering is active before the first query.
func (b *BlockList) loadInitial() {
	if b.cfg.BlockListDir == "" {
		b.cfg.BlockListDir = filepath.Join(b.cfg.Directory, "blacklists")
	}

	b.mu.Lock()
	for _, entry := range b.cfg.Whitelist {
		b.w[dns.CanonicalName(entry)] = true
	}
	b.mu.Unlock()

	for _, entry := range b.cfg.Blocklist {
		b.set(entry)
	}

	if _, err := os.Stat(b.cfg.BlockListDir); err == nil {
		if err := b.readBlocklists(); err != nil {
			zlog.Warn("Read local blocklists failed", "dir", b.cfg.BlockListDir, "error", err.Error())
		}
	}
}

// refreshRemote downloads remote blocklists and re-reads the
// directory to merge the refreshed entries. Runs as a goroutine
// so New can return once local state is loaded.
func (b *BlockList) refreshRemote() {
	<-time.After(time.Second)

	if _, err := os.Stat(b.cfg.BlockListDir); os.IsNotExist(err) {
		if err := os.Mkdir(b.cfg.BlockListDir, 0750); err != nil {
			zlog.Error("Create blocklist directory failed", "error", err.Error())
			return
		}
	}

	b.fetchBlocklist()

	if err := b.readBlocklists(); err != nil {
		zlog.Error("Read blocklists after refresh failed", "dir", b.cfg.BlockListDir, "error", err.Error())
	}
}

func (b *BlockList) downloadBlocklist(uri, name string) (err error) {
	filePath := filepath.Join(b.cfg.BlockListDir, name)

	output, err := os.Create(filePath) //nolint:gosec // G304 - path from config, not user input
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}

	// If this function returns an error, drop the partial file — it
	// otherwise lingers in the blocklist directory until the next
	// successful download of the same (host, count) and, critically,
	// is parsed by readBlocklists() in the meantime so truncated or
	// oversize content would still feed into the active blocklist.
	defer func() {
		closeErr := output.Close()
		if closeErr != nil {
			zlog.Warn("Blocklist file close failed", "name", name, "error", closeErr.Error())
		}
		if err != nil {
			if rmErr := os.Remove(filePath); rmErr != nil && !os.IsNotExist(rmErr) {
				zlog.Warn("Partial blocklist cleanup failed", "path", filePath, "error", rmErr.Error())
			}
		}
	}()

	response, err := httpClient.Get(uri)
	if err != nil {
		return fmt.Errorf("error downloading source: %w", err)
	}
	defer response.Body.Close()

	// Check response status
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	// Cap the download so a runaway or malicious remote can't fill
	// disk. Reading one byte past the cap distinguishes "exactly at
	// the cap" from "oversize" so we can fail loudly instead of
	// silently truncating.
	n, err := io.Copy(output, io.LimitReader(response.Body, maxBlocklistBytes+1))
	if err != nil {
		return fmt.Errorf("error copying output: %w", err)
	}
	if n > maxBlocklistBytes {
		return fmt.Errorf("blocklist exceeds %d bytes", maxBlocklistBytes)
	}

	return nil
}

func (b *BlockList) fetchBlocklist() {
	var wg sync.WaitGroup

	for _, uri := range b.cfg.BlockLists {
		u, err := url.Parse(uri)
		if err != nil {
			zlog.Error("Invalid blocklist URL", "uri", uri, "error", err.Error())
			continue
		}

		host := u.Host
		if host == "" {
			zlog.Error("Invalid blocklist URL: missing host", "uri", uri)
			continue
		}

		// Atomically increment the counter using our type-safe counter
		count := timesSeen.increment(host)
		fileName := fmt.Sprintf("%s.%d.tmp", host, count)

		wg.Add(1)
		go func(uri string, name string) {
			defer wg.Done()

			zlog.Info("Fetching blacklist", "uri", uri)
			if err := b.downloadBlocklist(uri, name); err != nil {
				zlog.Error("Fetching blacklist", "uri", uri, "error", err.Error())
			}
		}(uri, fileName)
	}

	wg.Wait()
}

func (b *BlockList) readBlocklists() error {
	zlog.Info("Loading blocked domains...", "path", b.cfg.BlockListDir)

	if _, err := os.Stat(b.cfg.BlockListDir); os.IsNotExist(err) {
		zlog.Warn("Path not found, skipping...", "path", b.cfg.BlockListDir)
		return nil
	}

	err := filepath.Walk(b.cfg.BlockListDir, func(path string, f os.FileInfo, walkErr error) error {
		// When Walk reports an error (unreadable dir, concurrent
		// removal, permission flip), f may be nil. Log and skip
		// that entry instead of dereferencing nil and panicking
		// the background updater.
		if walkErr != nil {
			zlog.Warn("Skipping blocklist path", "path", path, "error", walkErr.Error())
			return nil
		}
		if f == nil {
			return nil
		}
		if !f.IsDir() {
			file, err := os.Open(path) //nolint:gosec // G304 - path from walk, not user input
			if err != nil {
				return fmt.Errorf("error opening file: %w", err)
			}

			if err = b.parseHostFile(file); err != nil {
				_ = file.Close()
				return fmt.Errorf("error parsing hostfile: %w", err)
			}

			_ = file.Close()

			if filepath.Ext(path) == ".tmp" {
				_ = os.Remove(path) //nolint:gosec // G122 - trusted local temp files, not user-controlled symlinks
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking location: %w", err)
	}

	zlog.Info("Blocked domains loaded", "total", b.Length())

	return nil
}

func (b *BlockList) parseHostFile(file *os.File) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle inline comments using strings.Cut
		if domain, _, found := strings.Cut(line, "#"); found {
			line = strings.TrimSpace(domain)
		}

		// Parse hosts file format (IP domain)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// hosts-style "<ip> <name> [name...]" lines can list
		// multiple aliases; take every name field. For a bare
		// domain line, fields[0] is itself the name. An inline
		// "#" starts a trailing comment.
		var names []string
		if len(fields) == 1 {
			names = fields
		} else {
			names = fields[1:]
		}
		for _, n := range names {
			if strings.HasPrefix(n, "#") {
				break
			}
			canonical := dns.CanonicalName(n)
			if !b.Exists(canonical) {
				b.set(canonical)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning hostfile: %w", err)
	}

	return nil
}
