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

func (b *BlockList) fetchBlocklists() {
	if b.cfg.BlockListDir == "" {
		b.cfg.BlockListDir = filepath.Join(b.cfg.Directory, "blacklists")
	}

	<-time.After(time.Second)

	if err := b.updateBlocklists(); err != nil {
		zlog.Error("Update blocklists failed", "error", err.Error())
	}

	if err := b.readBlocklists(); err != nil {
		zlog.Error("Read blocklists failed", "dir", b.cfg.BlockListDir, "error", err.Error())
	}
}

func (b *BlockList) updateBlocklists() error {
	if _, err := os.Stat(b.cfg.BlockListDir); os.IsNotExist(err) {
		if err := os.Mkdir(b.cfg.BlockListDir, 0750); err != nil {
			return fmt.Errorf("error creating blacklist directory: %w", err)
		}
	}

	b.mu.Lock()
	for _, entry := range b.cfg.Whitelist {
		b.w[dns.CanonicalName(entry)] = true
	}
	b.mu.Unlock()

	for _, entry := range b.cfg.Blocklist {
		b.set(entry)
	}

	b.fetchBlocklist()

	return nil
}

func (b *BlockList) downloadBlocklist(uri, name string) error {
	filePath := filepath.Join(b.cfg.BlockListDir, name)

	output, err := os.Create(filePath) //nolint:gosec // G304 - path from config, not user input
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}

	defer func() {
		err := output.Close()
		if err != nil {
			zlog.Warn("Blocklist file close failed", "name", name, "error", err.Error())
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

	if _, err := io.Copy(output, response.Body); err != nil {
		return fmt.Errorf("error copying output: %w", err)
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

	err := filepath.Walk(b.cfg.BlockListDir, func(path string, f os.FileInfo, _ error) error {
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
				_ = os.Remove(path)
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
		switch len(fields) {
		case 0:
			continue
		case 1:
			// Just a domain
			line = fields[0]
		default:
			// IP address followed by domain(s)
			// Skip if second field is a comment
			if strings.HasPrefix(fields[1], "#") {
				line = fields[0]
			} else {
				line = fields[1]
			}
		}

		// Canonicalize and add if not exists
		line = dns.CanonicalName(line)
		if !b.Exists(line) {
			b.set(line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning hostfile: %w", err)
	}

	return nil
}
