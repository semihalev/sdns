package blocklist

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/atomicfile"
	"github.com/semihalev/sdns/internal/compactset"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/zlog/v2"
)

const compactDeltaLimit = 1024
const compactDeltaBytes = 256 << 10

// Distinct pending keys and journal bytes trigger background folding, not caps.
const compactFoldKeys = 4096

var (
	errCompactLockFile = errors.New("compact blocklist requires a regular lock file")
	errCompactClosed   = errors.New("compact blocklist is closed")
)

type compactManager struct {
	// Optional per-instance fault injection keeps durability tests independent.
	syncDirectory    func(*os.File) error
	syncBeforeRename func(*os.File) error
	lock             *os.File
	closed           bool
	failed           error           // uncertain durable commit disables further writes until restart
	configured       map[string]bool // replaced under journalMu and BlockList.mu
	// Lock order: mu, journalMu, checkpointMu, BlockList.mu. Build and reload
	// stabilize the view with mu and journalMu respectively. Checkpoint
	// capture uses checkpointMu and DNS uses BlockList.mu; publication
	// takes both before releasing old mappings.
	journalMu          sync.Mutex // serializes appends and the journal handoff
	mu                 sync.Mutex // serializes builds and manager state; never held by queries
	checkpointMu       sync.Mutex // protects capture and publication of checkpoint state
	dir                string
	manifest           compactManifest   // active policy and source metadata
	durable            compactCheckpoint // last confirmed on-disk manifest and its files
	inflight           *compactCheckpoint
	readyCheckpoint    *compactCheckpoint // sealed snapshot awaiting a checkpoint write, independent of inflight
	checkpointWake     chan struct{}
	checkpointWindow   time.Duration
	checkpointDeadline time.Time // under checkpointMu; the first uncheckpointed manifest change opens the window
	base               *compactset.Rolling
	cleanupPending     bool            // under mu or exclusive startup ownership
	pending            map[string]bool // latest edits in the writable journal(s)
	folding            map[string]bool // sealed prefix, still visible until commit
	foldWake           chan struct{}
	journal            string
	journalBytes       int64
	tombstones         int
	length             int
	refreshContext     context.Context
	cancelRefresh      context.CancelFunc
	workersDone        chan struct{}
	admissionObserver  compactAdmissionObserver
}

const compactLockName = "lock"

// Installed on the supported platforms; startup refuses all others before
// using filesystem operations that require native nonblocking open and flock.
var (
	lockCompactDirectory     func(string) (*os.File, error)
	openCompactStateFile     func(string, int) (*os.File, error)
	openCompactLocalFile     func(string) (*os.File, os.FileInfo, error)
	openCompactFeedDirectory func(string) (*os.File, error)
	compactPolicyDisk        func(string) (compactAdmissionDisk, error)
)

func (b *BlockList) startCompactWorkers(installed bool) {
	c := b.compact
	c.workersDone = make(chan struct{})
	var checkpoints sync.WaitGroup
	checkpoints.Go(b.runCompactCheckpointsAndFolds)
	go func() {
		b.runCompactRefresh(!installed)
		checkpoints.Wait()
		close(c.workersDone)
	}()
}

func (b *BlockList) initCompact(admission compactAdmissionObserver) (installed bool, err error) {
	dir, err := b.cfg.ValidateCompactBlocklist()
	if err != nil {
		return false, err
	}
	if b.cfg.BlockListDir == "" {
		b.cfg.BlockListDir = filepath.Join(b.cfg.Directory, "blacklists")
	}
	if err = os.MkdirAll(dir, 0750); err != nil {
		return false, err
	}
	// Check the directory we will lock, not a possibly retargeted alias.
	if _, _, _, err = config.ResolveCompactBlocklistRoots(dir, b.cfg.BlockListDir, false); err != nil {
		return false, err
	}
	c := &compactManager{
		dir: dir, pending: make(map[string]bool), admissionObserver: admission,
		foldWake:       make(chan struct{}, 1),
		checkpointWake: make(chan struct{}, 1), checkpointWindow: b.cfg.BlocklistCheckpointWindow.Duration,
	}
	c.refreshContext, c.cancelRefresh = context.WithCancel(context.Background())
	b.compact = c
	defer func() {
		if err == nil {
			return
		}
		if installed && c.failed == nil {
			err = errors.Join(err, c.cleanupCompactFiles(true))
		}
		err = errors.Join(err, b.Close())
	}()
	b.configured = slices.Clone(b.cfg.Blocklist)
	c.configured = compactConfiguredNames(b.configured)
	// Copied state need not include the lock. Check compatibility before
	// creating it, then re-read and validate under directory ownership.
	if info, statErr := os.Lstat(filepath.Join(dir, compactLockName)); os.IsNotExist(statErr) {
		manifest, readErr := readCompactManifest(dir)
		if readErr != nil && !os.IsNotExist(readErr) {
			return false, readErr
		}
		if readErr == nil {
			if err := c.checkRollingManifest(manifest, b.cfg.BlockLists); err != nil {
				return false, err
			}
		}
	} else if statErr != nil {
		return false, fmt.Errorf("lock compact directory %q: %w", dir, statErr)
	} else if !info.Mode().IsRegular() {
		return false, fmt.Errorf("lock compact directory %q: %w", dir, errCompactLockFile)
	}
	c.lock, err = lockCompactDirectory(dir)
	if err != nil {
		return false, err
	}
	manifest, err := readCompactManifest(dir)
	switch {
	case err == nil:
		if err = c.restoreCompactCheckpoint(manifest, b.cfg.BlockLists); err != nil {
			return false, err
		}
	case !os.IsNotExist(err):
		return false, err
	default:
		installed = true
	}
	b.w = compactConfiguredNames(b.cfg.Whitelist)
	// No writer is active. Recover space from an interrupted build or
	// refresh before admitting another operation.
	if cleanupErr := c.cleanupCompactFiles(false); cleanupErr != nil {
		if installed {
			return installed, cleanupErr
		}
		c.cleanupPending = true
		zlog.Error("Compact blocklist startup cleanup failed", "error", cleanupErr.Error())
	}
	if installed {
		available, workspace, err := c.admitRolling(admitInstall, "install")
		if err != nil {
			return installed, err
		}
		var token [compactJournalTokenWidth / 2]byte
		rand.Read(token[:])
		c.journal = compactJournalName(hex.EncodeToString(token[:]), 0)
		c.manifest.Journal = c.journal
		if err := c.createJournal(c.journal); err != nil {
			return installed, err
		}
		if err := b.buildRolling(false, available, workspace); err != nil {
			return installed, fmt.Errorf("load compact blocklist: %w", err)
		}
	} else {
		c.length = c.countLive(c.base, c.manifest.Rolling.Count, c.configured)
		if refreshErr := b.refreshRolling(false); refreshErr != nil {
			c.logRefreshFailure(refreshErr)
		}
	}
	active, durable := c.compactPolicyAges()
	zlog.Info("Compact blocklist policy ready", "active_policy_age", active.String(), "last_durable_policy_age", durable.String())
	return installed, nil
}

func (c *compactManager) restoreCompactCheckpoint(manifest compactManifest, uris []string) error {
	if err := c.checkRollingManifest(manifest, uris); err != nil {
		return err
	}
	for id, meta := range manifest.RollingSourceMetadata {
		meta.ETag = compactHTTPETag(meta.ETag)
		meta.LastModified = compactHTTPLastModified(meta.LastModified)
		manifest.RollingSourceMetadata[id] = meta
	}
	c.manifest = manifest
	if _, _, err := c.admitRolling(admitRestart, "restart"); err != nil {
		return err
	}
	base, err := compactset.OpenRolling(c.refreshContext, c.rollingOptions(uris), *manifest.Rolling)
	if err != nil {
		return fmt.Errorf("open compact rolling policy: %w", err)
	}
	c.base = base
	replayedBytes, err := c.replayJournals()
	if err != nil {
		return err
	}
	if err := atomicfile.SyncDir(c.dir); err != nil {
		return fmt.Errorf("sync recovered compact journal directory: %w", err)
	}
	if _, gen, _ := compactJournalGeneration(manifest.Journal); gen != 0 {
		if err := base.IterateOwner(c.refreshContext, compactAPIRemove, func([]byte) error { c.tombstones++; return nil }); err != nil {
			return err
		}
	}
	c.durable = compactCheckpoint{manifest: manifest, files: compactRollingFiles(base)}
	c.wakeFoldIfNeeded(replayedBytes)
	return nil
}

func compactConfiguredNames(keys []string) map[string]bool {
	names := make(map[string]bool, len(keys))
	for _, key := range keys {
		names[dns.CanonicalName(key)] = true
	}
	return names
}

func (c *compactManager) contains(key []byte) bool {
	if c.closed {
		return false
	}
	if v, ok := c.pending[string(key)]; ok {
		return v
	}
	if v, ok := c.folding[string(key)]; ok {
		return v
	}
	return compactContains(c.base, c.configured, key)
}

func compactContains(base *compactset.Rolling, configured map[string]bool, key []byte) bool {
	mask := base.OwnerMask(key)
	return mask&compactAPIRemoveBit == 0 && (mask != 0 || configured[string(key)])
}

// The rolling count includes keys that appear only in api-remove.
func (c *compactManager) countLive(base *compactset.Rolling, n int, configured map[string]bool) int {
	for key := range configured {
		if base.OwnerMask([]byte(key)) == 0 {
			n++
		}
	}
	n -= c.tombstones
	adjust := func(key string, add bool) {
		if present := compactContains(base, configured, []byte(key)); add != present {
			if add {
				n++
			} else {
				n--
			}
		}
	}
	for key, add := range c.folding {
		if _, superseded := c.pending[key]; !superseded {
			adjust(key, add)
		}
	}
	for key, add := range c.pending {
		adjust(key, add)
	}
	return n
}

func (c *compactManager) containsExact(key string) bool {
	return !strings.HasPrefix(key, "*.") && c.contains([]byte(key))
}

// nextCompactLabel finds an actual label boundary in a canonical
// presentation name. A dot preceded by an odd run of escapes is data.
func nextCompactLabel(key []byte, label int) int {
	for search := label; search < len(key); {
		i := bytes.IndexByte(key[search:], '.')
		if i < 0 {
			break
		}
		dot := search + i
		start := dot
		for start > label && key[start-1] == '\\' {
			start--
		}
		search = dot + 1
		if (dot-start)%2 == 0 {
			return search
		}
	}
	return len(key)
}

// compactAllowlisted uses the same DNS label boundaries for lookups and edits.
func (b *BlockList) compactAllowlisted(key []byte) bool {
	if len(b.w) != 0 {
		for off := 0; off < len(key); off = nextCompactLabel(key, off) {
			if b.w[string(key[off:])] {
				return true
			}
		}
	}
	return false
}

func (b *BlockList) compactMatch(key []byte) bool {
	if b.compactAllowlisted(key) {
		return false
	}
	c := b.compact
	if c.contains(key) {
		return true
	}
	var scratch [dnsname.MaxPresentationLength + 2]byte
	wildcard := scratch[:]
	copy(wildcard, "*.")
	for off := nextCompactLabel(key, 0); off < len(key); off = nextCompactLabel(key, off) {
		suffix := key[off:]
		if c.contains(suffix) {
			return true
		}
		if len(suffix)+2 > len(wildcard) {
			wildcard = make([]byte, len(suffix)+2)
			copy(wildcard, "*.")
		}
		copy(wildcard[2:], suffix)
		if c.contains(wildcard[:len(suffix)+2]) {
			return true
		}
	}
	return false
}

func (b *BlockList) compactMutate(keys []string, add bool) int {
	c := b.compact
	batch := make([]string, 0, min(len(keys), compactDeltaLimit))
	seen := make(map[string]struct{}, cap(batch))
	changed := 0
	var key string // Retain the canonical key across a byte-budget flush.
	for len(keys) > 0 || key != "" {
		c.journalMu.Lock()
		if c.closed {
			c.journalMu.Unlock()
			break
		}
		if err := c.writeError(); err != nil {
			c.journalMu.Unlock()
			zlog.Error("Compact blocklist writes disabled", "error", err.Error())
			break
		}
		batchBytes := 0
		b.mu.RLock()
		for (len(keys) > 0 || key != "") && len(batch) < compactDeltaLimit {
			if key == "" {
				key, keys = dns.CanonicalName(keys[0]), keys[1:]
				if !compactJournalKeyFits(key) || !dns.IsFqdn(key) {
					key = ""
					continue
				}
			}
			recordBytes := len(key) + compactJournalFraming
			if batchBytes+recordBytes > compactDeltaBytes && len(batch) != 0 {
				break
			}
			if _, ok := seen[key]; !ok && c.contains([]byte(key)) != add && (!add || !b.compactAllowlisted([]byte(key))) {
				seen[key] = struct{}{}
				batch = append(batch, key)
				batchBytes += recordBytes
			}
			key = ""
		}
		b.mu.RUnlock()
		if len(batch) == 0 {
			c.journalMu.Unlock()
			break
		}
		if err := c.appendOperations(batch, batchBytes, add, (*os.File).Sync); err != nil {
			c.journalMu.Unlock()
			zlog.Error("Compact blocklist persistence failed", "error", err.Error())
			break
		}
		b.mu.Lock()
		for _, key := range batch {
			c.pending[key] = add
		}
		c.wakeFoldIfNeeded(c.journalBytes)
		if add {
			c.length += len(batch)
		} else {
			c.length -= len(batch)
		}
		b.mu.Unlock()
		c.journalMu.Unlock()
		changed += len(batch)
		batch = batch[:0]
	}
	return changed
}

func (c *compactManager) finishCompactBuilder() {
	c.mu.Unlock()
	c.wakeFold()
}

func (b *BlockList) prepareCompactReload(cfg *config.Config) (func(), error) {
	c := b.compact
	blocks := slices.Clone(cfg.Blocklist)
	additions, whitelist := compactConfiguredNames(blocks), compactConfiguredNames(cfg.Whitelist)
	c.journalMu.Lock()
	closed := c.closed
	c.journalMu.Unlock()
	if closed {
		return nil, errCompactClosed
	}
	// Stock reloads retain configured names and add any newly configured ones.
	return func() {
		c.journalMu.Lock()
		if c.closed {
			c.journalMu.Unlock()
			return
		}
		maps.Copy(additions, c.configured)
		length := c.countLive(c.base, c.manifest.Rolling.Count, additions)
		dropped := droppedBlocklistEntries(b.configured, blocks)
		b.mu.Lock()
		b.configured = blocks
		c.configured, c.length, b.w = additions, length, whitelist
		b.mu.Unlock()
		c.journalMu.Unlock()
		warnDroppedBlocklistEntries(dropped)
	}, nil
}

// Persist stops background work without unmapping policy that requests may need.
func (b *BlockList) Persist(ctx context.Context) {
	if c := b.compact; c != nil {
		c.cancelRefresh()
		if c.workersDone != nil {
			select {
			case <-c.workersDone:
			case <-ctx.Done():
			}
		}
	}
}

// Close releases compact mappings and exclusive directory ownership. It is
// idempotent; callers replacing a resolver in process should close the retired
// middleware. The legacy backend has no resources to release.
func (b *BlockList) Close() error {
	c := b.compact
	if c == nil {
		return nil
	}
	b.Persist(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	c.journalMu.Lock()
	defer c.journalMu.Unlock()
	b.mu.Lock()
	if c.closed {
		b.mu.Unlock()
		return nil
	}
	c.closed = true
	c.length = 0
	var first error
	if c.base != nil {
		first = c.base.Close()
		c.base = nil
	}
	c.pending, c.folding, c.configured, b.w = nil, nil, nil, nil
	b.mu.Unlock()
	if c.writeError() == nil && c.durable.manifest.Rolling != nil {
		if err := c.cleanupCompactFiles(true); first == nil {
			first = err
		}
	}
	c.checkpointMu.Lock()
	c.manifest, c.durable = compactManifest{}, compactCheckpoint{}
	c.readyCheckpoint, c.inflight = nil, nil
	c.checkpointMu.Unlock()
	if c.lock != nil {
		first = errors.Join(first, c.lock.Close())
	}
	return first
}
