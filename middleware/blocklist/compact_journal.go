package blocklist

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/atomicfile"
	"github.com/semihalev/sdns/internal/compactset"
	"github.com/semihalev/zlog/v2"
)

const (
	compactJournalPrefix        = "journal-"
	compactJournalTokenWidth    = 32
	compactJournalSequenceWidth = 16
	compactJournalFraming       = 2 // operation byte and newline
	compactJournalReplayBuffer  = compactset.MaxKey + compactJournalFraming + 1
)

func compactJournalName(token string, sequence uint64) string {
	return fmt.Sprintf("%s%s-%0*x", compactJournalPrefix, token, compactJournalSequenceWidth, sequence)
}

// A manifest names the first journal to replay. Later generations are
// contiguous, so writers can switch journals while a fold is built.
func compactJournalGeneration(name string) (string, uint64, bool) {
	stem, ok := strings.CutPrefix(name, compactJournalPrefix)
	if !ok {
		return "", 0, false
	}
	token, sequence, ok := strings.Cut(stem, "-")
	if !ok || len(token) != compactJournalTokenWidth || len(sequence) != compactJournalSequenceWidth {
		return "", 0, false
	}
	if !compactLowerHex(token) || !compactLowerHex(sequence) {
		return "", 0, false
	}
	n, err := strconv.ParseUint(sequence, 16, 64)
	return token, n, err == nil
}

func compactLowerHex(s string) bool {
	for i := range len(s) {
		ch := s[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func (c *compactManager) replayJournals() (int64, error) {
	prefix, generation, _ := compactJournalGeneration(c.manifest.Journal)
	entries, err := os.ReadDir(c.dir) // sorted by name, hence by generation
	if err != nil {
		return 0, err
	}
	reader := bufio.NewReaderSize(nil, compactJournalReplayBuffer)
	var replayedBytes int64
	for _, entry := range entries {
		name := entry.Name()
		stem, n, ok := compactJournalGeneration(name)
		if !ok || stem != prefix || n < generation {
			continue
		}
		if n != generation {
			return 0, fmt.Errorf("missing compact journal %q", filepath.Join(c.dir, compactJournalName(prefix, generation)))
		}
		path := filepath.Join(c.dir, name)
		f, err := openCompactStateFile(path, os.O_RDONLY)
		if err != nil {
			return 0, err
		}
		reader.Reset(f)
		c.journalBytes = 0
		err = c.replayJournal(reader, path)
		if err := errors.Join(err, f.Close()); err != nil {
			return 0, err
		}
		replayedBytes += min(c.journalBytes, compactDeltaBytes-replayedBytes)
		c.journal = name
		generation++
	}
	if c.journal == "" {
		return 0, fmt.Errorf("missing compact journal %q", filepath.Join(c.dir, c.manifest.Journal))
	}
	return replayedBytes, nil
}

func (c *compactManager) replayJournal(reader *bufio.Reader, path string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("journal %q at byte %d: %w", path, c.journalBytes, err)
		}
	}()
	for {
		record, err := reader.ReadSlice('\n')
		// An overlong record with a newline is corruption, not a torn tail.
		if err == bufio.ErrBufferFull {
			for err == bufio.ErrBufferFull {
				_, err = reader.ReadSlice('\n')
			}
			if err == nil {
				return fmt.Errorf("invalid compact journal")
			}
		}
		if err == io.EOF {
			if len(record) == 0 {
				return nil
			}
			if err := truncateCompactJournal(path, c.journalBytes); err != nil {
				return fmt.Errorf("truncate torn compact journal: %w", err)
			}
			zlog.Warn("Truncated torn compact journal record", "path", path)
			return nil
		}
		if err != nil {
			return fmt.Errorf("read compact journal: %w", err)
		}
		line := record[:len(record)-1]
		if len(line) < 2 || (line[0] != '+' && line[0] != '-') {
			return fmt.Errorf("invalid compact journal")
		}
		key := string(line[1:])
		if !compactJournalKeyFits(key) || dns.CanonicalName(key) != key {
			return fmt.Errorf("invalid compact journal key")
		}
		c.pending[key] = line[0] == '+'
		c.journalBytes += int64(len(record))
	}
}

func compactJournalKeyFits(key string) bool {
	return len(key) <= compactset.MaxKey && !strings.ContainsAny(key, "\r\n")
}

func (c *compactManager) createJournal(name string) error {
	path := filepath.Join(c.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // name comes from the journal formatter
	if errors.Is(err, os.ErrExist) {
		f, err = openCompactStateFile(path, os.O_WRONLY)
		if err == nil {
			var st os.FileInfo
			st, err = f.Stat()
			if err == nil && st.Size() != 0 {
				err = fmt.Errorf("refusing nonempty compact journal %q", path)
			}
			if err != nil {
				return errors.Join(err, f.Close())
			}
		}
	}
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	return atomicfile.SyncDir(c.dir)
}

func (c *compactManager) appendOperations(keys []string, size int, add bool, syncFile func(*os.File) error) error {
	path := filepath.Join(c.dir, c.journal)
	f, err := openCompactStateFile(path, os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}
	op := byte('-')
	if add {
		op = '+'
	}
	batch := make([]byte, 0, size)
	for _, key := range keys {
		batch = append(batch, op)
		batch = append(batch, key...)
		batch = append(batch, '\n')
	}
	if _, err = f.Write(batch); err == nil {
		err = syncFile(f)
	}
	if err = errors.Join(err, f.Close()); err == nil {
		c.journalBytes += int64(len(batch))
		return nil
	}
	if e := truncateCompactJournal(path, c.journalBytes); e != nil {
		return c.disableCompactWrites(fmt.Errorf("%w: journal repair: %w", errCompactUncertainCommit, errors.Join(err, e)))
	}
	return err
}

func truncateCompactJournal(path string, offset int64) error {
	f, err := openCompactStateFile(path, os.O_WRONLY)
	if err != nil {
		return err
	}
	err = f.Truncate(offset)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// Fold from a sealed journal generation; keep the snapshot on failure so a
// retry cannot rotate the active writer or replay newer writes out of order.
func (b *BlockList) foldCompactEditsLocked() (err error) {
	c := b.compact
	if err := c.writeError(); err != nil {
		return err
	}
	if err := c.refreshContext.Err(); err != nil {
		return err
	}
	c.checkpointMu.Lock()
	sealed := c.readyCheckpoint != nil || c.inflight != nil
	c.checkpointMu.Unlock()
	b.mu.RLock()
	empty := len(c.pending) == 0 && len(c.folding) == 0
	b.mu.RUnlock()
	if sealed || empty {
		return nil
	}
	c.retryCompactCleanup()
	available, workspace, err := c.admitRolling(admitRefresh, "API fold")
	if err != nil {
		return err
	}
	admit, err := c.rollingWriteAdmission("API fold")
	if err != nil {
		return err
	}
	if c.folding == nil {
		if err := b.sealCompactJournal(); err != nil {
			return err
		}
	}
	defer c.sweepCompactFiles("API fold", nil)

	active, next, err := c.foldRolling(c.base, c.manifest, available, workspace, admit)
	if err != nil {
		return err
	}
	if next != c.base {
		defer func() {
			if err != nil {
				_ = next.Close()
			}
		}()
	}
	// Folding edit owners must not checkpoint a newer, still-live feed.
	// Preserve the durable feed by applying the same edits to its view.
	durable := c.durable.manifest
	var files map[string]bool
	if c.manifest.Rolling == durable.Rolling {
		durable.Rolling, durable.Journal = active.Rolling, active.Journal
		files = compactRollingFiles(next)
	} else {
		view, err := c.base.Reopen(c.refreshContext, *durable.Rolling)
		if err != nil {
			return err
		}
		defer view.Close()
		var disk *compactset.Rolling
		durable, disk, err = c.foldRolling(view, durable, available, workspace, admit)
		if err != nil {
			return err
		}
		if disk != view {
			defer disk.Close()
		}
		files = compactRollingFiles(disk)
	}
	if err := c.refreshContext.Err(); err != nil {
		return err
	}
	if err := c.writeError(); err != nil {
		return err
	}
	if err := c.writeCompactManifest(durable); err != nil {
		return err
	}
	tombstoneDelta := 0
	for key, add := range c.folding {
		wasRemove := c.base.OwnerMask([]byte(key))&compactAPIRemoveBit != 0
		if add && wasRemove {
			tombstoneDelta--
		} else if !add && !wasRemove {
			tombstoneDelta++
		}
	}
	c.journalMu.Lock()
	c.checkpointMu.Lock()
	b.mu.Lock()
	c.tombstones += tombstoneDelta
	old := c.base
	c.base, c.folding = next, nil
	c.wakeFoldIfNeeded(c.journalBytes)
	b.mu.Unlock()
	c.manifest, c.durable = active, compactCheckpoint{manifest: durable, files: files}
	c.checkpointMu.Unlock()
	c.journalMu.Unlock()
	if old != next {
		_ = old.Close()
	}
	return nil
}

func (b *BlockList) sealCompactJournal() error {
	c := b.compact
	c.journalMu.Lock()
	if c.journalBytes != 0 {
		c.journalMu.Unlock()
		prefix, generation, _ := compactJournalGeneration(c.journal)
		if generation == math.MaxUint64 {
			return errors.New("compact journal generations exhausted")
		}
		next := compactJournalName(prefix, generation+1)
		if err := c.createJournal(next); err != nil {
			return err
		}
		// Create and sync the successor without journalMu; reacquire it for the handoff.
		c.journalMu.Lock()
		c.journal, c.journalBytes = next, 0
	}
	b.mu.Lock()
	c.folding, c.pending = c.pending, make(map[string]bool)
	b.mu.Unlock()
	c.journalMu.Unlock()
	return nil
}

func (c *compactManager) foldRolling(base *compactset.Rolling, m compactManifest, available, workspace uint64, admit func(uint64, uint64) error) (compactManifest, *compactset.Rolling, error) {
	refresh := base.BeginRefresh(int64(workspace), admit) //nolint:gosec // workspace is capped at 1 GiB
	var changes []*compactset.RollingChange
	var ops uint64
	for _, id := range [...]string{compactAPIAdd, compactAPIRemove} {
		pipe := openCompactScanPipe(c.refreshContext, func(ctx context.Context, w io.Writer) error {
			return emitRollingOwner(ctx, w, base, id, c.folding)
		})
		change, err := compactOwnerDiff(c.refreshContext, refresh, id, pipe)
		if err != nil {
			return m, nil, err
		}
		if change == nil {
			continue
		}
		defer change.Close()
		changes = append(changes, change)
		ops = compactSizeAdd(ops, compactSizeAdd(uint64(change.Adds), uint64(change.Removes))) //nolint:gosec // nonnegative counts
	}
	m.Journal = c.journal
	if len(changes) == 0 {
		return m, base, nil
	}
	next, open, err := c.stageRollingRefresh("API fold", m.Rolling, refresh, changes, available, ops, ops)
	if err != nil {
		return m, nil, err
	}
	m.Rolling = &next
	view, err := open()
	return m, view, err
}
