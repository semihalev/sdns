package blocklist

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/semihalev/sdns/internal/compactset"
	"github.com/semihalev/zlog/v2"
)

const compactManifestName = "manifest.json"

var errCompactManifestSize = errors.New("compact manifest exceeds 1 MiB")

type compactCheckpoint struct {
	manifest compactManifest
	files    map[string]bool
}

var errCompactUncertainCommit = errors.New("compact file durability uncertain; restart required")

func (c *compactManager) writeError() error {
	c.checkpointMu.Lock()
	defer c.checkpointMu.Unlock()
	return c.failed
}

// On an uncertain commit neither generation can be collected.
func (c *compactManager) disableCompactWrites(err error) error {
	c.checkpointMu.Lock()
	c.failed = err
	c.checkpointMu.Unlock()
	c.cancelRefresh()
	return err
}

func compactRollingFiles(set *compactset.Rolling) map[string]bool {
	if set == nil {
		return nil
	}
	files := make(map[string]bool)
	set.Files(files)
	return files
}

// Ages follow activation of feed or local rules, not checkpoint completion or API edits.
func (c *compactManager) compactPolicyAges() (active, durable time.Duration) {
	c.checkpointMu.Lock()
	defer c.checkpointMu.Unlock()
	now := time.Now()
	age := func(at time.Time) time.Duration {
		if at.IsZero() {
			return 0
		}
		return max(0, now.Sub(at))
	}
	return age(c.manifest.ActivatedAt), age(c.durable.manifest.ActivatedAt)
}

// captureActive requires checkpointMu. Catalogs are immutable and the
// publisher cannot unmap the current catalog while we copy its shard names.
func (c *compactManager) captureActive() *compactCheckpoint {
	return &compactCheckpoint{manifest: c.manifest, files: compactRollingFiles(c.base)}
}

// publishCompactRevision requires mu (or exclusive startup ownership).
// Manifest maps are immutable after publication; refresh replaces them rather
// than editing them, so a checkpoint can pin a manifest without copying.
func (b *BlockList) publishCompactRevision(m compactManifest, set *compactset.Rolling) error {
	c := b.compact
	// Cold install awaits durability before the manager becomes accessible.
	first := c.durable.manifest.Rolling == nil
	metadataOnly := m.Rolling == c.manifest.Rolling
	if first {
		m.ActivatedAt = time.Now()
		if err := c.writeCompactManifest(m); err != nil {
			return err
		}
		c.durable = compactCheckpoint{manifest: m, files: compactRollingFiles(set)}
	}

	c.journalMu.Lock()
	old := c.base
	var length int
	if old != set {
		length = c.countLive(set, m.Rolling.Count, c.configured)
	}
	c.checkpointMu.Lock()
	if c.failed != nil {
		err := c.failed
		c.checkpointMu.Unlock()
		c.journalMu.Unlock()
		return err
	}
	if old != set {
		b.mu.Lock()
	}
	if err := c.refreshContext.Err(); err != nil {
		if old != set {
			b.mu.Unlock()
		}
		c.checkpointMu.Unlock()
		c.journalMu.Unlock()
		return err
	}
	now := time.Now()
	if old != set {
		c.base, c.length = set, length
		b.mu.Unlock()
	}
	if !first && !metadataOnly {
		m.ActivatedAt = now
	}
	previous := c.manifest
	// Keep the expired view open until captured, without blocking queries.
	if !first && c.readyCheckpoint == nil && !c.checkpointDeadline.IsZero() && !now.Before(c.checkpointDeadline) {
		c.readyCheckpoint = &compactCheckpoint{manifest: previous, files: compactRollingFiles(old)}
		c.checkpointDeadline = time.Time{}
	}
	c.manifest = m
	if !first && c.checkpointDeadline.IsZero() {
		c.checkpointDeadline = now.Add(c.checkpointWindow)
		c.wakeCheckpoint()
	}
	c.checkpointMu.Unlock()
	c.journalMu.Unlock()
	if old != nil && old != set {
		_ = old.Close()
	}

	if !metadataOnly {
		active, durable := c.compactPolicyAges()
		zlog.Info("Compact blocklist policy activated", "active_policy_age", active.String(), "last_durable_policy_age", durable.String())
		if first {
			zlog.Info("Compact blocklist checkpoint complete", "active_policy_age", active.String(), "last_durable_policy_age", durable.String())
		}
	}
	return nil
}

func (c *compactManager) wakeCheckpoint() {
	select {
	case c.checkpointWake <- struct{}{}:
	default:
	}
}

func (c *compactManager) wakeFold() {
	select {
	case c.foldWake <- struct{}{}:
	default:
	}
}

// Caller holds journalMu and BlockList.mu.
func (c *compactManager) wakeFoldIfNeeded(journalBytes int64) {
	if len(c.pending) >= compactFoldKeys || journalBytes >= compactDeltaBytes {
		c.wakeFold()
	}
}

func (b *BlockList) runCompactCheckpointsAndFolds() {
	c := b.compact
	const retryDelay = time.Second
	var retryAt time.Time
	var requested bool
	for {
		c.checkpointMu.Lock()
		deadline, failed := c.checkpointDeadline, c.failed != nil
		ready := c.readyCheckpoint != nil
		c.checkpointMu.Unlock()
		if failed || c.refreshContext.Err() != nil {
			return
		}
		if ready || !deadline.IsZero() && !time.Now().Before(deadline) {
			_ = c.checkpointCompact()
			c.wakeFold()
			continue
		}
		if !retryAt.IsZero() && !time.Now().Before(retryAt) {
			retryAt = time.Time{}
			select {
			case <-c.foldWake:
			default:
			}
			requested = true
		}
		if requested && c.mu.TryLock() {
			c.checkpointMu.Lock()
			due := c.readyCheckpoint != nil || !c.checkpointDeadline.IsZero() && !time.Now().Before(c.checkpointDeadline)
			c.checkpointMu.Unlock()
			if due {
				c.mu.Unlock()
				continue
			}
			err := b.foldCompactEditsLocked()
			c.mu.Unlock()
			if errors.Is(err, errCompactUncertainCommit) {
				zlog.Error("Compact blocklist API fold failed", "error", err.Error())
				return
			}
			if err != nil && c.refreshContext.Err() == nil {
				zlog.Error("Compact blocklist API fold failed", "error", err.Error())
				retryAt = time.Now().Add(retryDelay)
			}
			requested = false
			continue
		}
		wake := c.foldWake
		if !retryAt.IsZero() {
			wake = nil
			if deadline.IsZero() || retryAt.Before(deadline) {
				deadline = retryAt
			}
		}
		var timer *time.Timer
		var due <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			due = timer.C
		}
		select {
		case <-c.refreshContext.Done():
		case <-c.checkpointWake:
		case <-due:
		case <-wake:
			requested = true
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// Seal without waiting for a builder. A later activation can open the next
// window while this capture is written.
func (c *compactManager) checkpointCompact() error {
	c.checkpointMu.Lock()
	if c.failed != nil {
		err := c.failed
		c.checkpointMu.Unlock()
		return err
	}
	if c.refreshContext.Err() != nil || c.inflight != nil || (c.readyCheckpoint == nil && c.checkpointDeadline.IsZero()) {
		c.checkpointMu.Unlock()
		return nil
	}
	p := c.readyCheckpoint
	if p == nil {
		p = c.captureActive()
		// The first activation after capture starts its own fixed window.
		c.checkpointDeadline = time.Time{}
	}
	c.readyCheckpoint = nil
	c.inflight = p
	c.checkpointMu.Unlock()

	err := c.writeCompactManifest(p.manifest)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkpointMu.Lock()
	if err == nil {
		c.durable = *p
	} else if c.failed == nil && c.checkpointDeadline.IsZero() {
		// Preserve a later activation's deadline. Without one, rate-limit
		// retries rather than losing the pending policy or spinning on I/O.
		c.checkpointDeadline = time.Now().Add(max(c.checkpointWindow, time.Second))
	}
	c.inflight = nil
	c.checkpointMu.Unlock()
	active, durable := c.compactPolicyAges()
	if err != nil {
		zlog.Error("Compact blocklist checkpoint failed", "error", err.Error(), "active_policy_age", active.String(), "last_durable_policy_age", durable.String())
	} else {
		zlog.Info("Compact blocklist checkpoint complete", "active_policy_age", active.String(), "last_durable_policy_age", durable.String())
	}
	c.sweepCompactFiles("checkpoint", nil)
	return err
}

// The manifest is the commit point for the immutable rolling feed files.
type compactManifest struct {
	Journal               string
	ActivatedAt           time.Time
	Rolling               *compactset.RollingManifest
	RollingLocalSHA       string
	RollingSourceMetadata map[string]compactRollingSourceMetadata `json:",omitempty"`
}

func readCompactManifest(dir string) (compactManifest, error) {
	path := filepath.Join(dir, compactManifestName)
	var manifest compactManifest
	f, err := openCompactStateFile(path, os.O_RDONLY)
	if os.IsNotExist(err) {
		// Older stores used a separate codec marker. Its presence is not
		// evidence of an interrupted install of this format.
		if _, markerErr := os.Lstat(filepath.Join(dir, "codec")); markerErr == nil {
			return manifest, errors.New("incompatible compact blocklist codec marker")
		} else if !os.IsNotExist(markerErr) {
			return manifest, markerErr
		}
	}
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, compactManifestAllowance+1))
	if err != nil {
		return manifest, err
	}
	if len(data) > compactManifestAllowance {
		return manifest, fmt.Errorf("manifest %q: %w", path, errCompactManifestSize)
	}
	// Reject unknown and duplicate keys at every level before trusting
	// the checkpoint as an inventory of owned policy files.
	if err := jsonv2.Unmarshal(data, &manifest, jsonv2.RejectUnknownMembers(true)); err != nil {
		return manifest, fmt.Errorf("decode manifest %q: %w", path, err)
	}
	if manifest.Rolling == nil || manifest.ActivatedAt.IsZero() {
		return manifest, fmt.Errorf("incompatible compact blocklist manifest %q", path)
	}
	return manifest, nil
}

// Write a fixed-width activation timestamp so preparing a revision and
// capturing it both reserve the same number of manifest bytes.
func compactManifestBytes(m compactManifest) ([]byte, error) {
	const activationLayout = "2006-01-02T15:04:05.000000000Z"
	wire := struct {
		compactManifest
		ActivatedAt string
	}{m, m.ActivatedAt.UTC().Format(activationLayout)}
	return json.Marshal(wire)
}

func (c *compactManager) admittedCompactManifestBytes(m compactManifest) ([]byte, error) {
	data, err := compactManifestBytes(m)
	if err != nil {
		return nil, err
	}
	if len(data) > compactManifestAllowance {
		return nil, errCompactManifestSize
	}
	if err := c.admitCheckpointManifest(uint64(len(data))); err != nil {
		return nil, err
	}
	return data, nil
}

// The caller serializes manifest commits. An unconfirmed rename disables
// writes before checkpoint finalization can wait for the builder lock.
func (c *compactManager) writeCompactManifest(m compactManifest) error {
	data, err := c.admittedCompactManifestBytes(m)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.dir, compactTempManifestPrefix+"*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	e := f.Close()
	if err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	d, err := os.Open(c.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Persist the referenced names before making the new manifest visible.
	// The builders and journal have already synced their file contents.
	if c.syncBeforeRename != nil {
		err = c.syncBeforeRename(d)
	} else {
		err = d.Sync()
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(c.dir, compactManifestName)); err != nil {
		return err
	}
	if c.syncDirectory != nil {
		err = c.syncDirectory(d)
	} else {
		err = d.Sync()
	}
	if err != nil {
		return c.disableCompactWrites(fmt.Errorf("%w: %s: %w", errCompactUncertainCommit, compactManifestName, err))
	}
	return nil
}

// A failed sweep is retried before the next rolling admission sample.
func (c *compactManager) sweepCompactFiles(stage string, closeErr error) {
	err := c.cleanupCompactFiles(false)
	if errors.Is(err, errCompactUncertainCommit) {
		return
	}
	c.cleanupPending = err != nil
	if err := errors.Join(closeErr, err); err != nil {
		zlog.Error("Compact blocklist cleanup failed", "stage", stage, "error", err.Error())
	}
}

func (c *compactManager) retryCompactCleanup() {
	if c.cleanupPending {
		c.sweepCompactFiles("retry", nil)
	}
}

// Caller excludes builders with mu (or has exclusive startup ownership).
// Shutdown keeps the durable artifacts and its journal generation and successors.
func (c *compactManager) cleanupCompactFiles(closing bool) error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	var activeFiles, inflightFiles, readyFiles map[string]bool
	var active *compactset.Rolling
	c.checkpointMu.Lock()
	if !closing && c.failed != nil {
		err := c.failed
		c.checkpointMu.Unlock()
		return err
	}
	if !closing && c.manifest.Rolling != c.durable.manifest.Rolling {
		active = c.base
	}
	journal := c.durable.manifest.Journal
	journalPrefix, _, _ := compactJournalGeneration(journal)
	durableFiles := c.durable.files
	if !closing {
		if c.inflight != nil {
			inflightFiles = c.inflight.files
		}
		if c.readyCheckpoint != nil {
			readyFiles = c.readyCheckpoint.files
		}
	}
	// A capture after ReadDir cannot have created an entry in this list.
	writingManifest := c.inflight != nil
	c.checkpointMu.Unlock()
	if active != nil {
		activeFiles = compactRollingFiles(active)
	}
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() && compactset.IsScratchDir(name) {
			if err := os.RemoveAll(filepath.Join(c.dir, name)); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		prefix, _, isJournal := compactJournalGeneration(name)
		retiredJournal := isJournal && (prefix != journalPrefix || name < journal)
		owned := retiredJournal || compactset.IsArtifact(name) || !writingManifest && compactTempManifest(name)
		if owned && !e.IsDir() && !durableFiles[name] && !activeFiles[name] && !inflightFiles[name] && !readyFiles[name] {
			if err := os.Remove(filepath.Join(c.dir, name)); err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

const compactTempManifestPrefix = "manifest-"

// Temporary manifests have the decimal suffix chosen by os.CreateTemp.
func compactTempManifest(name string) bool {
	suffix, ok := strings.CutPrefix(name, compactTempManifestPrefix)
	if !ok || suffix == "" {
		return false
	}
	for i := range len(suffix) {
		b := suffix[i]
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

const (
	compactAPIAdd            = "api-add"
	compactAPIRemove         = "api-remove"
	compactRollingLocalOwner = "operator-local"
)

const (
	compactAPIAddSlot = iota
	compactAPIRemoveSlot
	compactLocalSlot
	compactReservedOwners
)

const compactAPIRemoveBit uint64 = 1 << compactAPIRemoveSlot

var errCompactFeedOwners = errors.New("compact rolling owners do not match configured feeds")

type compactRollingSourceMetadata struct {
	ETag         string `json:",omitempty"`
	LastModified string `json:",omitempty"`
}

func compactRollingOwners(uris []string) []string {
	owners := make([]string, compactReservedOwners, len(uris)+compactReservedOwners)
	owners[compactAPIAddSlot], owners[compactAPIRemoveSlot], owners[compactLocalSlot] = compactAPIAdd, compactAPIRemove, compactRollingLocalOwner
	for _, uri := range uris {
		owners = append(owners, compactSourceID(uri))
	}
	slices.Sort(owners[compactReservedOwners:])
	return slices.Compact(owners)
}

func (c *compactManager) rollingOptions(uris []string) compactset.RollingOptions {
	return compactset.RollingOptions{Dir: c.dir, Owners: compactRollingOwners(uris)}
}

func (c *compactManager) checkRollingManifest(m compactManifest, uris []string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("manifest %q: %w", filepath.Join(c.dir, compactManifestName), err)
		}
	}()
	if m.Rolling != nil {
		if err := m.Rolling.CheckLayout(); err != nil {
			return err
		}
	}
	_, _, validJournal := compactJournalGeneration(m.Journal)
	if m.Rolling == nil ||
		len(m.RollingLocalSHA) != sha256.Size*2 || !compactLowerHex(m.RollingLocalSHA) ||
		!validJournal || len(m.RollingSourceMetadata) != len(m.Rolling.Owners)-compactReservedOwners {
		return fmt.Errorf("incompatible compact rolling state")
	}
	if !slices.Equal(compactRollingOwners(uris), m.Rolling.Owners) {
		return errCompactFeedOwners
	}
	for _, id := range m.Rolling.Owners[compactReservedOwners:] {
		if _, ok := m.RollingSourceMetadata[id]; !ok {
			return fmt.Errorf("invalid compact rolling source metadata for %s", id)
		}
	}
	return nil
}

func (b *BlockList) buildRolling(refreshRemote bool, available, workspace uint64) error {
	uris := b.cfg.BlockLists
	c := b.compact
	stage := "install"
	previous := c.manifest.Rolling
	if previous != nil {
		stage = "rebuild"
	}
	input := rollingInstallInput{manager: c, available: available}
	opt := c.rollingOptions(uris)
	admitWrite, err := c.rollingWriteAdmission(stage)
	if err != nil {
		return err
	}
	opt.AdmitWrite = admitWrite
	ledger := rollingLedger(workspace)
	fingerprint, err := b.compactLocalFingerprint(ledger)
	if err != nil {
		return err
	}
	metadata := make(map[string]compactRollingSourceMetadata, len(uris))
	owners := make(map[string]func() (io.ReadCloser, error), len(uris)+compactReservedOwners)
	owners[compactRollingLocalOwner] = func() (io.ReadCloser, error) {
		return openCompactScanPipe(c.refreshContext, func(ctx context.Context, w io.Writer) error {
			return b.emitRollingLocal(ctx, input.wrap(w), ledger, fingerprint)
		}), nil
	}
	current := c.base
	stored := func(id string) (io.ReadCloser, error) {
		return openCompactScanPipe(c.refreshContext, func(ctx context.Context, w io.Writer) error {
			return emitRollingOwner(ctx, input.wrap(w), current, id, nil)
		}), nil
	}
	for _, id := range [...]string{compactAPIAdd, compactAPIRemove} {
		owners[id] = func() (io.ReadCloser, error) { return stored(id) }
	}
	for _, uri := range uris {
		id := compactSourceID(uri)
		owners[id] = func() (io.ReadCloser, error) {
			next := c.manifest.RollingSourceMetadata[id]
			if current != nil && !refreshRemote {
				metadata[id] = next
				return stored(id)
			}
			body, transport, err := requestCompactSource(c.refreshContext, uri, next)
			if err != nil {
				return nil, compactFeedError(uris, uri, err)
			}
			metadata[id] = transport
			if body == nil {
				return stored(id)
			}
			return openCompactKeyPipe(func(w io.Writer) error {
				err := errors.Join(c.emitRollingResponse(input.wrap(w), body), body.Close())
				if err == nil {
					return nil
				}
				return compactFeedError(uris, uri, err)
			}, body.cancel), nil
		}
	}
	m, err := compactset.BuildRolling(c.refreshContext, opt, int64(workspace), owners, previous) //nolint:gosec // workspace is capped at 1 GiB
	if err != nil {
		return err
	}
	names, retained := m.RecordCounts()
	if err := c.checkRollingReplacement(stage+" publication", available, rollingInstallMemory(names, input.bytes), names, retained); err != nil {
		return err
	}
	open := func() (*compactset.Rolling, error) { return compactset.OpenRolling(c.refreshContext, opt, m) }
	if err := b.publishRolling(&m, metadata, fingerprint, open); err != nil {
		return err
	}
	if previous != nil {
		zlog.Info("Compact blocklist rebuilt", "revision", m.Sequence, "rolling_keys", m.Count)
	} else {
		zlog.Info("Compact blocklist installed", "rolling_keys", m.Count)
	}
	return nil
}

// A pass stages successful downloads and publishes at most one base generation.
// A failed download or build leaves the entire active policy unchanged.
func (b *BlockList) refreshRolling(refreshRemote bool) error {
	c := b.compact
	if c.closed {
		return errCompactClosed
	}
	if err := c.writeError(); err != nil {
		return err
	}
	if err := c.refreshContext.Err(); err != nil {
		return err
	}
	var uris []string
	if refreshRemote {
		uris = b.cfg.BlockLists
	}
	c.retryCompactCleanup()
	failedLocalWorkspace, err := b.refreshRollingDelta(uris)
	localExhausted := failedLocalWorkspace != 0 && errors.Is(err, errCompactFeedWorking)
	if !localExhausted && !errors.Is(err, errRollingRAM) && !errors.Is(err, errRollingChurn) {
		return err
	}
	if err := c.refreshContext.Err(); err != nil {
		return err
	}
	// All diff scratch is closed. Return unreachable arenas before sampling
	// a workspace for the fallback, not while both builders are alive.
	debug.FreeOSMemory()
	c.retryCompactCleanup()
	available, workspace, admissionErr := c.admitRolling(admitInstall, "rebuild")
	if admissionErr != nil {
		return errors.Join(err, admissionErr)
	}
	if localExhausted {
		if workspace <= failedLocalWorkspace {
			return err
		}
		err = c.rollingRAMError("refresh", err)
	}
	zlog.Info("Rebuilding compact blocklist", "reason", err.Error())
	supersedesUndurable := c.manifest.Rolling != c.durable.manifest.Rolling
	buildErr := b.buildRolling(refreshRemote, available, workspace)
	if buildErr != nil || supersedesUndurable {
		c.sweepCompactFiles("rebuild", nil)
	}
	if buildErr != nil {
		return errors.Join(err, buildErr)
	}
	return nil
}

// A nonzero failedLocalWorkspace is the budget exhausted by local input.
func (b *BlockList) refreshRollingDelta(uris []string) (failedLocalWorkspace uint64, err error) {
	c := b.compact
	var available uint64
	workspace := uint64(compactFeedWorkingLimit)
	var admissionErr error
	if len(uris) != 0 {
		available, workspace, admissionErr = c.admitRolling(admitRefresh, "refresh")
	}
	ledger := rollingLedger(workspace)
	fingerprint, err := b.compactLocalFingerprint(ledger)
	if len(uris) == 0 && (errors.Is(err, errCompactFeedWorking) || err == nil && fingerprint != c.manifest.RollingLocalSHA) {
		available, workspace, admissionErr = c.admitRolling(admitRefresh, "refresh")
		ledger = rollingLedger(workspace)
		if err != nil {
			if admissionErr != nil {
				return compactFeedWorkingLimit, errors.Join(admissionErr, err)
			}
			if workspace <= compactFeedWorkingLimit {
				return compactFeedWorkingLimit, err
			}
			fingerprint, err = b.compactLocalFingerprint(ledger)
		}
	}
	if errors.Is(err, errCompactFeedWorking) {
		return workspace, errors.Join(err, admissionErr)
	}
	if err != nil {
		return 0, err
	}
	localChanged := fingerprint != c.manifest.RollingLocalSHA
	if len(uris) == 0 && !localChanged {
		return 0, nil
	}
	var refresh *compactset.RollingRefresh
	metadata := c.manifest.RollingSourceMetadata
	if len(uris) != 0 {
		metadata = make(map[string]compactRollingSourceMetadata, len(uris))
	}
	changes := make([]*compactset.RollingChange, 0, len(uris)+1)
	var adds, removes uint64
	diff := func(id string, open func() compactKeyPipe) error {
		if admissionErr != nil {
			return admissionErr
		}
		if refresh == nil {
			admitWrite, err := c.rollingWriteAdmission("refresh")
			if err != nil {
				return err
			}
			refresh = c.base.BeginRefresh(int64(workspace), admitWrite) //nolint:gosec // workspace is capped at 1 GiB
		}
		change, err := compactOwnerDiff(c.refreshContext, refresh, id, open())
		if err != nil {
			return err
		}
		if change == nil {
			return nil
		}
		adds = compactSizeAdd(adds, uint64(change.Adds))          //nolint:gosec // counts are nonnegative
		removes = compactSizeAdd(removes, uint64(change.Removes)) //nolint:gosec // counts are nonnegative
		changes = append(changes, change)
		ops := compactSizeAdd(adds, removes)
		if ops > rollingRefreshChurnLimit {
			return fmt.Errorf("%w: %d operations exceed %d", errRollingChurn, ops, rollingRefreshChurnLimit)
		}
		return nil
	}
	supersedesUndurable := false
	defer func() {
		var closeErr error
		for _, change := range changes {
			closeErr = errors.Join(closeErr, change.Close())
		}
		if err != nil || supersedesUndurable || closeErr != nil {
			c.sweepCompactFiles("refresh", closeErr)
		}
	}()
	if localChanged {
		if err := diff(compactRollingLocalOwner, func() compactKeyPipe {
			return openCompactScanPipe(c.refreshContext, func(ctx context.Context, w io.Writer) error {
				return b.emitRollingLocal(ctx, w, ledger, fingerprint)
			})
		}); err != nil {
			if errors.Is(err, errCompactFeedWorking) {
				return workspace, err
			}
			return 0, err
		}
	}
	for _, uri := range uris {
		id := compactSourceID(uri)
		if _, seen := metadata[id]; seen {
			continue
		}
		next, ok := c.manifest.RollingSourceMetadata[id]
		if !ok {
			return 0, fmt.Errorf("unknown compact rolling source %s", id)
		}
		body, transport, err := requestCompactSource(c.refreshContext, uri, next)
		if err == nil && body != nil {
			err = diff(id, func() compactKeyPipe {
				return openCompactKeyPipe(func(w io.Writer) error { return c.emitRollingResponse(w, body) }, body.cancel)
			})
			err = errors.Join(err, body.Close())
		}
		if err != nil {
			return 0, compactFeedError(b.cfg.BlockLists, uri, err)
		}
		metadata[id] = transport
	}
	if len(changes) == 0 {
		if localChanged || !maps.Equal(metadata, c.manifest.RollingSourceMetadata) {
			if err := b.publishRolling(c.manifest.Rolling, metadata, fingerprint, nil); err != nil {
				return 0, err
			}
		}
		zlog.Debug("Compact blocklist refresh unchanged")
		return 0, nil
	}
	if err := c.refreshContext.Err(); err != nil {
		return 0, err
	}
	m, open, err := c.stageRollingRefresh("refresh", c.manifest.Rolling, refresh, changes, available, adds, compactSizeAdd(adds, removes))
	if err != nil {
		return 0, err
	}
	// The durable manifest pins its own files. Collect superseded files
	// that were never checkpointed so they cannot accumulate.
	supersedesUndurable = c.manifest.Rolling != c.durable.manifest.Rolling
	if err := b.publishRolling(&m, metadata, fingerprint, open); err != nil {
		return 0, err
	}
	zlog.Info("Compact blocklist updated", "revision", m.Sequence, "rolling_keys", m.Count)
	return 0, nil
}

func (b *BlockList) publishRolling(rolling *compactset.RollingManifest, metadata map[string]compactRollingSourceMetadata, fingerprint string, open func() (*compactset.Rolling, error)) (err error) {
	c := b.compact
	if err = c.refreshContext.Err(); err != nil {
		return err
	}
	m := c.manifest
	m.Rolling = rolling
	m.RollingLocalSHA, m.RollingSourceMetadata = fingerprint, metadata
	if _, err = c.admittedCompactManifestBytes(m); err != nil {
		return err
	}
	if rolling == c.manifest.Rolling {
		return b.publishCompactRevision(m, c.base)
	}
	base, err := open()
	if err != nil {
		return fmt.Errorf("open compact rolling policy: %w", err)
	}
	defer func() {
		if err != nil {
			_ = base.Close()
		}
	}()
	return b.publishCompactRevision(m, base)
}

func (c *compactManager) stageRollingRefresh(stage string, previous *compactset.RollingManifest, refresh *compactset.RollingRefresh, changes []*compactset.RollingChange, available, growth, ops uint64) (compactset.RollingManifest, func() (*compactset.Rolling, error), error) {
	names, retained := previous.RecordCounts()
	working := rollingRefreshMemory(names, ops)
	if err := c.checkRollingReplacement(stage+" apply", available, working, compactSizeAdd(names, growth), compactSizeAdd(retained, ops)); err != nil {
		return compactset.RollingManifest{}, nil, err
	}
	if err := c.refreshContext.Err(); err != nil {
		return compactset.RollingManifest{}, nil, err
	}
	update, err := refresh.Apply(c.refreshContext, changes)
	if err != nil {
		return compactset.RollingManifest{}, nil, err
	}
	m := update.Manifest()
	names, retained = m.RecordCounts()
	if err := c.checkRollingReplacement(stage+" publication", available, working, names, retained); err != nil {
		return compactset.RollingManifest{}, nil, err
	}
	return m, func() (*compactset.Rolling, error) { return update.Open(c.refreshContext) }, nil
}

func emitRollingOwner(ctx context.Context, w io.Writer, base *compactset.Rolling, owner string, edits map[string]bool) error {
	out := bufio.NewWriterSize(w, 64<<10)
	if base != nil {
		if err := base.IterateOwner(ctx, owner, func(key []byte) error {
			if _, edited := edits[string(key)]; edited {
				return nil
			}
			if _, err := out.Write(key); err != nil {
				return err
			}
			return out.WriteByte('\n')
		}); err != nil {
			return err
		}
	}
	for key, add := range edits {
		if err := ctx.Err(); err != nil {
			return err
		}
		if add != (owner == compactAPIAdd) {
			continue
		}
		if _, err := out.WriteString(key); err != nil {
			return err
		}
		if err := out.WriteByte('\n'); err != nil {
			return err
		}
	}
	return out.Flush()
}

type compactKeyPipe struct {
	*io.PipeReader
	done   <-chan struct{}
	cancel context.CancelFunc
}

func (p compactKeyPipe) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	_ = p.PipeReader.Close()
	<-p.done
	return nil
}

// The consumer must close the pipe exactly once, even on failure.
func openCompactKeyPipe(emit func(io.Writer) error, cancel context.CancelFunc) compactKeyPipe {
	r, w := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.CloseWithError(emit(w))
	}()
	return compactKeyPipe{r, done, cancel}
}

func openCompactScanPipe(parent context.Context, emit func(context.Context, io.Writer) error) compactKeyPipe {
	ctx, cancel := context.WithCancel(parent)
	return openCompactKeyPipe(func(w io.Writer) error { return emit(ctx, w) }, cancel)
}

func compactOwnerDiff(ctx context.Context, refresh *compactset.RollingRefresh, id string, pipe compactKeyPipe) (*compactset.RollingChange, error) {
	// Close and join even if Diff stops reading early.
	defer pipe.Close()
	change, err := refresh.Diff(ctx, id, pipe)
	if err == nil && change.Adds == 0 && change.Removes == 0 {
		return nil, change.Close()
	}
	return change, err
}
