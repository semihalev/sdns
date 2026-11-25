package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/compactset"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

const compactSupported = runtime.GOOS == "linux" || runtime.GOOS == "darwin"

func compactTestAdmission() compactAdmissionObserver {
	return compactAdmissionObserver{
		memory: func() (uint64, error) { return 128 << 20, nil },
		disk: func(string) (compactAdmissionDisk, error) {
			return compactAdmissionDisk{available: 4 << 30, capacity: 8 << 30, block: 4096}, nil
		},
	}
}

// Construct synchronously: tests explicitly drive refreshes and avoid a
// background updater outliving the temporary directory.
func compactFixture(t testing.TB, cfg *config.Config) *BlockList {
	t.Helper()
	b := &BlockList{cfg: cfg, w: map[string]bool{}}
	if _, err := b.initCompact(compactTestAdmission()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}
func reopenCompactFixture(t testing.TB, b *BlockList) *BlockList {
	t.Helper()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return compactFixture(t, b.cfg)
}

func compactConfig(t testing.TB) *config.Config {
	t.Helper()
	if !compactSupported {
		t.Skip("compact blocklist requires Linux or macOS")
	}
	dir := t.TempDir()
	return &config.Config{Directory: dir, BlockListDir: filepath.Join(dir, "lists"), BlocklistCompact: true, BlocklistCompactDir: filepath.Join(dir, "compact"), BlocklistCheckpointWindow: config.Duration{Duration: 24 * time.Hour}}
}
func TestCompactIdentityPersistence(t *testing.T) {
	cfg := compactConfig(t)
	cfg.Blocklist = []string{"example.org", "child.example.org", "*.wild.org", "exempt.org"}
	cfg.Whitelist = []string{"exempt.org"}
	b := compactFixture(t, cfg)
	if b.Length() != 4 {
		t.Fatalf("length=%d", b.Length())
	}
	if b.Exists("exempt.org") || !b.Exists("child.wild.org") || b.Exists("wild.org") {
		t.Fatal("matching semantics")
	}
	if _, err := b.Get("*.wild.org"); err == nil {
		t.Fatal("Get must remain exact-only")
	}
	if !b.Remove("example.org") || !b.Exists("child.example.org") || b.Exists("other.example.org") {
		t.Fatal("independent child lost")
	}
	if !b.Remove("*.wild.org") || !b.Set("api.org") {
		t.Fatal("API mutation")
	}
	reloaded := reopenCompactFixture(t, b)
	if reloaded.Exists("example.org") || reloaded.Exists("child.wild.org") || !reloaded.Exists("api.org") || !reloaded.Exists("child.example.org") {
		t.Fatal("override restart lost")
	}
	if !reloaded.Set("example.org") || !reloaded.Exists("other.example.org") {
		t.Fatal("add did not clear deletion")
	}
}

func TestCompactAPIMatchesLongWildcard(t *testing.T) {
	b := compactFixture(t, compactConfig(t))
	suffix := strings.Repeat(strings.Repeat(`\046`, 63)+".", 5)
	if !b.Set("*."+suffix) || !b.Exists("child."+suffix) || b.Exists(suffix) {
		t.Fatal("long wildcard did not match only its descendant")
	}
}

func TestCompactManualAddUsesDNSLabelsForAllowlist(t *testing.T) {
	cfg := compactConfig(t)
	cfg.Whitelist = []string{"safe.test"}
	b := compactFixture(t, cfg)
	if b.Set("child.safe.test") {
		t.Error("accepted a true descendant of an Allowlist Rule")
	}
	if !b.Set(`not\.safe.test`) || !b.Exists(`not\.safe.test`) {
		t.Error("an escaped dot is part of the label, not an allowlisted suffix")
	}
}
func rollingExpect(t *testing.T, b *BlockList, present bool, names ...string) {
	t.Helper()
	for _, name := range names {
		if got := b.Exists(name); got != present {
			t.Errorf("Exists(%q) = %t, want %t", name, got, present)
		}
	}
}

func TestCompactDirectoryLockAndClose(t *testing.T) {
	cfg := compactConfig(t)
	b := compactFixture(t, cfg)
	other := &BlockList{cfg: cfg, w: map[string]bool{}}
	if _, err := other.initCompact(compactTestAdmission()); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatal("competing owner accepted")
	}
	if !b.Set("active.org") {
		t.Fatal("competing owner damaged active state")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	if b.Set("closed.org") || b.Exists("active.org") {
		t.Fatal("closed middleware remained active")
	}
	restarted := compactFixture(t, cfg)
	if !restarted.Exists("active.org") {
		t.Fatal("lock release/restart failed")
	}
}

func TestCompactLockRejectsNonRegularFile(t *testing.T) {
	cfg := compactConfig(t)
	if err := os.MkdirAll(filepath.Join(cfg.BlocklistCompactDir, compactLockName), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := lockCompactDirectory(cfg.BlocklistCompactDir)
	if err == nil || !strings.Contains(err.Error(), "lock compact directory") || strings.Contains(err.Error(), "already in use") {
		t.Fatalf("locking a directory: %v", err)
	}
}

func TestCompactJournalReplay(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "feed.test\nremoved.test\n")
	}))
	defer feed.Close()
	cfg := compactConfig(t)
	cfg.Nullroute = "192.0.2.42"
	cfg.BlockLists = []string{feed.URL}
	b := compactFixture(t, cfg)
	if b.Set(`bad\`) || b.SetBatch([]string{`batch\`}) != 0 || !b.Set(`escaped\.dot.test`) {
		t.Fatal("API must reject a bare trailing escape and accept an escaped dot")
	}
	if !b.Set("manual.test") || !b.Remove("removed.test") {
		t.Fatal("manual edits were not acknowledged")
	}
	path := filepath.Join(b.compact.dir, b.compact.durable.manifest.Journal)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	feed.Close()

	complete, err := os.ReadFile(path) //nolint:gosec // Journal in the test's temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	t.Run("malformed complete records", func(t *testing.T) {
		for _, tail := range []string{"broken\n", "+EXAMPLE.TEST.\n", "+example.test\n", "+" + strings.Repeat("x", 65538) + "\n"} {
			// A malformed complete record must not be treated as a torn tail.
			data := append(bytes.Clone(complete), tail...)
			if err := os.WriteFile(path, data, 0600); err != nil { //nolint:gosec // Test-owned journal.
				t.Fatal(err)
			}
			invalid := &BlockList{cfg: cfg, w: map[string]bool{}}
			if _, err := invalid.initCompact(compactTestAdmission()); err == nil ||
				!strings.Contains(err.Error(), fmt.Sprintf("journal %q at byte %d: invalid compact journal", path, len(complete))) {
				_ = invalid.Close()
				t.Fatalf("malformed complete journal record: got %v", err)
			}
			got, err := os.ReadFile(path) //nolint:gosec // Test-owned journal.
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("malformed complete record was changed: %v", err)
			}
		}
	})

	t.Run("torn tail", func(t *testing.T) {
		// Leave the physical tail on disk, bypassing appendOperations' repair.
		if err := os.WriteFile(path, append(bytes.Clone(complete), "+torn.test."...), 0600); err != nil { //nolint:gosec // Test-owned journal.
			t.Fatal(err)
		}
		writeCompactLocal(t, cfg.BlockListDir, "unadmitted.test\n")
		admission := compactTestAdmission()
		diskChecked := false
		admission.disk = func(string) (compactAdmissionDisk, error) {
			diskChecked = true
			return compactAdmissionDisk{}, errors.New("disk probe unavailable during warm start")
		}
		b = &BlockList{cfg: cfg, nullroute: net.ParseIP(cfg.Nullroute)}
		if _, err := b.initCompact(admission); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.Close() })
		if !diskChecked || b.Exists("unadmitted.test") {
			t.Fatal("warm startup did not preserve the checkpoint when local refresh failed")
		}
		for _, tc := range []struct {
			name    string
			blocked bool
		}{
			{"feed.test.", true},
			{"manual.test.", true},
			{`escaped\.dot.test.`, true},
			{"removed.test.", false},
			{"torn.test.", false},
		} {
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{b, passOn})
			ch.ResetWire(w, wireRequest(t, tc.name, dns.TypeA))
			ch.Next(context.Background())
			if got := w.Written(); got != tc.blocked {
				t.Errorf("DNS block for %s = %t, want %t", tc.name, got, tc.blocked)
			} else if got {
				answer := w.Msg().Answer
				if len(answer) != 1 {
					t.Fatalf("unexpected blocked answer for %s: %v", tc.name, answer)
				}
				a, ok := answer[0].(*dns.A)
				if !ok || a.A.String() != cfg.Nullroute {
					t.Errorf("unexpected blocked answer for %s: %v", tc.name, answer)
				}
			}
		}
		got, err := os.ReadFile(path) //nolint:gosec // Test-owned journal.
		if err != nil || !bytes.Equal(got, complete) {
			t.Fatalf("did not truncate journal to the last complete record: got %q, err %v", got, err)
		}
		if !b.Set("after.test") {
			t.Fatal("cannot append to the recovered journal")
		}
	})
}

func TestCompactJournalSuccessor(t *testing.T) {
	b := compactFixture(t, compactConfig(t))
	c := b.compact
	if !b.Set("manual.test") {
		t.Fatal("could not acknowledge edit")
	}
	original := c.journal
	token, sequence, _ := compactJournalGeneration(original)
	next := compactJournalName(token, sequence+1)
	path := filepath.Join(c.dir, next)
	const unexpected = "+unexpected.test.\n"
	if err := os.WriteFile(path, []byte(unexpected), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := foldCompactEdits(b); err == nil || c.journal != original {
		t.Fatalf("nonempty successor was not refused: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != unexpected { //nolint:gosec // test-owned journal
		t.Fatalf("refused successor changed: %q, %v", got, err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if err := foldCompactEdits(b); err != nil || c.durable.manifest.Journal != next || !b.Exists("manual.test") {
		t.Fatalf("empty successor was not reused: %v", err)
	}
}

func TestCompactJournalBatchSyncFailureRollsBack(t *testing.T) {
	cfg := compactConfig(t)
	b := compactFixture(t, cfg)
	if !b.Set("earlier.test") {
		t.Fatal("could not acknowledge earlier edit")
	}
	c := b.compact
	failure := errors.New("journal sync failed")
	keys := []string{"first.test.", "second.test."}
	size := len(keys[0]) + len(keys[1]) + 4
	err := c.appendOperations(keys, size, true, func(f *os.File) error {
		if st, err := f.Stat(); err != nil || st.Size() != c.journalBytes+int64(size) {
			t.Fatalf("batch was not written before sync: %v", err)
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("append returned %v", err)
	}
	recovered := reopenCompactFixture(t, b)
	rollingExpect(t, recovered, true, "earlier.test")
	rollingExpect(t, recovered, false, keys...)
}

func foldCompactEdits(b *BlockList) error {
	c := b.compact
	c.mu.Lock()
	defer c.mu.Unlock()
	return b.foldCompactEditsLocked()
}

func TestCompactInterruptedFoldKeepsPendingFeedIndependent(t *testing.T) {
	for _, stage := range []string{"before rename", "after rename", "success"} {
		t.Run(stage, func(t *testing.T) {
			var updated atomic.Bool
			feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				host := "old.test"
				if updated.Load() {
					host = "new.test"
				}
				_, _ = fmt.Fprintf(w, "%s\nchild.old.test\nshared.test\n", host)
			}))
			defer feed.Close()
			cfg := compactConfig(t)
			cfg.BlockLists = []string{feed.URL}
			b := compactFixture(t, cfg)
			if !b.Set("manual.test") {
				t.Fatal("initial add was not acknowledged")
			}
			updated.Store(true)
			if err := b.refreshCompact(true); err != nil {
				t.Fatal(err)
			}
			if !b.Set("old.test") || !b.Remove("old.test") || !b.Remove("shared.test") {
				t.Fatal("suppression was not acknowledged")
			}
			c := b.compact
			oldJournal := c.journal
			before := c.durable.manifest.Rolling
			injected := errors.New("interrupted API fold")
			entered, resume := make(chan struct{}), make(chan struct{})
			c.syncBeforeRename = func(dir *os.File) error {
				close(entered)
				<-resume
				if stage == "before rename" {
					return injected
				}
				return dir.Sync()
			}
			if stage == "after rename" {
				c.syncDirectory = func(dir *os.File) error {
					return errors.Join(dir.Sync(), injected)
				}
			}
			folded := make(chan error, 1)
			go func() { folded <- foldCompactEdits(b) }()
			select {
			case <-entered:
			case err := <-folded:
				t.Fatalf("fold never reached the manifest: %v", err)
			case <-time.After(5 * time.Second):
				close(resume)
				<-folded
				t.Fatal("fold did not reach the manifest")
			}
			// A newer operation on a snapshotted key and a new key append to the
			// next journal even while the fold's manifest sync is stalled.
			write := make(chan bool, 1)
			go func() { write <- b.Remove("manual.test") && b.Set("during.test") }()
			writeDrained := false
			select {
			case ok := <-write:
				writeDrained = true
				if !ok {
					t.Error("concurrent API edits were not acknowledged")
				}
			case <-time.After(5 * time.Second):
				t.Error("manifest sync blocked the API")
			}
			close(resume)
			if !writeDrained {
				<-write
			}
			if err := <-folded; !errors.Is(err, injected) && stage != "success" || err != nil && stage == "success" {
				t.Fatalf("fold error = %v in %s", err, stage)
			}
			rollingExpect(t, b, true, "new.test", "child.old.test", "during.test")
			rollingExpect(t, b, false, "old.test", "shared.test", "manual.test")
			newJournal := c.journal
			if stage == "before rename" {
				c.syncBeforeRename = func(*os.File) error { return injected }
				if err := foldCompactEdits(b); !errors.Is(err, injected) || c.journal != newJournal {
					t.Fatalf("retry rotated the journal or returned the wrong error: %v", err)
				}
				rollingExpect(t, b, true, "new.test", "child.old.test", "during.test")
				rollingExpect(t, b, false, "old.test", "shared.test", "manual.test")
				if c.durable.manifest.Rolling != before {
					t.Fatal("failed fold replaced the durable feed")
				}
			}
			if stage == "after rename" {
				// The durable manifest already excludes this still-present journal.
				// A corrupt record would stop startup if it is read again.
				if err := os.WriteFile(filepath.Join(c.dir, oldJournal), []byte("invalid\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			feed.Close()
			recovered := reopenCompactFixture(t, b)
			rollingExpect(t, recovered, false, "old.test", "new.test", "shared.test", "manual.test")
			rollingExpect(t, recovered, true, "child.old.test", "during.test")
			wantJournal := newJournal
			if stage == "before rename" {
				wantJournal = oldJournal
			}
			if got := recovered.compact.manifest.Journal; got != wantJournal {
				t.Fatalf("manifest journal = %q, want %q", got, wantJournal)
			}
			if !recovered.Set("old.test") || !recovered.Exists("old.test") {
				t.Fatal("later add did not supersede a removal")
			}
		})
	}
}

func notifyCompactCommit(committed chan<- struct{}) func(*os.File) error {
	return func(dir *os.File) error {
		if err := dir.Sync(); err != nil {
			return err
		}
		select {
		case committed <- struct{}{}:
		default:
		}
		return nil
	}
}

func startTestCompactCheckpoints(b *BlockList) {
	c := b.compact
	c.workersDone = make(chan struct{})
	go func() {
		defer close(c.workersDone)
		b.runCompactCheckpointsAndFolds()
	}()
}

func TestCompactOwnerScanCancelsBeforeFiltering(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := emitRollingOwner(ctx, io.Discard, nil, compactAPIAdd, map[string]bool{"removed.test.": false}); !errors.Is(err, context.Canceled) {
		t.Fatalf("owner scan = %v, want context.Canceled", err)
	}
}

func TestCompactFoldAdmissionKeepsPendingEdits(t *testing.T) {
	cfg := compactConfig(t)
	b := compactFixture(t, cfg)
	c := b.compact
	if !b.Set("manual.test") {
		t.Fatal("edit was not acknowledged")
	}
	journal := c.journal
	c.admissionObserver.disk = func(string) (compactAdmissionDisk, error) {
		return compactAdmissionDisk{available: 32 << 20, capacity: 1 << 30, block: 4096}, nil
	}
	if err := foldCompactEdits(b); err == nil {
		t.Fatal("fold ignored flash refusal")
	}
	if c.journal != journal || !b.Exists("manual.test") || !b.Set("after.test") {
		t.Fatal("failed fold lost an edit or refused another API write")
	}
	// Refuse the manifest after sealing so subsequent attempts must reuse
	// the same journal pair, even while the disk is temporarily full.
	c.admissionObserver = compactTestAdmission()
	var restored atomic.Bool
	refused := make(chan string, 1)
	committed := make(chan struct{}, 1)
	c.syncBeforeRename = func(dir *os.File) error {
		if !restored.Load() {
			select {
			case refused <- c.journal:
			default:
			}
			return syscall.ENOSPC
		}
		return dir.Sync()
	}
	c.syncDirectory = notifyCompactCommit(committed)
	startTestCompactCheckpoints(b)
	c.wakeFold()
	var sealedJournal string
	for attempt := range 2 {
		select {
		case current := <-refused:
			if current == journal || (attempt == 1 && current != sealedJournal) {
				t.Fatalf("attempt %d used journal %q; initial = %q, sealed = %q", attempt+1, current, journal, sealedJournal)
			}
			sealedJournal = current
		case <-time.After(5 * time.Second):
			t.Fatalf("attempt %d never reached manifest sync", attempt+1)
		}
	}
	restored.Store(true) // No further API edits, feed refresh, or explicit wake.
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("fold did not retry when flash headroom returned")
	}
	m, err := readCompactManifest(c.dir)
	if err != nil || m.Journal != sealedJournal {
		t.Fatalf("retry committed journal %q, want %q: %v", m.Journal, sealedJournal, err)
	}
	rollingExpect(t, b, true, "manual.test", "after.test")
	rollingExpect(t, reopenCompactFixture(t, b), true, "manual.test", "after.test")
}

func TestCompactDistinctAPIEditsFoldAtThreshold(t *testing.T) {
	cfg := compactConfig(t)
	b := compactFixture(t, cfg)
	c := b.compact
	keys := make([]string, 50_000)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%d.test.", i)
	}
	committed := make(chan struct{}, 1)
	c.syncDirectory = notifyCompactCommit(committed)
	startTestCompactCheckpoints(b)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// Exactly 4096 short keys hit the key trigger but not the byte trigger.
	if got := b.SetBatch(keys[:compactFoldKeys]); got != compactFoldKeys {
		t.Fatalf("at key threshold: added %d keys", got)
	}
	awaitCompactTest(t, ctx, committed, "key-triggered fold commit")
	if got := b.SetBatch(keys[compactFoldKeys:]); got != len(keys)-compactFoldKeys {
		t.Fatalf("after threshold: added %d keys", got)
	}
	awaitCompactTest(t, ctx, committed, "second fold commit")
	check := func(list *BlockList) {
		t.Helper()
		if got := list.Length(); got != len(keys) {
			t.Fatalf("Length = %d, want %d", got, len(keys))
		}
		for _, key := range keys {
			if !list.Exists(key) {
				t.Fatalf("missing acknowledged edit %s", key)
			}
		}
	}
	check(b)
	recovered := reopenCompactFixture(t, b)
	check(recovered)
}

func TestCompactAPIJournalBytesTriggerFold(t *testing.T) {
	label := strings.Repeat("x", 61)
	// 1024 records of 256 bytes hit the byte trigger but not the key trigger.
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("%04d.%s.%s.%s.%sx.", i, label, label, label, label)
	}
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprintf("replay=%t", replay), func(t *testing.T) {
			b := compactFixture(t, compactConfig(t))
			committed := make(chan struct{}, 1)
			start := func(b *BlockList) {
				b.compact.syncDirectory = notifyCompactCommit(committed)
				startTestCompactCheckpoints(b)
			}
			if !replay {
				start(b)
			}
			if got := b.SetBatch(keys); got != len(keys) {
				t.Fatalf("added %d, want %d", got, len(keys))
			}
			if replay {
				start(reopenCompactFixture(t, b))
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			awaitCompactTest(t, ctx, committed, "byte-triggered fold commit")
		})
	}
}

func TestCompactRejectsInvalidRestoredHTTPValidators(t *testing.T) {
	cfg := compactConfig(t)
	var notModified atomic.Bool
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			t.Error("invalid restored validators sent with request")
		}
		if notModified.Load() {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = io.WriteString(w, "feed.test\n")
	}))
	defer feed.Close()
	cfg.BlockLists = []string{feed.URL}
	b := compactFixture(t, cfg)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	notModified.Store(true)
	dir := b.compact.dir
	manifest, err := readCompactManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := compactSourceID(feed.URL)
	for _, tc := range []struct{ name, etag, modified string }{
		{"control byte", "\x01bad", "not an HTTP-date"},
		{"blank", " \t ", "not an HTTP-date"},
		{"legacy CET", "*", "Monday, 02-Jan-06 15:04:05 CET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest.RollingSourceMetadata[id] = compactRollingSourceMetadata{ETag: tc.etag, LastModified: tc.modified}
			data, err := compactManifestBytes(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, compactManifestName), data, 0600); err != nil {
				t.Fatal(err)
			}
			recovered := compactFixture(t, cfg)
			if err := recovered.refreshCompact(true); err == nil || !strings.Contains(err.Error(), "304 without a conditional request") {
				t.Fatalf("refresh with invalid validators = %v, want unsolicited 304 error", err)
			}
			rollingExpect(t, recovered, true, "feed.test")
			if got := recovered.compact.manifest.RollingSourceMetadata[id]; got != (compactRollingSourceMetadata{}) {
				t.Fatalf("unsafe validators restored: %q, %q", got.ETag, got.LastModified)
			}
		})
	}
}

func TestCompactMetadataOnlyCheckpoint(t *testing.T) {
	for _, mode := range []string{"local comments", "identical 200", "304 under tight flash budget"} {
		t.Run(mode, func(t *testing.T) {
			cfg := compactConfig(t)
			var updated atomic.Bool
			feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if updated.Load() {
					if r.Header.Get("If-None-Match") != `"old"` {
						t.Error("refresh did not use saved validator")
					}
					w.Header().Set("ETag", `W/"new"`)
					if mode == "304 under tight flash budget" {
						w.WriteHeader(http.StatusNotModified)
						return
					}
				} else {
					w.Header().Set("ETag", `"old"`)
				}
				_, _ = io.WriteString(w, "unchanged.test\n")
			}))
			defer feed.Close()
			cfg.BlockLists = []string{feed.URL}
			if mode == "local comments" {
				cfg.BlockLists = nil
				writeCompactLocal(t, cfg.BlockListDir, "unchanged.test\n")
			}
			b := compactFixture(t, cfg)
			c := b.compact
			before, files := c.manifest, compactRollingFiles(c.base)
			switch mode {
			case "local comments":
				writeCompactLocal(t, cfg.BlockListDir, "# metadata only\nunchanged.test\n")
			case "304 under tight flash budget":
				c.admissionObserver.disk = func(string) (compactAdmissionDisk, error) {
					return compactAdmissionDisk{available: 50<<20 + 32<<10, capacity: 500 << 20, block: 4096}, nil
				}
			}
			updated.Store(true)
			if err := b.refreshRolling(true); err != nil {
				t.Fatal(err)
			}
			if err := c.checkpointCompact(); err != nil {
				t.Fatal(err)
			}
			b = reopenCompactFixture(t, b)
			after := b.compact.durable.manifest
			if after.Rolling.Sequence != before.Rolling.Sequence || !after.ActivatedAt.Equal(before.ActivatedAt) ||
				!maps.Equal(files, compactRollingFiles(b.compact.base)) {
				t.Fatal("metadata-only refresh replaced the rolling policy")
			}
			if mode == "local comments" {
				if after.RollingLocalSHA == before.RollingLocalSHA {
					t.Fatal("new local fingerprint was not checkpointed")
				}
			} else if after.RollingSourceMetadata[compactSourceID(feed.URL)].ETag != `W/"new"` {
				t.Fatal("new validator was not checkpointed")
			}
			rollingExpect(t, b, true, "unchanged.test")
		})
	}
}

func writeCompactLocal(t testing.TB, dir, contents string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newStalledCompactFeed(entered, resume chan struct{}) *httptest.Server {
	var requests atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch requests.Add(1) {
		case 1:
			_, _ = io.WriteString(w, "old.test\n")
		case 2:
			_, _ = io.WriteString(w, "ready.test\n")
		default:
			close(entered)
			select {
			case <-resume:
				w.Header().Set("ETag", `"candidate"`)
				_, _ = io.WriteString(w, "ready.test\n")
			case <-r.Context().Done():
			}
		}
	}))
}

func TestRollingInterruptedPublication(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	feed := newStalledCompactFeed(entered, resume)
	defer feed.Close()
	cfg := compactConfig(t)
	cfg.BlockLists = []string{feed.URL}
	cfg.Blocklist = []string{"configured.test"}
	b := compactFixture(t, cfg)
	c := b.compact
	if err := b.refreshCompact(true); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("interrupted checkpoint")
	c.syncBeforeRename = func(*os.File) error { return injected }
	if err := c.checkpointCompact(); !errors.Is(err, injected) {
		t.Fatalf("checkpoint before rename = %v", err)
	}
	if durable, err := readCompactManifest(c.dir); err != nil || durable.Rolling.Sequence != 0 {
		t.Fatalf("checkpoint switched before syncing files: %v", err)
	}
	c.syncBeforeRename = nil
	c.syncDirectory = func(*os.File) error { return injected }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	atPublication := make(chan struct{})
	observeDisk := c.admissionObserver.disk
	firstManifest := true
	c.admissionObserver.disk = func(stage string) (compactAdmissionDisk, error) {
		if stage == compactCheckpointManifestStage && firstManifest {
			firstManifest = false
			close(atPublication)
			select {
			case <-c.refreshContext.Done():
			case <-ctx.Done():
			}
		}
		return observeDisk(stage)
	}
	refresh := make(chan error, 1)
	go func() { refresh <- b.refreshCompact(true); close(refresh) }()
	defer func() { c.cancelRefresh(); <-refresh }()
	awaitCompactTest(t, ctx, entered, "feed stall")
	reload := func(allow string) error {
		next := *cfg
		next.Whitelist = []string{allow}
		apply, err := b.PrepareReload(&next)
		if err == nil {
			apply()
		}
		return err
	}
	reloaded := make(chan error, 1)
	go func() { reloaded <- reload("configured.test") }()
	if err := awaitCompactTest(t, ctx, reloaded, "reload while feed is stalled"); err != nil {
		t.Fatal(err)
	}
	rollingExpect(t, b, false, "configured.test")
	close(resume)
	awaitCompactTest(t, ctx, atPublication, "candidate manifest admission")
	checkpoint := make(chan error, 1)
	go func() { checkpoint <- c.checkpointCompact(); close(checkpoint) }()
	defer func() { cancel(); <-checkpoint }()
	if err := awaitCompactTest(t, ctx, refresh, "refresh refusal during checkpoint uncertainty"); !errors.Is(err, injected) {
		t.Fatalf("refresh accepted uncertain state: %v", err)
	}
	if err := awaitCompactTest(t, ctx, checkpoint, "checkpoint completion"); !errors.Is(err, injected) {
		t.Fatalf("post-rename checkpoint = %v", err)
	}
	if err := b.refreshCompact(true); !errors.Is(err, injected) {
		t.Fatalf("refresh accepted uncertain state: %v", err)
	}
	rollingExpect(t, b, true, "ready.test")
	if c.manifest.RollingSourceMetadata[compactSourceID(feed.URL)].ETag != "" {
		t.Fatal("candidate validators published after checkpoint uncertainty")
	}
	if err := reload("ready.test"); err != nil || b.Set("later.test") {
		t.Fatalf("after uncertainty: reload = %v; API edits must stay disabled", err)
	}
	rollingExpect(t, b, false, "ready.test")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	feed.Close()
	rollingExpect(t, compactFixture(t, cfg), true, "ready.test")
}

func awaitCompactTest[T any](t *testing.T, ctx context.Context, ch <-chan T, stage string) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-ctx.Done():
		t.Fatalf("timed out awaiting %s", stage)
		var zero T
		return zero
	}
}

func TestCompactRefreshIsAtomicAndSealsExpiredWindow(t *testing.T) {
	var revision atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := revision.Load()
		if current == 2 && r.Header.Get("If-None-Match") != `"v0"` {
			t.Error("failed pass exposed a staged validator")
		}
		w.Header().Set("ETag", fmt.Sprintf(`"v%d"`, current))
		_, _ = fmt.Fprintf(w, "first-%d.test\n", current)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := revision.Load()
		body := fmt.Sprintf("second-%d.test\n", current)
		if current == 1 {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)+1))
		}
		_, _ = io.WriteString(w, body)
	}))
	defer second.Close()
	cfg := compactConfig(t)
	cfg.BlockLists = []string{first.URL, second.URL}
	b := compactFixture(t, cfg)
	c := b.compact
	revision.Store(1)
	if err := b.refreshRolling(true); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("second feed refresh: %v; want unexpected EOF", err)
	}
	rollingExpect(t, b, true, "first-0.test", "second-0.test")
	rollingExpect(t, b, false, "first-1.test", "second-1.test")
	revision.Store(2)
	if err := b.refreshRolling(true); err != nil {
		t.Fatal(err)
	}
	middle := c.manifest.Rolling.Sequence
	c.checkpointDeadline = time.Now().Add(-time.Second) // no checkpoint worker is running
	revision.Store(3)
	if err := b.refreshRolling(true); err != nil {
		t.Fatal(err)
	}
	rollingExpect(t, b, true, "first-3.test", "second-3.test")
	for i, tag := range []string{`"v2"`, `"v3"`} {
		if err := c.checkpointCompact(); err != nil {
			t.Fatal(err)
		}
		if m := c.durable.manifest; m.Rolling.Sequence != middle+uint64(i) || m.RollingSourceMetadata[compactSourceID(first.URL)].ETag != tag {
			t.Fatalf("checkpoint did not seal the window for %s", tag)
		}
	}
}

func TestRollingRefreshAdmission(t *testing.T) {
	for _, tc := range []struct{ name, wantError string }{
		{"flash", "flash during rolling feed refresh"},
		{"RAM", "RAM during rolling feed rebuild"},
		{"rebuild", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "flash" && !compactRollingLinuxAdmission {
				t.Skip("RAM admission is Linux-only")
			}
			cfg := compactConfig(t)
			var updated atomic.Bool
			feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				name := "old.test"
				if updated.Load() {
					name = "new.test"
				}
				_, _ = fmt.Fprintf(w, "%s\nmasked.test\n", name)
			}))
			defer feed.Close()
			cfg.BlockLists = []string{feed.URL}
			b := compactFixture(t, cfg)
			c := b.compact
			switch tc.name {
			case "flash":
				c.admissionObserver.disk = func(string) (compactAdmissionDisk, error) {
					return compactAdmissionDisk{available: compactDeviceReserve + compactManifestAllowance, capacity: 128 << 20, block: 4096}, nil
				}
			case "RAM":
				c.admissionObserver.memory = func() (uint64, error) { return compactDeviceReserve - 1, nil }
			case "rebuild":
				if !b.Set("manual.test") || !b.Remove("masked.test") {
					t.Fatal("cannot create API overrides")
				}
				if err := foldCompactEdits(b); err != nil {
					t.Fatal(err)
				}
				ample := c.admissionObserver.memory
				c.admissionObserver.memory = func() (uint64, error) {
					c.admissionObserver.memory = ample // refuse delta admission only
					return compactDeviceReserve - 1, nil
				}
			}
			before := c.manifest.Rolling
			updated.Store(true)
			err := b.refreshCompact(true)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || tc.name == "RAM" && !errors.Is(err, errRollingRAM) {
					t.Fatalf("refresh = %v, want %q", err, tc.wantError)
				}
				durable, err := readCompactManifest(c.dir)
				if err != nil || durable.Rolling == nil || durable.Rolling.Sequence != before.Sequence || c.manifest.Rolling != before {
					t.Fatalf("refused refresh changed policy: durable=%+v err=%v", durable.Rolling, err)
				}
				rollingExpect(t, b, true, "old.test")
				rollingExpect(t, b, false, "new.test")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			check := func(list *BlockList) {
				t.Helper()
				rollingExpect(t, list, true, "new.test", "manual.test")
				rollingExpect(t, list, false, "old.test", "masked.test")
			}
			check(b)
			if err := c.checkpointCompact(); err != nil {
				t.Fatal(err)
			}
			check(reopenCompactFixture(t, b))
		})
	}
}

func TestCompactRejectsIncompatibleStateBeforeCreatingLock(t *testing.T) {
	cfg := compactConfig(t)
	b := compactFixture(t, cfg)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.BlocklistCompactDir, compactLockName)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.BlocklistCompactDir, "manifest.json")
	manifest, err := readCompactManifest(cfg.BlocklistCompactDir)
	if err != nil {
		t.Fatal(err)
	}
	original, err := compactManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Rolling.Version--
	old, err := compactManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Rolling.Version++
	manifest.Rolling.Slices = manifest.Rolling.Slices[1:]
	missingSlice, err := compactManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, file string
		data       []byte
		uris       []string
	}{
		{"version", compactManifestName, old, nil},
		{"missing slice", compactManifestName, missingSlice, nil},
		{"legacy envelope", compactManifestName, []byte(`{"Base":"snapshot","Sources":{}}`), nil},
		{"duplicate field", compactManifestName, append([]byte(`{"Journal":"other",`), original[1:]...), nil},
		{"duplicate rolling field", compactManifestName, bytes.Replace(original, []byte(`"Rolling":{`), []byte(`"Rolling":{"version":0,`), 1), nil},
		{"changed feeds", compactManifestName, original, []string{"http://127.0.0.1:1/new"}},
		{"legacy codec marker", "codec", []byte("legacy"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.file != compactManifestName {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			fixture := filepath.Join(cfg.BlocklistCompactDir, tc.file)
			if err := os.WriteFile(fixture, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			settings := *cfg
			settings.BlockLists = tc.uris
			candidate := &BlockList{cfg: &settings, w: make(map[string]bool)}
			if _, err := candidate.initCompact(compactTestAdmission()); err == nil {
				_ = candidate.Close()
				t.Fatal("incompatible state accepted")
			}
			if _, err := os.Stat(filepath.Join(cfg.BlocklistCompactDir, compactLockName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("incompatible startup created lock: %v", err)
			}
			if after, err := os.ReadFile(fixture); err != nil || !bytes.Equal(after, tc.data) { //nolint:gosec // read back the fixture under t.TempDir
				t.Fatalf("incompatible startup modified manifest: %v", err)
			}
		})
	}
}

func TestCompactReloadSwapsAllowlistAndKeepsPriorDenies(t *testing.T) {
	cfg := compactConfig(t)
	cfg.Blocklist = []string{"old.test", "unmasked.test", "masked.test"}
	cfg.Whitelist = []string{"unmasked.test"}
	b := compactFixture(t, cfg)
	if !b.Remove("old.test") {
		t.Fatal("initial deny was not removable")
	}
	next := &config.Config{Blocklist: []string{"new.test", "old.test"}, Whitelist: []string{"masked.test"}}
	apply, err := b.PrepareReload(next)
	if err != nil {
		t.Fatal(err)
	}
	rollingExpect(t, b, false, "new.test", "unmasked.test", "old.test")
	rollingExpect(t, b, true, "masked.test")
	apply()
	rollingExpect(t, b, true, "new.test", "unmasked.test")
	rollingExpect(t, b, false, "masked.test", "old.test")
}

func TestCompactShutdownCancelsFeedWithoutUnmapping(t *testing.T) {
	var calls atomic.Int32
	started, canceled := make(chan struct{}), make(chan struct{})
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, "durable.test\n")
			return
		}
		_, _ = io.WriteString(w, "unconfirmed.test\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer feed.Close()
	cfg := compactConfig(t)
	cfg.BlockLists = []string{feed.URL}
	cfg.BlocklistRefreshInterval.Duration = time.Millisecond
	b := compactFixture(t, cfg)
	b.startCompactWorkers(true)
	defer b.compact.cancelRefresh()
	rollingExpect(t, b, true, "durable.test")
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("background poll did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b.Persist(ctx)
	select {
	case <-b.compact.workersDone:
	default:
		t.Fatal("Persist returned before canceling the refresh worker")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("feed did not see cancellation")
	}
	rollingExpect(t, b, true, "durable.test")
	rollingExpect(t, b, false, "unconfirmed.test")
}

func TestCompactUncertainCommitStopsWorkers(t *testing.T) {
	cfg := compactConfig(t)
	cfg.BlocklistRefreshInterval.Duration = time.Hour
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "retained.test\n")
	}))
	defer feed.Close()
	cfg.BlockLists = []string{feed.URL}
	b := compactFixture(t, cfg)
	b.startCompactWorkers(true)
	c := b.compact
	_ = c.disableCompactWrites(errCompactUncertainCommit)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	awaitCompactTest(t, ctx, c.workersDone, "worker exit after uncertain commit")
	rollingExpect(t, b, true, "retained.test")
}

func TestCompactFoldWakeDoesNotDelayFeedCheckpoint(t *testing.T) {
	entered := make(chan struct{})
	feed := newStalledCompactFeed(entered, nil)
	defer feed.Close()
	cfg := compactConfig(t)
	cfg.BlockLists = []string{feed.URL}
	b := compactFixture(t, cfg)
	c := b.compact
	if err := b.refreshCompact(true); err != nil {
		t.Fatal(err)
	}
	ready := c.manifest.Rolling.Sequence
	if !b.Set("manual.test") {
		t.Fatal("cannot queue API edit")
	}
	committed := make(chan struct{}, 1)
	c.syncDirectory = notifyCompactCommit(committed)
	c.foldWake = make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		_ = b.refreshCompact(true)
	}()
	defer func() {
		c.cancelRefresh()
		<-refreshDone
	}()
	awaitCompactTest(t, ctx, entered, "feed stall")
	startTestCompactCheckpoints(b)
	for range 2 {
		select {
		case c.foldWake <- struct{}{}:
		case <-ctx.Done():
			t.Fatal("checkpoint worker did not return to its select after a fold wake")
		}
	}
	c.checkpointMu.Lock()
	c.checkpointDeadline = time.Now()
	c.checkpointMu.Unlock()
	c.wakeCheckpoint()
	awaitCompactTest(t, ctx, committed, "checkpoint behind a stalled feed")
	m, err := readCompactManifest(c.dir)
	if err != nil || m.Rolling.Sequence != ready {
		t.Fatalf("durable feed is not the captured revision: %v", err)
	}
}

func TestCompactCheckpointRetriesAfterFlashHeadroomReturns(t *testing.T) {
	cfg := compactConfig(t)
	var revision atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "revision-%d.test\n", revision.Load())
	}))
	defer feed.Close()
	cfg.BlockLists = []string{feed.URL}
	b := compactFixture(t, cfg)
	revision.Store(1)
	if err := b.refreshCompact(true); err != nil {
		t.Fatal(err)
	}
	c := b.compact
	manifest := filepath.Join(cfg.BlocklistCompactDir, "manifest.json")
	original, err := os.ReadFile(manifest) //nolint:gosec // read the manifest in this test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	const capacity = 500 << 20
	const reserve = capacity / 10
	retry, releaseRetry := make(chan struct{}), make(chan struct{})
	attempts := 0
	c.admissionObserver.disk = func(string) (compactAdmissionDisk, error) {
		attempts++
		if attempts == 1 {
			return compactAdmissionDisk{available: reserve, capacity: capacity, block: 4096}, nil
		}
		if attempts == 2 {
			close(retry)
			select {
			case <-releaseRetry:
			case <-c.refreshContext.Done():
			}
		}
		return compactAdmissionDisk{available: reserve + 4<<20, capacity: capacity, block: 4096}, nil
	}
	c.syncDirectory = func(dir *os.File) error {
		defer c.cancelRefresh()
		return dir.Sync()
	}
	c.checkpointWindow = time.Second
	c.checkpointDeadline = time.Now()
	startTestCompactCheckpoints(b)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	awaitCompactTest(t, ctx, retry, "checkpoint retry without another activation")
	after, err := os.ReadFile(manifest) //nolint:gosec // read the manifest in this test's temporary directory
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("the refused checkpoint replaced the durable manifest: %v", err)
	}
	if !b.Exists("revision-1.test") || b.Exists("revision-0.test") {
		t.Fatal("checkpoint attempt changed the active policy")
	}
	close(releaseRetry)
	awaitCompactTest(t, ctx, c.workersDone, "checkpoint completion")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	feed.Close()
	recovered := compactFixture(t, cfg)
	if !recovered.Exists("revision-1.test") || recovered.Exists("revision-0.test") {
		t.Fatal("offline restart did not recover the deferred retry")
	}
}

func TestCompactCleanupPreservesUnrelatedFiles(t *testing.T) {
	cfg := compactConfig(t)
	if err := os.MkdirAll(cfg.BlocklistCompactDir, 0o750); err != nil {
		t.Fatal(err)
	}
	const retired = "rolling-part-12ab-0123456789abcdef0123456789abcdef.psn"
	unrelated := []string{"manifest-backup", "rolling-part-notes", "set-records", "rolling-part-23AB-0123456789abcdef0123456789abcdef.psn"}
	orphans := []string{retired, "manifest-123"}
	for _, name := range append(unrelated, orphans...) {
		if err := os.WriteFile(filepath.Join(cfg.BlocklistCompactDir, name), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	compactFixture(t, cfg)
	for _, name := range orphans {
		if _, err := os.Stat(filepath.Join(cfg.BlocklistCompactDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphan %s still present or unreadable: %v", name, err)
		}
	}
	for _, name := range unrelated {
		if got, err := os.ReadFile(filepath.Join(cfg.BlocklistCompactDir, name)); err != nil || string(got) != "keep" { //nolint:gosec // read back the fixture under t.TempDir
			t.Fatalf("operator file %s: %q, %v", name, got, err)
		}
	}
}

func TestRollingFeedLifecycle(t *testing.T) {
	cfg := compactConfig(t)
	local := writeCompactLocal(t, cfg.BlockListDir, "owned-local.test\n")
	cfg.Blocklist = []string{"configured.test"}
	cfg.Whitelist = []string{"exempt.test"}

	var revision atomic.Int32
	var fetched, unchanged atomic.Int32
	const a0 = "0.0.0.0 Overlap.test old.test owned-local.test\n# comment\n*.wild.test\nexempt.test\n"
	const a1 = "0.0.0.0 New.test new.test\n*.wild.test\nexempt.test\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var etag, body string
		switch r.URL.Path {
		case "/a":
			etag, body = `"a0"`, a0
			if revision.Load() > 0 {
				etag, body = `"a1"`, a1
				if r.Header.Get("If-None-Match") != `"a0"` {
					t.Error("updated feed request did not carry its saved ETag")
				}
			}
		case "/b":
			etag, body = `"b0"`, "overlap.test\nonly-b.test\n"
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", etag)
		if etag == r.Header.Get("If-None-Match") {
			unchanged.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fetched.Add(1)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	cfg.BlockLists = []string{server.URL + "/a", server.URL + "/b"}
	b := compactFixture(t, cfg)
	rollingExpect(t, b, true, "old.test", "child.overlap.test", "only-b.test", "owned-local.test", "child.wild.test", "configured.test")
	rollingExpect(t, b, false, "wild.test", "new.test", "exempt.test", "child.exempt.test")
	if got := b.Length(); got != 7 {
		t.Fatalf("initial stored count = %d, want 7", got)
	}
	revision.Store(1)
	if err := b.refreshCompact(true); err != nil {
		t.Fatal(err)
	}
	if fetched.Load() != 3 || unchanged.Load() != 1 {
		t.Fatalf("expected one request per feed per pass, got %d bodies and %d unchanged responses", fetched.Load(), unchanged.Load())
	}
	rollingExpect(t, b, true, "new.test", "child.overlap.test", "only-b.test", "owned-local.test", "child.wild.test", "configured.test")
	rollingExpect(t, b, false, "old.test", "exempt.test")
	if got := b.Length(); got != 7 {
		t.Fatalf("updated stored count = %d, want 7", got)
	}
	if err := b.compact.checkpointCompact(); err != nil {
		t.Fatal(err)
	}
	if !b.Remove("new.test") || !b.Set("manual.test") || b.Length() != 7 {
		t.Fatalf("manual overrides failed (count %d)", b.Length())
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	reopened := compactFixture(t, cfg)
	rollingExpect(t, reopened, true, "manual.test", "child.overlap.test", "only-b.test", "owned-local.test", "child.wild.test", "configured.test")
	rollingExpect(t, reopened, false, "old.test", "new.test", "exempt.test")
	if got := reopened.Length(); got != 7 {
		t.Fatalf("offline stored count = %d, want 7", got)
	}
	if err := os.WriteFile(local, []byte("replacement-local.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	localUpdated := reopenCompactFixture(t, reopened)
	rollingExpect(t, localUpdated, true, "replacement-local.test", "child.overlap.test", "manual.test")
	rollingExpect(t, localUpdated, false, "owned-local.test", "new.test")
}

func TestCompactStartupRejectsMissingCaseAlias(t *testing.T) {
	cfg := compactConfig(t)
	if err := os.Mkdir(filepath.Join(cfg.Directory, "CaseProbe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "caseprobe")); os.IsNotExist(err) {
		t.Skip("temporary volume is case-sensitive")
	} else if err != nil {
		t.Fatal(err)
	}
	cfg.BlockListDir = filepath.Join(cfg.Directory, "Lists")
	cfg.BlocklistCompactDir = filepath.Join(cfg.Directory, "lists", "state")
	b := &BlockList{cfg: cfg}
	_, err := b.initCompact(compactTestAdmission())
	if err == nil {
		t.Cleanup(func() { _ = b.Close() })
	}
	if err == nil || !strings.Contains(err.Error(), "must be separate from blocklistdir") {
		t.Fatalf("initCompact() error = %v; want overlap rejection", err)
	}
	entries, err := os.ReadDir(cfg.BlocklistCompactDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("created state directory = %v, %v; want no lock or artifacts", entries, err)
	}
}

type compactTestReader func([]byte) (int, error)

func (r compactTestReader) Read(p []byte) (int, error) { return r(p) }

func TestCompactLocalSkipsFIFO(t *testing.T) {
	const child = "SDNS_TEST_COMPACT_FIFO_CHILD"
	if os.Getenv(child) != "1" {
		t.Run("cancel fingerprint copy", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			r := compactTestReader(func(p []byte) (int, error) {
				if ctx.Err() != nil {
					t.Fatal("read again after cancellation")
				}
				cancel()
				p[0] = 'x'
				return 1, nil
			})
			if err := copyCompactFingerprint(ctx, sha256.New(), r, make([]byte, 32<<10)); err != context.Canceled {
				t.Fatalf("copy error = %v, want context.Canceled", err)
			}
		})
		// Canceling a context cannot interrupt a blocking FIFO open. Use a
		// subprocess so a regression fails this test without leaking a goroutine.
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCompactLocalSkipsFIFO$") //nolint:gosec // run this test binary with fixed arguments
		cmd.Env = append(os.Environ(), child+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("FIFO startup and refresh: %v (context: %v)\n%s", err, ctx.Err(), out)
		}
		return
	}

	cfg := compactConfig(t)
	local := writeCompactLocal(t, cfg.BlockListDir, "before.test\n")
	target := filepath.Join(cfg.Directory, "target.txt")
	if err := os.WriteFile(target, []byte("linked.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(cfg.BlockListDir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cfg.Directory, filepath.Join(cfg.BlockListDir, "nofollow")); err != nil {
		t.Fatal(err)
	}
	b := compactFixture(t, cfg)
	rollingExpect(t, b, true, "before.test", "linked.test")
	fifo := filepath.Join(cfg.BlockListDir, "pipe")
	if out, err := exec.Command("mkfifo", "-m", "600", fifo).CombinedOutput(); err != nil { //nolint:gosec // FIFO path is in the test fixture
		t.Fatalf("mkfifo: %v: %s", err, out)
	}
	if err := os.Symlink(fifo, filepath.Join(cfg.BlockListDir, "pipe-link")); err != nil {
		t.Fatal(err)
	}
	before := b.compact.manifest.RollingLocalSHA
	refresh := func() {
		t.Helper()
		b.compact.mu.Lock()
		defer b.compact.mu.Unlock()
		if err := b.refreshRolling(false); err != nil {
			t.Fatal(err)
		}
	}
	refresh()
	if got := b.compact.manifest.RollingLocalSHA; got != before {
		t.Fatalf("FIFO changed local fingerprint: %q != %q", got, before)
	}
	if err := os.WriteFile(local, []byte("after.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	refresh()
	rollingExpect(t, b, true, "after.test")
	rollingExpect(t, b, false, "before.test")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.BlocklistCompactDir = filepath.Join(cfg.Directory, "fresh")
	rollingExpect(t, compactFixture(t, cfg), true, "after.test")
}

func TestCompactRemoteHostsParsing(t *testing.T) {
	const input = " # comment\r\nUPPER.Example\n*.EXAMPLE.\t#wildcard\n0.0.0.0 a.test B.TEST.\n2001:DB8::7\tc.test\u2003D.test\nfe80::1%eth0 zoned.test\na\\.b.test.\nBücher.Test\n.\n"
	const expected = "upper.example.\n*.example.\na.test.\nb.test.\nc.test.\nd.test.\nzoned.test.\na\\.b.test.\nbücher.test.\n.\n"
	c := compactManager{refreshContext: t.Context()}
	var out bytes.Buffer
	if err := c.emitRollingResponse(&out, strings.NewReader(input)); err != nil || out.String() != expected {
		t.Fatalf("parse = %q, %v", out.String(), err)
	}
	for _, bad := range []string{"not-an-ip a.test\n", "double..dot\n", strings.Repeat("a", 64) + ".test", `bare\`} {
		if err := scanRollingHosts(strings.NewReader(bad), bufio.NewWriter(io.Discard), false); err == nil {
			t.Errorf("accepted malformed feed %q", bad)
		}
	}
}

func TestCompactLocalHostsParsing(t *testing.T) {
	var out strings.Builder
	writer := bufio.NewWriter(&out)
	if err := scanRollingHosts(strings.NewReader("ignored-column UPPER..test\n"), writer, true); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil || out.String() != "upper..test.\n" {
		t.Fatalf("local parse = %q, %v", out.String(), err)
	}
}

func TestCompactWireLookup(t *testing.T) { checkCompactWireLookup(t, nil) }

func checkCompactWireLookup(t *testing.T, check func(*BlockList, []byte)) {
	t.Helper()
	cfg := compactConfig(t)
	cfg.Blocklist = []string{"blocked.org", "*.wild.org"}
	writeCompactLocal(t, cfg.BlockListDir, "feed.org\n")
	b := compactFixture(t, cfg)
	if !b.Set("manual.org") || !b.Remove("blocked.org") {
		t.Fatal("cannot set up manual overrides")
	}
	if err := foldCompactEdits(b); err != nil {
		t.Fatal(err)
	}
	if b.Length() != 3 || b.Exists("blocked.org") || !b.Exists("manual.org") {
		t.Fatal("fold changed the effect or count of manual overrides")
	}
	if !b.Set("pending.org") {
		t.Fatal("cannot set up pending override")
	}
	for _, name := range []string{"blocked.org.", "sub.blocked.org.", "sub.wild.org.", "feed.org.", "manual.org.", "pending.org.", "missing.org."} {
		wire := make([]byte, 255)
		end, err := dns.PackDomainName(name, wire, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		wire = wire[:end]
		if got, ok := b.existsWire(wire); !ok || got != b.Exists(name) {
			t.Fatal("wire mismatch", name)
		}
		if check != nil {
			check(b, wire)
		}
	}
}

func TestParseCompactBlocklist(t *testing.T) {
	for _, tc := range []struct {
		name, extra, wantError string
		compact                bool
		poll, window           time.Duration
	}{
		{name: "default"},
		{name: "compact", extra: "blocklist_compact = true\n", compact: true, window: 24 * time.Hour},
		{name: "explicit zero", extra: "blocklist_compact = true\nblocklist_refresh_interval = '30s'\nblocklist_checkpoint_window = '0s'\n", compact: true, poll: 30 * time.Second},
		{name: "equal paths", extra: "blocklist_compact = true\n", compact: true, wantError: "must be separate from blocklistdir"},
		{name: "poll requires compact", extra: "blocklist_refresh_interval = '1s'\n", wantError: "blocklist_refresh_interval requires blocklist_compact"},
		{name: "checkpoint requires compact", extra: "blocklist_checkpoint_window = '1s'\n", wantError: "blocklist_checkpoint_window requires blocklist_compact"},
		{name: "negative poll", extra: "blocklist_compact = true\nblocklist_refresh_interval = '-1s'\n", wantError: "blocklist_refresh_interval must be nonnegative"},
		{name: "negative checkpoint", extra: "blocklist_compact = true\nblocklist_checkpoint_window = '-1s'\n", wantError: "blocklist_checkpoint_window must be nonnegative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "sdns.conf")
			content := fmt.Sprintf("directory = %q\ndnssec = \"off\"\nrootservers = [\"192.0.2.1:53\"]\n%s", filepath.Join(dir, "db"), tc.extra)
			if tc.name == "equal paths" {
				content += fmt.Sprintf("blocklistdir = %[1]q\nblocklist_compact_dir = %[1]q\n", dir)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Parse(path, nil)
			wantError := tc.wantError
			if tc.compact && !compactSupported {
				wantError = "compact blocklist requires Linux or macOS"
			}
			if wantError != "" {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("Parse() error = %v; want %q", err, wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.BlocklistCompact != tc.compact || cfg.BlocklistRefreshInterval.Duration != tc.poll || cfg.BlocklistCheckpointWindow.Duration != tc.window {
				t.Fatalf("compact = %t, refresh = %v, checkpoint = %v", cfg.BlocklistCompact, cfg.BlocklistRefreshInterval.Duration, cfg.BlocklistCheckpointWindow.Duration)
			}
		})
	}
}

func TestParseCompactBlocklistPaths(t *testing.T) {
	if !compactSupported {
		t.Skip("compact blocklist requires Linux or macOS")
	}
	dir := t.TempDir()
	physicalRoot := filepath.Join(dir, "physical")
	target := filepath.Join(physicalRoot, "nested")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	writeCompactLocal(t, filepath.Join(physicalRoot, "lists"), "local.test\n")
	file := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	working := link + "/.."
	local := link + "/../lists"
	parse := func(state string) (*config.Config, error) {
		t.Helper()
		path := filepath.Join(dir, "sdns.conf")
		content := fmt.Sprintf("directory = %q\ndnssec = 'off'\nrootservers = ['192.0.2.1:53']\nblocklist_compact = true\nblocklists = ['http://127.0.0.1:1/feed']\nblocklistdir = %q\n",
			working, local)
		if state != "" {
			content += fmt.Sprintf("blocklist_compact_dir = %q\n", state)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return config.Parse(path, nil)
	}
	cfg, err := parse("")
	if err != nil {
		t.Fatalf("compact symlink-before-dot-dot paths: %v", err)
	}
	root, err := filepath.EvalSymlinks(physicalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cfg.ValidateCompactBlocklist(); err != nil || got != filepath.Join(root, "blocklist-compact") {
		t.Fatalf("compact state dir = %q, %v; want a child of %q", got, err, root)
	}
	for _, state := range []string{file, filepath.Join(file, "child")} {
		if _, err := parse(state); err == nil || !strings.Contains(err.Error(), "blocklist_compact_dir:") {
			t.Fatalf("Parse with state path %q under a file: %v", state, err)
		}
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{dangling, dangling + "/", filepath.Join(dangling, "sub"), dangling + "/../store", dir + "/missing/../dangling/../store"} {
		if _, err := parse(state); err == nil || !strings.Contains(err.Error(), "blocklist_compact_dir: dangling symlink") {
			t.Errorf("Parse with dangling path %q: %v", state, err)
		}
	}
	t.Run("state writability", func(t *testing.T) {
		unwritable := filepath.Join(dir, "readonly")
		if err := os.Mkdir(unwritable, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(unwritable, 0o700) }() //nolint:gosec // G302: restore test directory.
		f, err := os.CreateTemp(unwritable, "permission-test-*")
		if err == nil {
			_ = f.Close()
			t.Skip("process can write despite directory permissions")
		}
		if !os.IsPermission(err) {
			t.Fatal(err)
		}
		for _, state := range []string{unwritable, filepath.Join(unwritable, "nested", "store")} {
			if _, err := parse(state); err == nil || !strings.Contains(err.Error(), "blocklist_compact_dir:") {
				t.Errorf("Parse with unwritable state %q: %v", state, err)
			}
		}
		unreadable := filepath.Join(dir, "write-only-input")
		if err := os.Mkdir(unreadable, 0o300); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(unreadable, 0o700) }() //nolint:gosec // G302: restore test directory.
		originalLocal := local
		local = unreadable
		defer func() { local = originalLocal }()
		if _, err := parse(unwritable); err == nil ||
			!strings.Contains(err.Error(), "blocklist_compact_dir:") ||
			!strings.Contains(err.Error(), fmt.Sprintf("blocklistdir = %q:", unreadable)) {
			t.Errorf("Parse with unwritable state and unreadable input: %v", err)
		}
	})
	t.Run("state readability", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read directories without read permissions")
		}
		unreadable := filepath.Join(dir, "write-only-state")
		if err := os.Mkdir(unreadable, 0o300); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(unreadable, 0o700) }() //nolint:gosec // G302: restore test directory.
		if _, err := parse(unreadable); err == nil || !strings.Contains(err.Error(), "blocklist_compact_dir:") {
			t.Fatalf("Parse with unreadable state: %v", err)
		}
		if _, err := parse(filepath.Join(unreadable, "absent")); err != nil {
			t.Fatalf("Parse with creatable state under write-only parent: %v", err)
		}
	})
	working = filepath.Join(dir, "missing")
	missing := filepath.Join(working, "nested", "store")
	if _, err := parse(missing); err != nil {
		t.Fatalf("Parse with creatable state %q: %v", missing, err)
	}
	if _, err := os.Stat(working); !os.IsNotExist(err) {
		t.Fatalf("Parse must not create the state path: %v", err)
	}
	for _, local = range []string{dangling, dangling + "/", filepath.Join(dangling, "sub")} {
		_, err := parse(missing)
		if err == nil || strings.Count(err.Error(), "blocklistdir =") != 1 ||
			strings.Contains(err.Error(), "blocklist_compact_dir") || !strings.Contains(err.Error(), "dangling symlink") {
			t.Errorf("Parse with dangling input root %q: %v", local, err)
		}
	}
	local = dangling
	if _, err := parse(file); err == nil ||
		!strings.Contains(err.Error(), "blocklist_compact_dir:") || !strings.Contains(err.Error(), "is not a directory") ||
		!strings.Contains(err.Error(), fmt.Sprintf("blocklistdir = %q: dangling symlink", dangling)) {
		t.Errorf("Parse with an invalid state directory and a dangling input root: %v", err)
	}
	readonly := filepath.Join(dir, "read-only-input")
	if err := os.Mkdir(readonly, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(readonly, 0o700) }() //nolint:gosec // G302: restore test directory.
	for _, local = range []string{readonly, filepath.Join(readonly, "absent", "nested")} {
		if _, err := parse(missing); err != nil {
			t.Errorf("Parse with read-only or absent input %q: %v", local, err)
		}
	}
	for _, path := range []string{filepath.Base(file), "state"} {
		local = dir + "/missing/../" + path
		if _, err := parse(filepath.Join(dir, "state")); err != nil {
			t.Errorf("Parse with absent literal input %q: %v", local, err)
		}
	}
}

func TestCompactBlocklistDirectories(t *testing.T) {
	if !compactSupported {
		t.Skip("compact blocklist requires Linux or macOS")
	}
	dir := t.TempDir()
	c := &config.Config{Directory: dir, BlocklistCompact: true}
	resolved, _ := filepath.EvalSymlinks(dir)
	got, err := c.ValidateCompactBlocklist()
	if err != nil || got != filepath.Join(resolved, "blocklist-compact") {
		t.Fatalf("default %q %v", got, err)
	}
	c.BlockListDir = filepath.Join(dir, "lists")
	c.BlocklistCompactDir = filepath.Join(c.BlockListDir, "child")
	if _, err = c.ValidateCompactBlocklist(); err == nil {
		t.Fatal("nested accepted")
	}
	c.BlocklistCompactDir = dir
	if _, err = c.ValidateCompactBlocklist(); err == nil {
		t.Fatal("parent accepted")
	}
	if err = os.Mkdir(c.BlockListDir, 0750); err != nil {
		t.Fatal(err)
	}
	c.BlockListDir = filepath.VolumeName(dir) + string(os.PathSeparator)
	c.BlocklistCompactDir = filepath.Join(dir, "compact")
	if _, err = c.ValidateCompactBlocklist(); err == nil {
		t.Fatal("root nesting accepted")
	}
	t.Run("symlink ancestor", func(t *testing.T) {
		lists := filepath.Join(dir, "lists")
		link := filepath.Join(dir, "alias")
		if err := os.Symlink(lists, link); err != nil {
			t.Skip(err)
		}
		c.BlockListDir = lists
		c.BlocklistCompactDir = filepath.Join(link, "not-yet-created")
		if _, err := c.ValidateCompactBlocklist(); err == nil {
			t.Fatal("nested symlink accepted")
		}
	})
	t.Run("symlink before dot-dot", func(t *testing.T) {
		lists := filepath.Join(dir, "lists")
		target := filepath.Join(lists, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "literal")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		c.BlockListDir = lists
		c.BlocklistCompactDir = link + "/../absent"
		if _, err := c.ValidateCompactBlocklist(); err == nil {
			t.Fatal("nested symlink/.. accepted")
		}
	})
}

func TestCompactUnsupportedPlatform(t *testing.T) {
	if compactSupported {
		t.Skip("platform supports compact mode")
	}
	cfg := &config.Config{BlocklistCompact: true}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "compact blocklist requires Linux or macOS") {
		t.Fatalf("config accepted unsupported compact platform: %v", err)
	}
	b := &BlockList{cfg: cfg}
	if _, err := b.initCompact(compactAdmissionObserver{}); err == nil || err.Error() != "compact blocklist requires Linux or macOS" {
		t.Fatalf("compact platform refusal: %v", err)
	}
}

func TestCompactRejectsTooManyFeeds(t *testing.T) {
	cfg := compactConfig(t)
	for i := range 62 {
		cfg.BlockLists = append(cfg.BlockLists, fmt.Sprintf("http://127.0.0.1:1/feed-%d", i))
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "at most 61 distinct remote blocklists") {
		t.Fatalf("config accepted too many feeds: %v", err)
	}
	b := &BlockList{cfg: cfg}
	if _, err := b.initCompact(compactTestAdmission()); err == nil || !strings.Contains(err.Error(), "at most 61 distinct remote blocklists") {
		t.Fatalf("compact feed limit: %v", err)
	}
}

func TestCompactLocalRootResolution(t *testing.T) {
	for _, kind := range []string{"dangling root", "symlink before dot-dot"} {
		t.Run(kind, func(t *testing.T) {
			cfg := compactConfig(t)
			target := filepath.Join(cfg.Directory, "target", "lists")
			writeCompactLocal(t, target, "kept.test\n")
			link := cfg.BlockListDir
			if kind == "symlink before dot-dot" {
				writeCompactLocal(t, cfg.BlockListDir, "wrong.test\n")
				link = filepath.Join(cfg.Directory, "alias")
				cfg.BlockListDir = link + "/../lists"
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			b := compactFixture(t, cfg)
			kept := "kept.test"
			rollingExpect(t, b, true, kept)
			if kind == "symlink before dot-dot" {
				rollingExpect(t, b, false, "wrong.test")
				writeCompactLocal(t, target, "refreshed.test\n")
				if err := b.refreshRolling(false); err != nil {
					t.Fatal(err)
				}
				kept = "refreshed.test"
				rollingExpect(t, b, true, kept)
			}
			if err := os.Rename(target, target+"-offline"); err != nil {
				t.Fatal(err)
			}
			if err := b.refreshRolling(false); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("dangling root refresh: %v", err)
			}
			rollingExpect(t, b, true, kept)
		})
	}
}

func TestCompactLocalRootCannotRetargetIntoStore(t *testing.T) {
	cfg := compactConfig(t)
	target := filepath.Join(cfg.Directory, "local")
	writeCompactLocal(t, target, "kept.test\n")
	if err := os.Symlink(target, cfg.BlockListDir); err != nil {
		t.Fatal(err)
	}
	if f, err := openCompactFeedDirectory(cfg.BlockListDir); err == nil {
		_ = f.Close()
		t.Fatal("descriptor open followed a directory symlink")
	}
	b := compactFixture(t, cfg)
	if err := os.Remove(cfg.BlockListDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b.compact.dir, cfg.BlockListDir); err != nil {
		t.Fatal(err)
	}
	if err := b.refreshRolling(false); err == nil || !strings.Contains(err.Error(), "must be separate from blocklistdir") {
		t.Fatalf("retargeted local root refresh: %v", err)
	}
	rollingExpect(t, b, true, "kept.test")
}

func TestCompactLocalOpenedDirectoryCannotAliasStore(t *testing.T) {
	cfg := compactConfig(t)
	writeCompactLocal(t, cfg.BlockListDir, "kept.test\n")
	b := compactFixture(t, cfg)
	if err := os.Mkdir(filepath.Join(cfg.BlockListDir, "mounted-state"), 0o700); err != nil {
		t.Fatal(err)
	}
	open := openCompactFeedDirectory
	t.Cleanup(func() { openCompactFeedDirectory = open })
	openCompactFeedDirectory = func(path string) (*os.File, error) {
		if filepath.Base(path) == "mounted-state" {
			// Model a bind mount without requiring a mount syscall.
			return open(b.compact.dir)
		}
		return open(path)
	}
	if err := b.refreshRolling(false); err == nil || !strings.Contains(err.Error(), "is the compact state directory") {
		t.Fatalf("refresh with state directory alias: %v", err)
	}
	rollingExpect(t, b, true, "kept.test")
}

func TestCompactLocalOversizeKeyNamesFile(t *testing.T) {
	cfg := compactConfig(t)
	writeCompactLocal(t, cfg.BlockListDir, "kept.test\n")
	b := compactFixture(t, cfg)
	// The line fits the scanner, but appending the final dot exceeds MaxKey.
	path := writeCompactLocal(t, cfg.BlockListDir, strings.Repeat("x", compactset.MaxKey)+"\n")
	err := b.refreshRolling(false)
	if err == nil || !strings.Contains(err.Error(), filepath.Base(path)) || !strings.Contains(err.Error(), "canonical DNS name exceeds") {
		t.Fatalf("refresh with oversize key: %v", err)
	}
	rollingExpect(t, b, true, "kept.test")
}

func TestCompactRelativeAliasFingerprint(t *testing.T) {
	cfg := compactConfig(t)
	input := filepath.Join(cfg.Directory, "input")
	const body = "local.test\n"
	writeCompactLocal(t, input, body)
	t.Chdir(input)
	if err := os.Symlink(".", "alias"); err != nil {
		t.Fatal(err)
	}
	cfg.BlockListDir = "alias"
	got := compactFixture(t, cfg).compact.manifest.RollingLocalSHA
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("11:alias/hosts:11:"+body)))
	if got != want {
		t.Fatalf("relative alias fingerprint = %q; want %q", got, want)
	}
}

func TestCompactLocalIngestChecksFingerprint(t *testing.T) {
	cfg := compactConfig(t)
	const lines = compactLocalEmitBuffer/len("modified.test.\n") + 1
	a := strings.Repeat("original.test\n", lines)
	writeCompactLocal(t, cfg.BlockListDir, a)
	b := compactFixture(t, cfg)
	ledger := rollingLedger(compactFeedWorkingLimit)
	fingerprint, err := b.compactLocalFingerprint(ledger)
	if err != nil {
		t.Fatal(err)
	}
	local := writeCompactLocal(t, cfg.BlockListDir, strings.Repeat("modified.test\n", lines))
	restored := false
	out := compactTestWriter(func(p []byte) (int, error) {
		if !restored {
			if !bytes.HasPrefix(p, []byte("modified.test.")) {
				t.Fatal("local parser did not emit B before restoring A")
			}
			// Restore on the open inode without changing the file length.
			f, err := os.OpenFile(local, os.O_WRONLY, 0) //nolint:gosec // G304: path is a temporary test fixture.
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteString(a)
			if err := errors.Join(err, f.Close()); err != nil {
				t.Fatal(err)
			}
			restored = true
		}
		return len(p), nil
	})
	ingestErr := b.emitRollingLocal(t.Context(), out, ledger, fingerprint)
	if !restored || ingestErr == nil || !strings.Contains(ingestErr.Error(), "local blocklist files changed") {
		t.Fatalf("A→B→A ingest: restored = %t, error = %v", restored, ingestErr)
	}
	if got, err := b.compactLocalFingerprint(ledger); err != nil || got != fingerprint {
		t.Fatalf("restored fingerprint = %q, %v; want %q", got, err, fingerprint)
	}
}

type compactTestWriter func([]byte) (int, error)

func (w compactTestWriter) Write(p []byte) (int, error) { return w(p) }

func TestCompactResponseValidators(t *testing.T) {
	cfg := compactConfig(t)
	const modified = "Mon, 02 Jan 2006 15:04:05 GMT"
	const july = "Sun, 02 Jul 2006 15:04:05 GMT"
	var request atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := request.Add(1)
		want := ""
		switch n {
		case 2, 3:
			want = modified
		case 5:
			want = july
		}
		if got := r.Header.Get("If-Modified-Since"); got != want {
			t.Errorf("request %d: If-Modified-Since = %q, want %q", n, got, want)
		}
		switch n {
		case 1:
			w.Header().Set("ETag", `"saved"`)
			w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05.9 GMT")
		case 2:
			if got := r.Header.Get("If-None-Match"); got != `"saved"` {
				t.Errorf("conditional ETag = %q", got)
			}
			w.Header().Set("ETag", `"`+strings.Repeat("<", 200)+`"`)
			w.Header().Set("Last-Modified", "not an HTTP date")
			w.WriteHeader(http.StatusNotModified)
			return
		case 3:
			w.Header().Set("ETag", "\"\xff\"")
			w.Header().Set("Last-Modified", "not an HTTP date")
		case 4, 5:
			if got := r.Header.Get("If-None-Match"); got != "" {
				t.Errorf("invalid ETag sent: %q", got)
			}
			if n == 4 {
				w.Header().Set("ETag", "*")
				w.Header().Set("Last-Modified", "Sunday, 02-Jul-06 15:04:05 GMT")
			} else {
				w.Header().Set("Last-Modified", "Monday, 02-Jan-06 15:04:05 BST")
			}
		}
		_, _ = io.WriteString(w, "kept.test\n")
	}))
	defer server.Close()
	cfg.BlockLists = []string{server.URL}
	b := compactFixture(t, cfg)
	id := compactSourceID(server.URL)
	for _, want := range []compactRollingSourceMetadata{{ETag: `"saved"`, LastModified: modified}, {}, {LastModified: july}, {}} {
		if err := b.refreshCompact(true); err != nil {
			t.Fatal(err)
		}
		got := b.compact.manifest.RollingSourceMetadata[id]
		if got.ETag != want.ETag || got.LastModified != want.LastModified {
			t.Fatalf("stored validators = (%q, %q); want (%q, %q)", got.ETag, got.LastModified, want.ETag, want.LastModified)
		}
	}
}

func TestCompactRejectsMalformedUTF8Names(t *testing.T) {
	const input = "0.0.0.0 invalid-\xff.test\n"
	for _, local := range []bool{false, true} {
		err := scanRollingHosts(strings.NewReader(input), bufio.NewWriter(io.Discard), local)
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Errorf("scanner (local=%t): %v", local, err)
		}
	}
}

func TestCompactPipeReportsProducerErrorOnce(t *testing.T) {
	want := errors.New("producer failed")
	pipe := openCompactKeyPipe(func(io.Writer) error { return want }, nil)
	if _, err := io.ReadAll(pipe); !errors.Is(err, want) {
		t.Fatalf("pipe read: %v", err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("duplicate error on close: %v", err)
	}
}

func TestCompactPipeCloseCancelsStalledFetch(t *testing.T) {
	b := compactFixture(t, compactConfig(t))
	refresh := b.compact.base.BeginRefresh(compactFeedWorkingLimit, nil)
	watchdog, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	fetch, cancel := context.WithCancel(t.Context())
	defer cancel()
	body, _, err := requestCompactSource(fetch, server.URL, compactRollingSourceMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	pipe := openCompactKeyPipe(func(io.Writer) error {
		defer body.Close()
		close(started)
		_, err := io.Copy(io.Discard, body)
		return err
	}, body.cancel)
	awaitCompactTest(t, watchdog, started, "stalled body reader")
	consumer, refuse := context.WithCancelCause(t.Context())
	refused := errors.New("builder refused input")
	refuse(refused)
	finished := make(chan error, 1)
	go func() {
		_, err := compactOwnerDiff(consumer, refresh, compactRollingLocalOwner, pipe)
		finished <- err
	}()
	if err := awaitCompactTest(t, watchdog, finished, "refused builder return"); !errors.Is(err, refused) {
		t.Fatalf("early consumer close lost builder error: %v", err)
	}
	awaitCompactTest(t, watchdog, canceled, "fetch cancellation")
}

func TestCompactFeedErrorOmitsSecrets(t *testing.T) {
	const uri = "https://example.com/private/path?token=configured-secret"
	cause := &url.Error{Op: "Get", URL: uri, Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
	err := compactFeedError([]string{"first", uri}, uri, cause)
	if got, want := err.Error(), "blocklists[2] example.com: dial: "+syscall.ECONNREFUSED.Error(); got != want {
		t.Fatalf("feed error = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("redaction lost the underlying error")
	}
	cause.Err = fmt.Errorf("private transport detail: %w", http.ErrSchemeMismatch)
	err = compactFeedError([]string{uri}, uri, cause)
	if got, want := err.Error(), "blocklists[1] example.com: "+http.ErrSchemeMismatch.Error(); got != want || !errors.Is(err, http.ErrSchemeMismatch) {
		t.Fatalf("scheme mismatch error = %q, want %q wrapping the sentinel", got, want)
	}
}

func TestCompactFeedErrorRedactsMalformedRedirect(t *testing.T) {
	cfg := compactConfig(t)
	const secret = "reflected-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/%ZZ?token="+r.URL.Query().Get("token"))
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	uri := server.URL + "?token=" + secret
	cfg.BlockLists = []string{uri}
	b := &BlockList{cfg: cfg, w: map[string]bool{}}
	_, err := b.initCompact(compactTestAdmission())
	if err == nil {
		_ = b.Close()
		t.Fatal("compact startup accepted a malformed feed redirect")
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) || !strings.Contains(urlErr.Err.Error(), secret) {
		t.Fatalf("compact startup did not retain the underlying redirect error: %v", err)
	}
	if got, want := err.Error(), "blocklists[1] "+strings.TrimPrefix(server.URL, "http://")+": feed request failed"; strings.Contains(got, secret) || !strings.Contains(got, want) {
		t.Fatalf("redacted redirect error = %q; want %q without the token", got, want)
	}
}
