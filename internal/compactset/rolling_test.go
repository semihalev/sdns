//go:build linux || darwin

package compactset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
	"golang.org/x/sys/unix"
)

const maxMemory = 32 << 20

func TestSyncRollingParentsStopsAtMountBoundary(t *testing.T) {
	const mount = "/volumes/mount"
	const nested = mount + "/nested"
	const store = nested + "/store"
	var stats, synced []string
	device := func(path string) (uint64, error) {
		stats = append(stats, path)
		switch path {
		case store, nested, mount:
			return 1, nil
		case "/volumes":
			return 2, nil
		default:
			t.Fatalf("stat above mount boundary: %s", path)
			return 0, nil
		}
	}
	syncDir := func(path string) error {
		synced = append(synced, path)
		return nil
	}
	if err := syncRollingParents(store, device, syncDir); err != nil {
		t.Fatal(err)
	}
	if want := []string{store, nested, mount, "/volumes"}; !slices.Equal(stats, want) {
		t.Errorf("stat paths = %v, want %v", stats, want)
	}
	if want := []string{nested, mount}; !slices.Equal(synced, want) {
		t.Errorf("synced paths = %v, want %v", synced, want)
	}

	synced = nil
	if err := syncRollingParents(mount, device, syncDir); err != nil || len(synced) != 0 {
		t.Errorf("store at mount root synced %v, err %v", synced, err)
	}
	failed := errors.New("injected sync error")
	if err := syncRollingParents(store, device, func(string) error { return failed }); !errors.Is(err, failed) {
		t.Errorf("same-device sync failure = %v, want %v", err, failed)
	}
}

func TestRollingInstallUnderSearchOnlyAncestor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged directory permissions")
	}
	ancestor := t.TempDir()
	store := filepath.Join(ancestor, "store")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0111); err != nil { //nolint:gosec // G302: search-only ancestor under test.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0700) }) //nolint:gosec // G302: restore test directory.
	rollingTestBuild(t, RollingOptions{Dir: store, Owners: []string{"feed"}}, maxMemory, map[string][]string{"feed": {"blocked.example."}})
}

func rollingTestInput(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return strings.Join(keys, "\n") + "\n"
}

func rollingTestBuild(t *testing.T, opt RollingOptions, workspace int64, owners map[string][]string) RollingManifest {
	t.Helper()
	readers := make(map[string]func() (io.ReadCloser, error), len(owners))
	for id, keys := range owners {
		input := rollingTestInput(keys)
		readers[id] = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(input)), nil }
	}
	m, err := BuildRolling(t.Context(), opt, workspace, readers, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func rollingTestOpen(t *testing.T, opt RollingOptions, m RollingManifest) *Rolling {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RollingManifest
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRolling(t.Context(), opt, decoded)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rollingTestClose(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}

func rollingTestDiff(t *testing.T, r *RollingRefresh, owner string, keys []string) *RollingChange {
	t.Helper()
	c, err := r.Diff(t.Context(), owner, strings.NewReader(rollingTestInput(keys)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rollingTestApply(t *testing.T, r *RollingRefresh, cs ...*RollingChange) RollingManifest {
	t.Helper()
	update, err := r.Apply(t.Context(), cs)
	for _, c := range cs {
		rollingTestClose(t, c)
	}
	if err != nil {
		t.Fatal(err)
	}
	return update.Manifest()
}
func TestRollingRandomizedModel(t *testing.T) {
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed-a", "feed-b", "local"}}
	rng := rand.New(rand.NewPCG(29, 47)) //nolint:gosec // G404: deterministic test input.
	keys := make([]string, 768)
	for i := range keys {
		keys[i] = fmt.Sprintf("%c%c-name%d.example.", 'a'+rune(i%24), 'a'+rune(i/24%16), i)
		if i < len(keys)/2 {
			// Exercise cold count verification in both sparse shards and
			// dense shards with many independently seekable key blocks.
			keys[i] = fmt.Sprintf("z%c-name%04d.example.", 'a'+rune(i%4), i)
		}
	}
	var owner [3]map[string]bool
	for i := range owner {
		owner[i] = make(map[string]bool)
		for j := range 400 {
			owner[i][keys[(j+i*108)%len(keys)]] = true
		}
	}
	body := func(i int) []string {
		var names []string
		for _, key := range keys {
			if owner[i][key] {
				names = append(names, key)
			}
		}
		rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
		return append(names, names[:12]...)
	}
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{opt.Owners[0]: body(0), opt.Owners[1]: body(1), opt.Owners[2]: body(2)})
	for step := range rollingSlices + 2 {
		r := rollingTestOpen(t, opt, m)
		count := 0
		for _, key := range keys {
			var want uint64
			for i, set := range owner {
				if set[key] {
					want |= 1 << i
				}
			}
			if want != 0 {
				count++
			}
			got := r.OwnerMask([]byte(key))
			if got != want {
				t.Fatalf("step %d key %s: got mask %b want %b", step, key, got, want)
			}
		}
		if m.Count != count || r.OwnerMask([]byte("not-in-model.example.")) != 0 {
			t.Fatalf("step %d count %d want %d", step, m.Count, count)
		}
		if step == rollingSlices+1 {
			rollingTestClose(t, r)
			break
		}
		refresh := r.BeginRefresh(maxMemory, nil)
		var changes []*RollingChange
		for i := range owner {
			if i != step%3 && (step+i)%4 != 0 {
				continue
			}
			var have, absent []string
			for _, key := range keys {
				if owner[i][key] {
					have = append(have, key)
				} else {
					absent = append(absent, key)
				}
			}
			rng.Shuffle(len(have), func(a, b int) { have[a], have[b] = have[b], have[a] })
			rng.Shuffle(len(absent), func(a, b int) { absent[a], absent[b] = absent[b], absent[a] })
			n := len(have) / 100
			if step%8 == 3 {
				n = len(have) * 8 / 100
			}
			for j := range n {
				delete(owner[i], have[j])
				owner[i][absent[j]] = true
			}
			c := rollingTestDiff(t, refresh, opt.Owners[i], body(i))
			if c.Adds != n || c.Removes != n {
				t.Fatalf("step %d owner %d: unexpected diff +%d -%d", step, i, c.Adds, c.Removes)
			}
			changes = append(changes, c)
		}
		m = rollingTestApply(t, refresh, changes...)
		rollingTestClose(t, r)
	}
}

func TestRollingOwnerOverlapAndWideMasks(t *testing.T) {
	ids := make([]string, 64)
	owner := make(map[string][]string, len(ids))
	for i := range ids {
		ids[i] = fmt.Sprint(i)
		owner[ids[i]] = nil
	}
	owner[ids[0]], owner[ids[63]] = []string{"same.example."}, []string{"same.example."}
	opt := RollingOptions{Dir: t.TempDir(), Owners: ids}
	m := rollingTestBuild(t, opt, maxMemory, owner)
	r := rollingTestOpen(t, opt, m)
	refresh := r.BeginRefresh(maxMemory, nil)
	first := rollingTestDiff(t, refresh, ids[0], nil)
	m = rollingTestApply(t, refresh, first)
	rollingTestClose(t, r)
	r = rollingTestOpen(t, opt, m)
	if r.OwnerMask([]byte("same.example.")) != 1<<63 || m.Count != 1 {
		t.Fatal("overlapping owner lost")
	}
	refresh = r.BeginRefresh(maxMemory, nil)
	last := rollingTestDiff(t, refresh, ids[63], nil)
	m = rollingTestApply(t, refresh, last)
	rollingTestClose(t, r)
	r = rollingTestOpen(t, opt, m)
	defer rollingTestClose(t, r)
	if r.OwnerMask([]byte("same.example.")) != 0 || m.Count != 0 {
		t.Fatal("last owner's name survived")
	}
}
func TestRollingRejectsCorruption(t *testing.T) {
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": {"base.example."}})
	r := rollingTestOpen(t, opt, m)
	populated := r.sliceFor(psnID([]byte("base.example.")))
	part, mask := r.catalog[populated].entry(0).names()
	refresh := r.BeginRefresh(maxMemory, nil)
	c := rollingTestDiff(t, refresh, "feed", []string{"base.example.", "zz-supplement.example."})
	next := rollingTestApply(t, refresh, c)
	rollingTestClose(t, r)
	swapped := m
	swapped.Slices = slices.Clone(m.Slices)
	other := (populated + 1) % rollingSlices
	a, b := &swapped.Slices[populated].Catalog, &swapped.Slices[other].Catalog
	*a, *b = *b, *a
	if view, err := OpenRolling(t.Context(), opt, swapped); !errors.Is(err, errRolling) {
		if view != nil {
			rollingTestClose(t, view)
		}
		t.Fatalf("expected rejection of a valid catalog assigned to the wrong slice, got %v", err)
	}
	for _, name := range []string{part, mask, m.Slices[1].Catalog.Name, next.Segments[0].Name} {
		t.Run(strings.Split(name, "-")[1], func(t *testing.T) {
			use := m
			if name == next.Segments[0].Name {
				use = next
			}
			path := filepath.Join(opt.Dir, name)
			data, err := os.ReadFile(path) //nolint:gosec // G304: test-owned artifact.
			if err != nil {
				t.Fatal(err)
			}
			broken := bytes.Clone(data)
			broken[len(broken)-1] ^= 1
			if err = os.WriteFile(path, broken, 0600); err != nil { //nolint:gosec // G703: test-owned artifact.
				t.Fatal(err)
			}
			if opened, err := OpenRolling(t.Context(), opt, use); err == nil {
				rollingTestClose(t, opened)
				t.Fatal("accepted corrupt file")
			}
			if err = os.WriteFile(path, data, 0600); err != nil { //nolint:gosec // G703: test-owned artifact.
				t.Fatal(err)
			}
			r := rollingTestOpen(t, opt, use)
			rollingTestClose(t, r)
		})
	}
	t.Run("FIFO", func(t *testing.T) {
		view := rollingTestOpen(t, opt, next)
		rollingTestClose(t, view)
		path := filepath.Join(opt.Dir, next.Segments[0].Name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			view, err := OpenRolling(t.Context(), opt, next)
			if view != nil {
				_ = view.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, errRolling) || !strings.Contains(err.Error(), "artifact "+filepath.Base(path)+" is not a regular file") {
				t.Fatalf("expected refusal of FIFO, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("opening a FIFO artifact blocked")
		}
	})
	t.Run("key digest", func(t *testing.T) {
		ref := &m.Slices[populated].Catalog
		path := filepath.Join(opt.Dir, ref.Name)
		data, err := os.ReadFile(path) //nolint:gosec // G304: test-owned artifact.
		if err != nil {
			t.Fatal(err)
		}
		record := data[rollingCatalogHeader:]
		meta := parseRollingPart(record)
		meta.keyDigest ^= 1
		meta.encode(record)
		rollingTestReplaceFile(t, opt.Dir, ref.Name, data)
		*ref = rollingReference(ref.Name, xxhash.Sum64(data))
		if opened, err := OpenRolling(t.Context(), opt, m); !errors.Is(err, errRolling) || !strings.Contains(err.Error(), "key digest mismatch") {
			if opened != nil {
				rollingTestClose(t, opened)
			}
			t.Fatalf("expected invalid key digest, got %v", err)
		}
	})
}

// Replace the pathname rather than writing through the MAP_SHARED inode.
// Rolling files are immutable once mapped.
func rollingTestReplaceFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, data, 0600); err != nil { //nolint:gosec // G703: test-owned artifact.
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
}
func TestRollingRejectsSegmentFilterOmittingDelete(t *testing.T) {
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	key := []byte("zz-delete.example.")
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": {string(key)}})
	m.Cursor = (testSliceFor(m, string(key)) + 1) % rollingSlices
	r := rollingTestOpen(t, opt, m)
	refresh := r.BeginRefresh(maxMemory, nil)
	c := rollingTestDiff(t, refresh, "feed", nil)
	next := rollingTestApply(t, refresh, c)
	rollingTestClose(t, r)
	r = rollingTestOpen(t, opt, next)
	if r.OwnerMask(key) != 0 || len(next.Segments) != 1 {
		t.Fatal("expected deletion in an unfolded segment")
	}
	rollingTestClose(t, r)

	ref := &next.Segments[0].rollingFile
	path := filepath.Join(opt.Dir, ref.Name)
	data, err := os.ReadFile(path) //nolint:gosec // G304: test-owned segment.
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the damaged segment so validation reaches the filter contents
	// instead of failing the outer file digest check.
	clear(data[len(data)-8:])                             // One Bloom word for the single tombstone.
	if err = os.WriteFile(path, data, 0600); err != nil { //nolint:gosec // G703: test-owned segment.
		t.Fatal(err)
	}
	*ref = rollingReference(ref.Name, xxhash.Sum64(data))
	if r, err = OpenRolling(t.Context(), opt, next); !errors.Is(err, errRolling) {
		if r != nil {
			rollingTestClose(t, r)
		}
		t.Fatalf("expected invalid filter, got %v", err)
	}
}

func TestRollingApplyUnlinksFullyFoldedSegment(t *testing.T) {
	const key = "new.example."
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": nil})
	// Visit the changed partition last with no budget for retained operations.
	m.Cursor = (testSliceFor(m, key) + 1) % len(m.Slices)
	r := rollingTestOpen(t, opt, m)
	defer rollingTestClose(t, r)
	refresh := r.BeginRefresh(1, nil)
	change := rollingTestDiff(t, refresh, "feed", []string{key})
	defer rollingTestClose(t, change)
	m, err := refresh.apply(t.Context(), []*RollingChange{change}, func(dir *os.File, names []string) error {
		for _, name := range names {
			if strings.HasPrefix(name, rollingSegmentPrefix) {
				t.Errorf("fully folded segment %s in the sync list", name)
			}
		}
		entries, err := os.ReadDir(dir.Name())
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), rollingSegmentPrefix) {
				t.Errorf("fully folded segment %s still present at sync", entry.Name())
			}
		}
		return rollingSyncFiles(dir, names)
	})
	if err != nil || len(m.Segments) != 0 || m.Count != 1 {
		t.Fatalf("fully folded Apply: count %d, %d segments, error %v", m.Count, len(m.Segments), err)
	}
}

func TestRollingSpillMatchesMemory(t *testing.T) {
	var base, next []string
	for i := range 80 {
		base = append(base, fmt.Sprintf("aa-%03d.example.", i))
		next = append(next, fmt.Sprintf("aa-%03d.example.", i+67))
	}
	for i := range 40 {
		next = append(next, next[i])
	}
	for _, budget := range []int64{maxMemory, 160} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
			m := rollingTestBuild(t, opt, budget, map[string][]string{"feed": base})
			r := rollingTestOpen(t, opt, m)
			writes := 0
			refresh := r.BeginRefresh(budget, func(_, _ uint64) error {
				writes++
				return nil
			})
			c := rollingTestDiff(t, refresh, "feed", next)
			if spilled, want := writes > 0, budget != maxMemory; spilled != want {
				t.Fatalf("diff admitted %d scratch writes; want spill: %t", writes, want)
			}
			if c.Adds != 67 || c.Removes != 67 {
				t.Fatalf("diff +%d -%d, want +67 -67", c.Adds, c.Removes)
			}
			m = rollingTestApply(t, refresh, c)
			if m.Count != 80 {
				t.Fatalf("manifest count = %d, want 80", m.Count)
			}
			rollingTestClose(t, r)
			r = rollingTestOpen(t, opt, m)
			defer rollingTestClose(t, r)
			for i := range 155 {
				if got, want := r.OwnerMask([]byte(fmt.Sprintf("aa-%03d.example.", i))) != 0, i >= 67 && i < 147; got != want {
					t.Fatalf("key %d: got %v want %v", i, got, want)
				}
			}
		})
	}
}

func TestRollingExactLookupAndAllocs(t *testing.T) {
	long := "zz" + strings.Repeat("x", MaxKey-3)
	keys := []string{"", "A", "a", "aa", "a\r", "a\x00", "a\x00a", "aabb.example.", "b.example.", long + "a", long + "b", "\xff"}
	slices.Sort(keys)
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed", "local"}}
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": keys, "local": {"a"}})
	r := rollingTestOpen(t, opt, m)
	for _, key := range append(slices.Clone(keys), "\x00", "aa.", "b", "z", long, long+"c", long+"aa") {
		b := []byte(key)
		var want uint64
		if slices.Contains(keys, key) {
			want = 1
		}
		if key == "a" {
			want |= 2
		}
		if got := r.OwnerMask(b); got != want {
			t.Fatalf("key len=%d got mask %b want %b", len(b), got, want)
		}
	}
	newKeys := []string{"", "b.example.", "other.example.", long + "b", long + "c"}
	refresh := r.BeginRefresh(maxMemory, nil)
	c := rollingTestDiff(t, refresh, "feed", newKeys)
	m = rollingTestApply(t, refresh, c)
	rollingTestClose(t, r)
	r = rollingTestOpen(t, opt, m)
	defer rollingTestClose(t, r)
	for _, tc := range []struct {
		key  string
		want uint64
	}{{"", 1}, {"a", 2}, {"b.example.", 1}, {"other.example.", 1}, {long + "a", 0}, {long + "b", 1}, {long + "c", 1}, {"does-not-exist.", 0}} {
		key := []byte(tc.key)
		if got := r.OwnerMask(key); got != tc.want {
			t.Fatalf("lookup len=%d got mask %b want %b", len(key), got, tc.want)
		}
		if n := testing.AllocsPerRun(100, func() { r.OwnerMask(key) }); n != 0 {
			t.Fatalf("lookup len=%d allocs %f", len(key), n)
		}
	}
}
func TestRollingParallelDiffCancelsOnRefusedWrite(t *testing.T) {
	old := runtime.GOMAXPROCS(maxRollingWorkers + 1)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })
	opt := RollingOptions{
		Dir: t.TempDir(), Owners: []string{"a"},
	}
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("%c%c-%04d.example.", 'a'+rune(i%8), 'a'+rune(i%16), i)
	}
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"a": keys})
	r := rollingTestOpen(t, opt, m)
	defer rollingTestClose(t, r)
	const refreshBudget = 224
	refused := errors.New("diff scratch write refused")
	attempts := 0
	refresh := r.BeginRefresh(refreshBudget, func(_, _ uint64) error {
		attempts++
		return refused
	})
	change, err := refresh.Diff(t.Context(), "a", strings.NewReader(""))
	if change != nil || !errors.Is(err, refused) || attempts != 1 {
		t.Fatalf("diff = %v, %v; attempts=%d", change, err, attempts)
	}
	scratch, err := filepath.Glob(filepath.Join(opt.Dir, rollingDiffPrefix+"*"))
	if err != nil || len(scratch) != 0 {
		t.Fatalf("failed diff retained scratch: %v (%v)", scratch, err)
	}
}

func TestRollingDiffCancelsDuringFinalJoin(t *testing.T) {
	const budget = 1 << 20
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	keys := make([]string, 4096)
	for i := range keys {
		keys[i] = fmt.Sprintf("aa-%04d.example.", i)
	}
	m := rollingTestBuild(t, opt, budget, map[string][]string{"feed": keys})
	r := rollingTestOpen(t, opt, m)
	defer rollingTestClose(t, r)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	visited := 0
	err := r.diffJoin(ctx, &rollingPartMerge{}, r.parts, &rollingKeySet{}, 1, nil, nil, true, nil, func([]byte) error {
		visited++
		if visited == 1 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || visited == 0 || visited > 1024 {
		t.Fatalf("final join = %v after %d of %d removals", err, visited, len(keys))
	}
}

func TestRollingApplyPreservesCurrentSnapshotOnFailure(t *testing.T) {
	const oldKey, newKey = "aa-old.example.", "aa-new.example."
	for _, failSync := range []bool{false, true} {
		name := "admission"
		if failSync {
			name = "sync"
		}
		t.Run(name, func(t *testing.T) {
			opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
			m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": {oldKey}})
			m.Cursor = testSliceFor(m, oldKey)
			r := rollingTestOpen(t, opt, m)
			keep := make(map[string]bool)
			r.Files(keep)
			failed := errors.New("injected apply failure")
			refresh := r.BeginRefresh(maxMemory, func(_, _ uint64) error {
				if failSync {
					return nil
				}
				entries, err := os.ReadDir(opt.Dir)
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if name := entry.Name(); IsArtifact(name) && !keep[name] {
						return failed
					}
				}
				return nil
			})
			change := rollingTestDiff(t, refresh, "feed", []string{newKey})
			var err error
			if failSync {
				_, err = refresh.apply(t.Context(), []*RollingChange{change}, func(_ *os.File, names []string) error {
					if len(names) == 0 {
						t.Error("data barrier ran without staged artifacts")
					}
					return failed
				})
			} else {
				_, err = refresh.Apply(t.Context(), []*RollingChange{change})
			}
			rollingTestClose(t, change)
			rollingTestClose(t, r)
			if !errors.Is(err, failed) {
				t.Fatalf("Apply error = %v, want %v", err, failed)
			}
			entries, err := os.ReadDir(opt.Dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !keep[entry.Name()] {
					t.Errorf("failed Apply left %s", entry.Name())
				}
			}
			r = rollingTestOpen(t, opt, m)
			defer rollingTestClose(t, r)
			if r.OwnerMask([]byte(oldKey)) == 0 || r.OwnerMask([]byte(newKey)) != 0 {
				t.Fatal("predecessor checkpoint changed after failed Apply")
			}
		})
	}
}

func TestRollingRejectsIncorrectManifestCount(t *testing.T) {
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	const oldKey, newKey = "zz-old.example.", "zz-new.example."
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": {oldKey}})
	m.Cursor = (testSliceFor(m, oldKey) + 1) % rollingSlices
	r := rollingTestOpen(t, opt, m)
	defer rollingTestClose(t, r)
	refresh := r.BeginRefresh(maxMemory, nil)
	change := rollingTestDiff(t, refresh, "feed", []string{newKey})
	m = rollingTestApply(t, refresh, change)
	m.Count = 2 // One base record plus a live replacement, not two live names.
	for name, open := range map[string]func() (*Rolling, error){
		"cold":   func() (*Rolling, error) { return OpenRolling(t.Context(), opt, m) },
		"reopen": func() (*Rolling, error) { return r.Reopen(t.Context(), m) },
	} {
		t.Run(name, func(t *testing.T) {
			opened, err := open()
			if opened != nil {
				rollingTestClose(t, opened)
			}
			if !errors.Is(err, errRolling) || !strings.Contains(err.Error(), "manifest count") {
				t.Fatalf("opening bad checkpoint = %v, want count mismatch", err)
			}
		})
	}
}

func TestRollingUpdateRejectsNewCorruptionAndSurvivesClosingPredecessor(t *testing.T) {
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	const base, added = "zz-base.example.", "zz-added.example."
	m := rollingTestBuild(t, opt, maxMemory, map[string][]string{"feed": {base}})
	baseSlice := testSliceFor(m, base)
	m.Cursor = (baseSlice + 1) % rollingSlices
	old := rollingTestOpen(t, opt, m)
	defer old.Close()
	refresh := old.BeginRefresh(maxMemory, nil)
	change := rollingTestDiff(t, refresh, "feed", []string{base, added})
	update, err := refresh.Apply(t.Context(), []*RollingChange{change})
	rollingTestClose(t, change)
	if err != nil {
		t.Fatal(err)
	}
	manifest := update.Manifest()
	name := manifest.Segments[0].Name
	good, err := os.ReadFile(filepath.Join(opt.Dir, name)) //nolint:gosec // G304: test-owned segment.
	if err != nil {
		t.Fatal(err)
	}
	rollingTestReplaceFile(t, opt.Dir, name, []byte("corrupt new segment"))
	if next, err := update.Open(t.Context()); !errors.Is(err, errRolling) {
		if next != nil {
			rollingTestClose(t, next)
		}
		t.Fatalf("Open accepted corrupt staged segment: %v", err)
	}
	if old.OwnerMask([]byte(base)) == 0 || old.OwnerMask([]byte(added)) != 0 {
		t.Fatal("staging or failed Open changed the predecessor")
	}
	rollingTestReplaceFile(t, opt.Dir, name, good)
	manifest.Count = 0
	manifest.Owners[0] = "different owner"
	manifest.Segments[0].Name = "different segment"
	next, err := update.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollingTestClose(t, next)
	rollingTestClose(t, old)
	if next.OwnerMask([]byte(base)) == 0 || next.OwnerMask([]byte(added)) == 0 {
		t.Fatal("closing predecessor changed the successor")
	}
}

func TestRollingInstallRefusesScratchWrite(t *testing.T) {
	refused := errors.New("install scratch write refused")
	opt := RollingOptions{
		Dir: t.TempDir(), Owners: []string{"feed", "later"},
		AdmitWrite: func(_, _ uint64) error { return refused },
	}
	openedLater := false
	owners := map[string]func() (io.ReadCloser, error){
		"feed": func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("example.\n")), nil },
		"later": func() (io.ReadCloser, error) {
			openedLater = true
			return nil, errors.New("later owner opened after scratch refusal")
		},
	}
	if _, err := BuildRolling(t.Context(), opt, maxMemory, owners, nil); !errors.Is(err, refused) {
		t.Fatalf("BuildRolling error = %v, want %v", err, refused)
	}
	if openedLater {
		t.Fatal("build opened the later owner after scratch refusal")
	}
	if entries, err := os.ReadDir(opt.Dir); err != nil || len(entries) != 0 {
		t.Fatalf("refused build left files: %v, %v", entries, err)
	}
}

func TestRollingRebuildAdvancesSequence(t *testing.T) {
	opt := RollingOptions{Dir: t.TempDir(), Owners: []string{"feed"}}
	m := RollingManifest{Sequence: 7}
	opens := 0
	owners := map[string]func() (io.ReadCloser, error){
		"feed": func() (io.ReadCloser, error) {
			opens++
			return io.NopCloser(strings.NewReader("example.\n")), nil
		},
	}
	next, err := BuildRolling(t.Context(), opt, maxMemory, owners, &m)
	if err != nil || next.Sequence != 8 || len(next.Segments) != 0 {
		t.Fatalf("rebuild = %+v, %v", next, err)
	}
	for _, s := range next.Slices {
		if s.FoldedThrough != next.Sequence {
			t.Fatalf("slice [%d,%d) folded through %d, want %d", s.Start, s.End, s.FoldedThrough, next.Sequence)
		}
	}
	m.Sequence = math.MaxUint64
	if _, err := BuildRolling(t.Context(), opt, maxMemory, owners, &m); !errors.Is(err, errRolling) || opens != 1 {
		t.Fatalf("exhausted rebuild = %v; input opens = %d", err, opens)
	}
}

func TestRollingInstallEmptyOwnersDoNotReduceRunAllowance(t *testing.T) {
	// At the minimum install budget, 6,000 distinct 128-byte keys fill
	// twelve runs. Counting all three owners would force a merge at ten.
	keys := make([]string, 6000)
	prefix := strings.Repeat("a", 124)
	for i := range keys {
		keys[i] = fmt.Sprintf("%s%04d", prefix, len(keys)-1-i)
	}
	install := func(order []string, owners map[string][]string, wantReduction bool) uint64 {
		var written uint64
		var atOpen [4]uint64
		opt := RollingOptions{Dir: t.TempDir(), Owners: order}
		opt.AdmitWrite = func(old, new uint64) error {
			written += new - old
			return nil
		}
		readers := make(map[string]func() (io.ReadCloser, error), len(order))
		for i, owner := range order {
			readers[owner] = func() (io.ReadCloser, error) {
				atOpen[i] = written
				return io.NopCloser(strings.NewReader(rollingTestInput(owners[owner]))), nil
			}
		}
		m, err := BuildRolling(t.Context(), opt, 32<<10, readers, nil)
		if err != nil {
			t.Fatal(err)
		}
		// The second and third owners each write one run of the same size.
		// Extra bytes after the third opener come from reducing earlier runs.
		if wantReduction {
			if got, ordinary := atOpen[3]-atOpen[2], atOpen[2]-atOpen[1]; got <= ordinary {
				t.Fatalf("third owner admitted %d bytes, want more than the second's %d", got, ordinary)
			}
		}
		r := rollingTestOpen(t, opt, m)
		defer rollingTestClose(t, r)
		masks := make(map[string]uint64, len(keys))
		for i, owner := range order {
			for _, key := range owners[owner] {
				masks[key] |= 1 << i
			}
		}
		if m.Count != len(masks) {
			t.Fatalf("install with %v: %d keys, want %d", order, m.Count, len(masks))
		}
		for key, want := range masks {
			if got := r.OwnerMask([]byte(key)); got != want {
				t.Fatalf("install with %v: mask for %q = %b, want %b", order, key, got, want)
			}
		}
		return written
	}
	want := install([]string{"feed"}, map[string][]string{"feed": keys}, false)
	if got := install([]string{"api-add", "feed", "api-remove"}, map[string][]string{
		"api-add": nil, "feed": keys, "api-remove": nil,
	}, false); got != want {
		t.Fatalf("install with empty owners writes %d admitted bytes, want %d", got, want)
	}
	// The third nonempty owner lowers the retained-run allowance to ten.
	install([]string{"feed", "tiny-a", "tiny-b", "tiny-c"}, map[string][]string{
		"feed": keys, "tiny-a": {"tiny-a.", keys[0]}, "tiny-b": {"tiny-b.", keys[1]}, "tiny-c": {"tiny-c.", keys[1]},
	}, true)
}

func testSliceFor(m RollingManifest, key string) int {
	id := uint32(psnID([]byte(key)))
	return slices.IndexFunc(m.Slices, func(s rollingSlice) bool { return id < s.End })
}
