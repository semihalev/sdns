//go:build linux

package blocklist

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semihalev/sdns/internal/compactset"
)

func TestCompactRollingCgroupMount(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(dir, "cgroup mount")
	child := filepath.Join(mount, "workers")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	mountinfo := filepath.Join(dir, "mountinfo")
	cgroup := filepath.Join(dir, "cgroup")
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(id, root, point, fs string) string {
		escape := func(s string) string { return strings.ReplaceAll(s, " ", `\040`) }
		return id + " 25 0:26 " + escape(root) + " " + escape(point) + " rw shared:1 - " + fs + " none rw\n"
	}
	inheritedEntry := entry("31", "/..", mount, "cgroup2")
	namespaceEntry := entry("32", "/", mount, "cgroup2")
	subtreeEntry := entry("33", "/services/sdns instance", mount, "cgroup2")
	nonV2Entry := entry("34", "/", mount, "tmpfs")
	write(filepath.Join(mount, "memory.max"), "100\n")
	write(filepath.Join(mount, "memory.current"), "30\n")
	write(filepath.Join(child, "memory.max"), "160\n")
	write(filepath.Join(child, "memory.current"), "60\n")
	const unicodeRoot = "/services/sdns\u00a0instance\u2003group"
	for _, tc := range []struct {
		name, mounts, process, wantError string
		want                             uint64
		id                               uint64
	}{
		{name: "absent mount", mounts: entry("35", "/", mount+"-other", "cgroup2"), want: math.MaxUint64},
		{name: "non-v2 mount", mounts: nonV2Entry, want: math.MaxUint64},
		{name: "inherited root", mounts: inheritedEntry, process: "/", wantError: "mount cgroup2 from this cgroup namespace"},
		{name: "namespace root", mounts: namespaceEntry, process: "/", want: 70},
		{name: "overmount replaces inherited root", mounts: inheritedEntry + namespaceEntry, process: "/", want: 70},
		{name: "overmount hides v2 mount", mounts: namespaceEntry + nonV2Entry, want: math.MaxUint64},
		{name: "visible mount listed first", mounts: namespaceEntry + inheritedEntry, process: "/", id: 32, want: 70},
		{name: "visible mount listed last", mounts: inheritedEntry + namespaceEntry, process: "/", id: 32, want: 70},
		{name: "visible non-v2 mount listed first", mounts: nonV2Entry + namespaceEntry, id: 34, want: math.MaxUint64},
		{name: "subtree root", mounts: subtreeEntry, process: "/services/sdns instance", want: 70},
		{name: "subtree mount ID with a different mountpoint", mounts: entry("37", "/services/sdns", child, "cgroup2"), process: "/services/sdns", id: 37, want: 100},
		{name: "unicode whitespace in root", mounts: entry("36", unicodeRoot, mount, "cgroup2"), process: unicodeRoot + "/workers", want: 70},
		{name: "ancestor limit", mounts: subtreeEntry, process: "/services/sdns instance/workers", want: 70},
		{name: "outside subtree", mounts: subtreeEntry, process: "/services/sdns instance2", wantError: "mount cgroup2 from this cgroup namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(mountinfo, tc.mounts)
			write(cgroup, "0::"+tc.process+"\n")
			got, err := compactRollingCgroupAvailableAt(mount, mountinfo, cgroup, tc.id)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("available = %d, error = %v; want %q", got, err, tc.wantError)
				}
			} else if got != tc.want || err != nil {
				t.Fatalf("available = %d, error = %v; want %d", got, err, tc.want)
			}
		})
	}
	alias := filepath.Join(dir, "cgroup alias")
	if err := os.Symlink(mount, alias); err != nil {
		t.Fatal(err)
	}
	write(mountinfo, namespaceEntry)
	write(cgroup, "0::/workers\n")
	if got, err := compactRollingCgroupAvailableAt(alias, mountinfo, cgroup, 0); got != 70 || err != nil {
		t.Fatalf("aliased mount: available = %d, error = %v; want 70", got, err)
	}
	if err := os.Remove(filepath.Join(mount, "memory.current")); err != nil {
		t.Fatal(err)
	}
	write(mountinfo, namespaceEntry)
	write(cgroup, "0::/\n")
	if _, err := compactRollingCgroupAvailableAt(mount, mountinfo, cgroup, 32); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing memory.current: got %v; want os.ErrNotExist", err)
	}
}

func TestCompactRollingCgroupMissingMountpoint(t *testing.T) {
	dir := t.TempDir()
	got, err := compactRollingCgroupAvailableAt(filepath.Join(dir, "missing"), filepath.Join(dir, "mountinfo"), filepath.Join(dir, "cgroup"), 0)
	if got != math.MaxUint64 || err != nil {
		t.Fatalf("absent cgroup mount: available = %d, error = %v", got, err)
	}
}

func TestCompactRestartAdmissionCountsVerificationScratch(t *testing.T) {
	const names = 2_700_000
	m := &compactset.RollingManifest{Count: names}
	if err := json.Unmarshal([]byte(`{"segments":[{"count":2048},{"count":0},{"count":4096}]}`), m); err != nil {
		t.Fatal(err)
	}
	const needed uint64 = 2<<20 + names + 6144 + 2*3*65_535
	budget := needed - 1
	c := compactManager{
		admissionObserver: compactAdmissionObserver{memory: func() (uint64, error) { return budget, nil }},
		manifest:          compactManifest{Rolling: m},
	}
	if _, _, err := c.admitRolling(admitRestart, "restart"); !errors.Is(err, errRollingRAM) {
		t.Fatalf("accepted restart without count-verification scratch: %v", err)
	}
	budget++
	if _, _, err := c.admitRolling(admitRestart, "restart"); err != nil {
		t.Fatalf("refused restart with sufficient scratch: %v", err)
	}
}
