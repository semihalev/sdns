package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A systemd unit is the case the first version missed: the limit is not
// on the mount root, it is on the slice this process was placed in, or
// on one of the slices above it. Missing it means deriving the ingress
// bounds from the host's memory inside a service that may have a
// fraction of it — which is an out-of-memory kill, not a slow server.
func TestCgroupLimitFoundOnThisProcessCgroup(t *testing.T) {
	const (
		mib     = 1 << 20
		leaf    = "/system.slice/sdns.service"
		unified = ""
	)

	cases := []struct {
		name   string
		files  map[string]string // path under the mount -> contents
		cgroup string
		want   uint64
	}{
		{
			name:   "limit on the unit itself",
			files:  map[string]string{"system.slice/sdns.service/memory.max": "134217728"},
			cgroup: leaf,
			want:   128 * mib,
		},
		{
			name:   "limit on a parent slice binds too",
			files:  map[string]string{"system.slice/memory.max": "268435456"},
			cgroup: leaf,
			want:   256 * mib,
		},
		{
			name: "the tightest ancestor wins",
			files: map[string]string{
				"memory.max":                            "1073741824",
				"system.slice/memory.max":               "268435456",
				"system.slice/sdns.service/memory.max":  "134217728",
				"system.slice/sdns.service/memory.high": "1024",
			},
			cgroup: leaf,
			want:   128 * mib,
		},
		{
			name: "a looser leaf does not widen a tighter parent",
			files: map[string]string{
				"system.slice/memory.max":              "134217728",
				"system.slice/sdns.service/memory.max": "1073741824",
			},
			cgroup: leaf,
			want:   128 * mib,
		},
		{
			name:   "max means no limit",
			files:  map[string]string{"system.slice/sdns.service/memory.max": "max"},
			cgroup: leaf,
			want:   0,
		},
		{
			name:   "no files at all",
			files:  nil,
			cgroup: leaf,
			want:   0,
		},
		{
			name:   "container at the mount root",
			files:  map[string]string{"memory.max": "134217728"},
			cgroup: unified,
			want:   128 * mib,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mount := t.TempDir()
			for name, content := range tc.files {
				full := filepath.Join(mount, name)
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := cgroupMemoryLimit([]cgroupMount{{point: mount, root: "/"}}, tc.cgroup, nil, ""); got != tc.want {
				t.Fatalf("v2 limit = %d, want %d", got, tc.want)
			}
		})
	}
}

// The v1 hierarchy spells the same thing differently, including
// "unlimited" as a number so large it is really a sentinel.
func TestCgroupV1Limit(t *testing.T) {
	mount := t.TempDir()
	dir := filepath.Join(mount, "docker", "abc123")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v1 := []cgroupMount{{point: mount, root: "/"}}
	if got := cgroupMemoryLimit(nil, "", v1, "/docker/abc123"); got != 128<<20 {
		t.Fatalf("v1 limit = %d, want %d", got, 128<<20)
	}

	if err := os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"),
		[]byte("9223372036854771712\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cgroupMemoryLimit(nil, "", v1, "/docker/abc123"); got != 0 {
		t.Fatalf("the v1 unlimited sentinel was read as a %d byte limit", got)
	}
}

func TestParseCgroupMountsAndPaths(t *testing.T) {
	mountinfo := `25 30 0:22 / /proc rw,nosuid - proc proc rw
31 25 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw,nsdelegate
32 25 0:27 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory
33 25 0:28 / /sys/fs/cgroup/cpu rw,nosuid - cgroup cgroup rw,cpu,cpuacct`
	v2, v1 := parseCgroupMounts(mountinfo)
	if len(v2) != 1 || v2[0].point != "/sys/fs/cgroup" || v2[0].root != "/" {
		t.Fatalf("v2 mounts = %+v", v2)
	}
	if len(v1) != 1 || v1[0].point != "/sys/fs/cgroup/memory" || v1[0].root != "/" {
		t.Fatalf("v1 memory mounts = %+v", v1)
	}

	procCgroup := `12:cpu,cpuacct:/system.slice/sdns.service
5:memory:/system.slice/sdns.service
0::/system.slice/sdns.service`
	p2, p1 := parseCgroupPaths(procCgroup)
	if p2 != "/system.slice/sdns.service" || p1 != "/system.slice/sdns.service" {
		t.Fatalf("cgroup paths = %q / %q", p2, p1)
	}
}

// Whatever this machine is, reading its own cgroup must not report a
// limit smaller than a server could run in — a parsing slip there would
// shrink the ingress bounds silently.
func TestThisProcessCgroupLimitIsSane(t *testing.T) {
	limit := containerMemoryLimit()
	t.Logf("cgroup limit for this process: %d bytes", limit)
	if limit != 0 && limit < 8<<20 {
		t.Fatalf("read a %d byte limit for this process, which cannot be right", limit)
	}
}

// A cgroup mount does not have to expose the whole hierarchy. Delegated
// and bind-mounted setups show a subtree, and then the path in
// /proc/self/cgroup is written in the hierarchy's terms while the
// directory that exists is written in the mount's. Appending the first
// to the second names nothing, the limit reads as absent, and the server
// sizes itself for the host's memory inside a service that cannot have
// it — the exact failure this file is here to prevent.
func TestCgroupLimitUnderASubtreeRootedMount(t *testing.T) {
	mount := t.TempDir()
	// The mount exposes /system.slice, so this process's cgroup —
	// /system.slice/sdns.service — is simply "sdns.service" here.
	dir := filepath.Join(mount, "sdns.service")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A limit on the exposed root binds as well, and is looser here, so
	// the leaf's has to win.
	if err := os.WriteFile(filepath.Join(mount, "memory.max"), []byte("1073741824\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	v2 := []cgroupMount{{point: mount, root: "/system.slice"}}
	if got := cgroupMemoryLimit(v2, "/system.slice/sdns.service", nil, ""); got != 128<<20 {
		t.Fatalf("limit = %d, want %d; the mount's root prefix has to come off "+
			"the cgroup path before it names a directory", got, 128<<20)
	}
}

// A path outside what the mount exposes cannot be read at all — a
// namespace describing itself in terms this mount does not share. The
// mount point is then the closest readable thing, and its limit still
// binds.
func TestCgroupPathOutsideTheMountFallsBackToItsRoot(t *testing.T) {
	mount := t.TempDir()
	if err := os.WriteFile(filepath.Join(mount, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v2 := []cgroupMount{{point: mount, root: "/system.slice"}}
	if got := cgroupMemoryLimit(v2, "/user.slice/session-3.scope", nil, ""); got != 128<<20 {
		t.Fatalf("limit = %d, want the mount root's %d", got, 128<<20)
	}
}

func TestCgroupRelPath(t *testing.T) {
	cases := []struct{ root, cgroup, want string }{
		{"/", "/system.slice/sdns.service", "/system.slice/sdns.service"},
		{"/", "/", "/"},
		{"/system.slice", "/system.slice/sdns.service", "/sdns.service"},
		{"/system.slice", "/system.slice", "/"},
		{"/system.slice", "/user.slice/other", "/"},
		{"/kubepods/burstable/podabc", "/kubepods/burstable/podabc/container1", "/container1"},
		{"", "/system.slice", "/system.slice"},
	}
	for _, tc := range cases {
		got, _ := cgroupRelPath(cgroupMount{point: "/mnt", root: tc.root}, tc.cgroup)
		if got != tc.want {
			t.Fatalf("cgroupRelPath(root=%q, cgroup=%q) = %q, want %q",
				tc.root, tc.cgroup, got, tc.want)
		}
	}
}

// mountinfo carries the root and the mount point in separate fields, and
// a subtree-rooted mount is exactly where confusing them shows.
func TestParseCgroupMountsKeepsTheFilesystemRoot(t *testing.T) {
	mountinfo := `31 25 0:26 /system.slice /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw,nsdelegate
32 25 0:27 /docker/abc /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory`
	v2, v1 := parseCgroupMounts(mountinfo)
	if len(v2) != 1 || v2[0].point != "/sys/fs/cgroup" || v2[0].root != "/system.slice" {
		t.Fatalf("v2 mounts = %+v", v2)
	}
	if len(v1) != 1 || v1[0].point != "/sys/fs/cgroup/memory" || v1[0].root != "/docker/abc" {
		t.Fatalf("v1 mounts = %+v", v1)
	}
}

// A machine can show the same cgroups through more than one mount — a
// bind mount, a container's own view, a namespace's — and only some of
// them expose the subtree this process is in.
func TestCgroupLimitPrefersTheMountThatMapsThisProcess(t *testing.T) {
	// Stopping at the first mount is the failure: it does not describe
	// this process and says nothing about a limit, so the answer becomes
	// "no limit" and the bounds come from the host's memory — while the
	// mount that does describe us, and carries the real limit, is one
	// line further down.
	t.Run("a mount that says nothing must not end the search", func(t *testing.T) {
		silent := t.TempDir()
		if err := os.WriteFile(filepath.Join(silent, "memory.max"), []byte("max\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ours := t.TempDir()
		leaf := filepath.Join(ours, "sdns.service")
		if err := os.MkdirAll(leaf, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mounts := []cgroupMount{
			{point: silent, root: "/user.slice"},
			{point: ours, root: "/system.slice"},
		}
		if got := cgroupMemoryLimit(mounts, "/system.slice/sdns.service", nil, ""); got != 128<<20 {
			t.Fatalf("limit = %d, want %d", got, 128<<20)
		}
	})

	// And a limit belonging to somebody else is not ours to adopt: a
	// mount that does not expose our cgroup can only be read at its root,
	// which describes a different process. Reading it would shrink this
	// server for a limit it is not under.
	t.Run("a stranger's tighter limit is not ours", func(t *testing.T) {
		stranger := t.TempDir()
		if err := os.WriteFile(filepath.Join(stranger, "memory.max"), []byte("67108864\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ours := t.TempDir()
		leaf := filepath.Join(ours, "sdns.service")
		if err := os.MkdirAll(leaf, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mounts := []cgroupMount{
			{point: stranger, root: "/user.slice"},
			{point: ours, root: "/system.slice"},
		}
		if got := cgroupMemoryLimit(mounts, "/system.slice/sdns.service", nil, ""); got != 128<<20 {
			t.Fatalf("limit = %d, want our own %d", got, 128<<20)
		}
	})
}

// With nothing that maps, the roots are all there is — a namespace whose
// paths this mount does not share still has a limit, and reading it is
// better than deriving bounds from the host's memory.
func TestCgroupLimitFallsBackWhenNoMountMaps(t *testing.T) {
	mount := t.TempDir()
	if err := os.WriteFile(filepath.Join(mount, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mounts := []cgroupMount{{point: mount, root: "/user.slice"}}
	if got := cgroupMemoryLimit(mounts, "/system.slice/sdns.service", nil, ""); got != 128<<20 {
		t.Fatalf("limit = %d, want the mount root's %d", got, 128<<20)
	}
}

// Several views that all map are all read, and the tightest wins —
// they describe the same cgroups, so a disagreement means one of them
// carries a limit the others do not show.
func TestCgroupLimitTakesTheTightestMappingMount(t *testing.T) {
	loose := t.TempDir()
	if err := os.WriteFile(filepath.Join(loose, "memory.max"), []byte("1073741824\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tight := t.TempDir()
	if err := os.WriteFile(filepath.Join(tight, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mounts := []cgroupMount{
		{point: loose, root: "/system.slice/sdns.service"},
		{point: tight, root: "/system.slice/sdns.service"},
	}
	if got := cgroupMemoryLimit(mounts, "/system.slice/sdns.service", nil, ""); got != 128<<20 {
		t.Fatalf("limit = %d, want the tightest %d", got, 128<<20)
	}
}

func TestParseCgroupMountsKeepsEveryCandidate(t *testing.T) {
	mountinfo := `31 25 0:26 /user.slice /sys/fs/cgroup rw - cgroup2 cgroup2 rw
40 25 0:26 /system.slice /run/host/cgroup rw - cgroup2 cgroup2 rw
32 25 0:27 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
33 25 0:28 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu`
	v2, v1 := parseCgroupMounts(mountinfo)
	if len(v2) != 2 {
		t.Fatalf("v2 mounts = %+v, want both cgroup2 views", v2)
	}
	if v2[1].point != "/run/host/cgroup" || v2[1].root != "/system.slice" {
		t.Fatalf("second v2 mount = %+v", v2[1])
	}
	if len(v1) != 1 || v1[0].point != "/sys/fs/cgroup/memory" {
		t.Fatalf("v1 mounts = %+v, want only the memory controller", v1)
	}
}

// mountinfo escapes the characters that would break its whitespace-
// separated format. A mount path with a space in it must come out with
// the space, not with the escape — an escaped path names no directory,
// so the limit reads as absent and the bounds fall back to host memory.
func TestParseCgroupMountsDecodesEscapedPaths(t *testing.T) {
	mountinfo := `31 25 0:26 /pod\040a /run/host\011cg rw - cgroup2 cgroup2 rw
32 25 0:27 /back\134slash /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory`
	v2, v1 := parseCgroupMounts(mountinfo)
	if len(v2) != 1 || v2[0].root != "/pod a" || v2[0].point != "/run/host\tcg" {
		t.Fatalf("v2 = %+v", v2)
	}
	if len(v1) != 1 || v1[0].root != `/back\slash` {
		t.Fatalf("v1 = %+v", v1)
	}
}

// The same, end to end: a mount point containing a space, spelled the
// way mountinfo spells it, still yields the real limit.
func TestCgroupLimitWithASpaceInTheMountPath(t *testing.T) {
	mount := filepath.Join(t.TempDir(), "cg dir")
	leaf := filepath.Join(mount, "sdns.service")
	if err := os.MkdirAll(leaf, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("31 25 0:26 / %s rw - cgroup2 cgroup2 rw",
		strings.ReplaceAll(mount, " ", `\040`))
	v2, _ := parseCgroupMounts(line)
	if got := cgroupMemoryLimit(v2, "/sdns.service", nil, ""); got != 128<<20 {
		t.Fatalf("limit = %d, want %d; the escaped mount path has to be "+
			"decoded before it names a directory", got, 128<<20)
	}
}

// A namespace can name this process's cgroup above its own root —
// "/../something". Clean would rewrite that into a sibling that exists
// but is not this process; its limit is not ours, in either direction.
// Unmappable means the root fallback, which at least belongs to the
// right hierarchy.
func TestCgroupPathThatClimbsIsNotMapped(t *testing.T) {
	mount := t.TempDir()
	if err := os.WriteFile(filepath.Join(mount, "memory.max"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The sibling Clean would fabricate, carrying a limit that is not ours.
	sibling := filepath.Join(mount, "other")
	if err := os.MkdirAll(sibling, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "memory.max"), []byte("67108864\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if rel, ok := cgroupRelPath(cgroupMount{point: mount, root: "/"}, "/../other"); ok {
		t.Fatalf("a climbing path mapped to %q; it names nothing this mount exposes", rel)
	}
	mounts := []cgroupMount{{point: mount, root: "/"}}
	if got := cgroupMemoryLimit(mounts, "/../other", nil, ""); got != 128<<20 {
		t.Fatalf("limit = %d, want the mount root's %d, not the fabricated sibling's", got, 128<<20)
	}
}
