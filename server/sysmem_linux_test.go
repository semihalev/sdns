package server

import (
	"os"
	"path/filepath"
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
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := cgroupMemoryLimit(mount, tc.cgroup, "", ""); got != tc.want {
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"), []byte("134217728\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cgroupMemoryLimit("", "", mount, "/docker/abc123"); got != 128<<20 {
		t.Fatalf("v1 limit = %d, want %d", got, 128<<20)
	}

	if err := os.WriteFile(filepath.Join(dir, "memory.limit_in_bytes"),
		[]byte("9223372036854771712\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cgroupMemoryLimit("", "", mount, "/docker/abc123"); got != 0 {
		t.Fatalf("the v1 unlimited sentinel was read as a %d byte limit", got)
	}
}

func TestParseCgroupMountsAndPaths(t *testing.T) {
	mountinfo := `25 30 0:22 / /proc rw,nosuid - proc proc rw
31 25 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw,nsdelegate
32 25 0:27 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory
33 25 0:28 / /sys/fs/cgroup/cpu rw,nosuid - cgroup cgroup rw,cpu,cpuacct`
	v2, v1 := parseCgroupMounts(mountinfo)
	if v2 != "/sys/fs/cgroup" {
		t.Fatalf("v2 mount = %q", v2)
	}
	if v1 != "/sys/fs/cgroup/memory" {
		t.Fatalf("v1 memory mount = %q", v1)
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
