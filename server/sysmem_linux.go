package server

import (
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// systemMemoryBytes is what the machine has.
func systemMemoryBytes() uint64 {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return 0
	}
	// Totalram is uint32 on 32-bit targets and uint64 on 64-bit ones, so
	// both operands are widened rather than assumed: this is the field
	// that has to compile for the ARM and MIPS builds as well. The
	// conversion is redundant only on the 64-bit target the linter reads
	// it on.
	return uint64(si.Totalram) * uint64(si.Unit) //nolint:unconvert // required on 32-bit targets
}

// containerMemoryLimit is what this process is actually allowed to use,
// which on a container host — or under systemd, which is the same
// mechanism — is the only number that matters: the machine may have 64GB
// and this unit 128MB of it.
//
// The limit is not a fixed file. It belongs to the cgroup this process is
// in, so that cgroup has to be found (/proc/self/cgroup), located under
// its mount (/proc/self/mountinfo), and then read together with its
// ancestors: a limit set on a parent slice binds this process just as
// tightly as one set on its own leaf, and the smallest of them is what
// the kernel enforces. Reading only the mount root — which is what a
// container sees, but not what a systemd unit does — misses exactly the
// case that matters, and a process that misses its limit derives its
// bounds from the host's memory and gets killed for it.
//
// Zero means nothing said so, not "no memory".
func containerMemoryLimit() uint64 {
	v2Mount, v1Mount := cgroupMounts()
	v2Path, v1Path := cgroupPaths()
	return cgroupMemoryLimit(v2Mount, v2Path, v1Mount, v1Path)
}

// cgroupMount is one hierarchy as this process can reach it: where it is
// visible, and which part of the hierarchy that mount exposes. The second
// half is not decoration — a delegated or bind-mounted cgroup shows a
// subtree, so a path read from /proc/self/cgroup is written in the
// hierarchy's terms and has to be translated into the mount's before it
// names a directory that exists.
type cgroupMount struct {
	point string
	root  string
}

// cgroupMemoryLimit is containerMemoryLimit with the lookup already done,
// so the walk can be checked against a hierarchy built for the purpose.
func cgroupMemoryLimit(v2 cgroupMount, v2Path string, v1 cgroupMount, v1Path string) uint64 {
	var limit uint64
	narrow := func(v uint64) {
		if v > 0 && (limit == 0 || v < limit) {
			limit = v
		}
	}

	// v2: memory.max, from this cgroup up to the mount root.
	if v2.point != "" {
		for _, dir := range ancestors(v2.point, cgroupRelPath(v2, v2Path)) {
			narrow(readMemoryLimit(path.Join(dir, "memory.max")))
		}
	}
	// v1: memory.limit_in_bytes, same walk.
	if v1.point != "" {
		for _, dir := range ancestors(v1.point, cgroupRelPath(v1, v1Path)) {
			narrow(readMemoryLimit(path.Join(dir, "memory.limit_in_bytes")))
		}
	}
	return limit
}

// cgroupRelPath translates a hierarchy path into a path under the mount
// that exposes it.
//
// A mount rooted at "/" shows the whole hierarchy and the two are the
// same. A mount rooted at a subtree shows only what is below it, so the
// root prefix has to come off — appending the full path there would name
// a directory that does not exist, the limit would read as absent, and
// the bounds would come from the host's memory inside a service that
// cannot have it.
//
// A path outside what this mount exposes cannot be reached at all: that
// is a cgroup namespace describing itself in terms this mount does not
// share, and the mount point is then the closest thing to the process's
// own cgroup that is actually readable.
func cgroupRelPath(m cgroupMount, cgroupPath string) string {
	root := path.Clean("/" + m.root)
	full := path.Clean("/" + cgroupPath)
	switch {
	case root == "/":
		return full
	case full == root:
		return "/"
	case strings.HasPrefix(full, root+"/"):
		return strings.TrimPrefix(full, root)
	default:
		return "/"
	}
}

// cgroupMounts returns where the v2 hierarchy and the v1 memory
// controller are mounted, and which part of each this process sees.
func cgroupMounts() (v2, v1 cgroupMount) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return cgroupMount{}, cgroupMount{}
	}
	return parseCgroupMounts(string(data))
}

func parseCgroupMounts(mountinfo string) (v2, v1 cgroupMount) {
	for line := range strings.SplitSeq(mountinfo, "\n") {
		// id parent major:minor <root> <mount point> options... - <fstype> <source> <super options>
		//                        (4)      (5)
		// The root and the mount point are different questions: the first
		// is which part of the filesystem this mount exposes, the second
		// is where it appears. A cgroup mount is regularly rooted at a
		// subtree, and then only their difference names a directory.
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		fields := strings.Fields(line[:sep])
		rest := strings.Fields(line[sep+3:])
		if len(fields) < 5 || len(rest) < 3 {
			continue
		}
		mount := cgroupMount{point: fields[4], root: fields[3]}
		switch rest[0] {
		case "cgroup2":
			if v2.point == "" {
				v2 = mount
			}
		case "cgroup":
			if v1.point == "" && hasOption(rest[2], "memory") {
				v1 = mount
			}
		}
	}
	return v2, v1
}

func hasOption(options, want string) bool {
	for opt := range strings.SplitSeq(options, ",") {
		if opt == want {
			return true
		}
	}
	return false
}

// cgroupPaths returns this process's cgroup path in the v2 hierarchy and
// in the v1 memory controller.
func cgroupPaths() (v2, v1 string) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", ""
	}
	return parseCgroupPaths(string(data))
}

func parseCgroupPaths(procCgroup string) (v2, v1 string) {
	for line := range strings.SplitSeq(procCgroup, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[1] == "":
			v2 = parts[2] // "0::/path" is the unified hierarchy
		case hasOption(parts[1], "memory"):
			v1 = parts[2]
		}
	}
	return v2, v1
}

// ancestors lists mount/rel and every directory above it, up to the
// mount itself: the kernel enforces the smallest limit on the way up, so
// every level has to be read.
func ancestors(mount, rel string) []string {
	rel = path.Clean("/" + rel)
	dirs := []string{mount}
	if rel == "/" {
		return dirs
	}
	current := mount
	for _, element := range strings.Split(strings.TrimPrefix(rel, "/"), "/") {
		if element == "" {
			continue
		}
		current = path.Join(current, element)
		dirs = append(dirs, current)
	}
	return dirs
}

// readMemoryLimit reads one cgroup limit file. Zero means no limit here:
// the file is missing (this level does not constrain memory), says "max",
// or carries the sentinel v1 uses to spell "unlimited" as a number.
func readMemoryLimit(file string) uint64 {
	data, err := os.ReadFile(file) //nolint:gosec // a kernel file under a mount the kernel named; the path is computed because the cgroup is
	if err != nil {
		return 0
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return 0
	}
	limit, err := strconv.ParseUint(value, 10, 64)
	if err != nil || limit > 1<<62 {
		return 0
	}
	return limit
}
