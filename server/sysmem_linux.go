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
//
// Every mount of a hierarchy is a candidate, not just the first one seen.
// A machine regularly has several views of the same cgroups — a bind
// mount, a container's own view, a namespace's — and only some of them
// expose the subtree this process is in. Stopping at the first one and
// falling back to its root when it does not match is how a process reads
// a loose limit from a mount that does not describe it while the mount
// that does sits further down the list.
func cgroupMemoryLimit(v2Mounts []cgroupMount, v2Path string, v1Mounts []cgroupMount, v1Path string) uint64 {
	var limit uint64
	narrow := func(v uint64) {
		if v > 0 && (limit == 0 || v < limit) {
			limit = v
		}
	}

	walk := func(mounts []cgroupMount, cgroupPath, file string) {
		// A mount that actually exposes this process's cgroup answers the
		// question; one that does not can only be read at its root, which
		// is a guess. So the guesses are used only when nothing maps.
		mapped := false
		for _, m := range mounts {
			if _, ok := cgroupRelPath(m, cgroupPath); ok {
				mapped = true
				break
			}
		}
		for _, m := range mounts {
			rel, ok := cgroupRelPath(m, cgroupPath)
			if mapped && !ok {
				continue
			}
			for _, dir := range ancestors(m.point, rel) {
				narrow(readMemoryLimit(path.Join(dir, file)))
			}
		}
	}

	walk(v2Mounts, v2Path, "memory.max")
	walk(v1Mounts, v1Path, "memory.limit_in_bytes")
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
// The second return says whether the mount exposes this path at all. A
// path outside it cannot be reached here: that is a cgroup namespace
// describing itself in terms this mount does not share. The mount point
// is still returned, because with no better mount anywhere it is the
// closest readable thing — but the caller prefers a mount that maps.
func cgroupRelPath(m cgroupMount, cgroupPath string) (string, bool) {
	// A path that climbs is a namespace naming a cgroup above its own
	// root — outside anything a mount in this namespace exposes. Clean
	// would silently rewrite it into a sibling that exists but is not
	// this process, and the sibling's limit is not ours to read.
	if hasDotDot(cgroupPath) {
		return "/", false
	}
	root := path.Clean("/" + m.root)
	full := path.Clean("/" + cgroupPath)
	switch {
	case root == "/":
		return full, true
	case full == root:
		return "/", true
	case strings.HasPrefix(full, root+"/"):
		return strings.TrimPrefix(full, root), true
	default:
		return "/", false
	}
}

// cgroupMounts returns where the v2 hierarchy and the v1 memory
// controller are mounted, and which part of each this process sees.
func cgroupMounts() (v2, v1 []cgroupMount) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, nil
	}
	return parseCgroupMounts(string(data))
}

func parseCgroupMounts(mountinfo string) (v2, v1 []cgroupMount) {
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
		mount := cgroupMount{
			point: unescapeMountField(fields[4]),
			root:  unescapeMountField(fields[3]),
		}
		switch rest[0] {
		case "cgroup2":
			v2 = append(v2, mount)
		case "cgroup":
			if hasOption(rest[2], "memory") {
				v1 = append(v1, mount)
			}
		}
	}
	return v2, v1
}

func hasDotDot(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// unescapeMountField decodes the octal escapes mountinfo uses for the
// characters that would break its whitespace-separated format: \040
// space, \011 tab, \012 newline, \134 backslash. A mount path with a
// space in it is otherwise read with the escape still inside — it names
// no directory, the limit reads as absent, and the bounds fall back to
// the host's memory.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			d0, d1, d2 := s[i+1], s[i+2], s[i+3]
			if d0 >= '0' && d0 <= '3' && d1 >= '0' && d1 <= '7' && d2 >= '0' && d2 <= '7' {
				b.WriteByte((d0-'0')<<6 | (d1-'0')<<3 | (d2 - '0'))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
