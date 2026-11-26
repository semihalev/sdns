package blocklist

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func init() {
	compactAvailableMemory = linuxCompactAvailableMemory
	compactPolicyBlockSize = linuxCompactPolicyBlockSize
}

func linuxCompactAvailableMemory() (uint64, error) {
	host, err := compactHostAvailableMemory()
	if err != nil {
		return 0, err
	}
	const mount = "/sys/fs/cgroup"
	id, _ := compactMountID(mount)
	group, err := compactRollingCgroupAvailableAt(mount, "/proc/self/mountinfo", "/proc/self/cgroup", id)
	return min(host, group), err
}

// compactMountID returns zero when fdinfo does not contain a mount ID.
func compactMountID(path string) (uint64, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd)) //nolint:gosec // fd is assigned by the kernel
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		}
	}
	return 0, nil
}

func compactRollingCgroupAvailableAt(mount, mountinfo, cgroup string, id uint64) (uint64, error) {
	mount, err := filepath.EvalSymlinks(mount)
	if os.IsNotExist(err) {
		return math.MaxUint64, nil
	}
	if err != nil {
		return 0, err
	}
	root, mount, err := compactCgroupMountRoot(mount, mountinfo, id)
	if err != nil {
		return 0, err
	}
	if root == "" {
		return math.MaxUint64, nil
	}
	const remount = "mount cgroup2 from this cgroup namespace"
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		// An inherited root such as /.. has no mapping to the process
		// path. Cleaning it would read the wrong group's limits.
		return 0, fmt.Errorf("cannot map cgroup v2 mount root %q; %s", root, remount)
	}
	data, err := os.ReadFile(cgroup) //nolint:gosec // fixed procfs path outside tests
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return 0, fmt.Errorf("cannot map process cgroup path %q; %s", path, remount)
			}
			rel, err := filepath.Rel(root, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				return 0, fmt.Errorf("process cgroup %q is outside mount root %q; %s", path, root, remount)
			}
			return compactCgroupTreeAvailable(mount, filepath.Join(mount, rel))
		}
	}
	return 0, errors.New("unified process cgroup not found")
}

func compactCgroupMountRoot(mount, mountinfo string, id uint64) (root, mountpoint string, err error) {
	data, err := os.ReadFile(mountinfo) //nolint:gosec // fixed procfs path outside tests
	if err != nil {
		return "", "", err
	}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	idField := strconv.FormatUint(id, 10)
	for line := range strings.SplitSeq(string(data), "\n") {
		// The filesystem type follows the separator; optional fields precede it.
		before, after, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields := strings.Split(before, " ")
		if len(fields) < 6 {
			continue
		}
		point := unescape.Replace(fields[4])
		if id != 0 && fields[0] != idField || id == 0 && point != mount {
			continue
		}
		// Without mount IDs, fall back to the last row at this mount point.
		root, mountpoint = "", ""
		if strings.HasPrefix(after, "cgroup2 ") {
			root, mountpoint = unescape.Replace(fields[3]), point
		}
		if id != 0 {
			break
		}
	}
	return root, mountpoint, nil
}

func compactCgroupTreeAvailable(root, group string) (uint64, error) {
	available := uint64(math.MaxUint64)
	for {
		if st, err := os.Stat(group); err != nil {
			return 0, err
		} else if !st.IsDir() {
			return 0, fmt.Errorf("not a cgroup directory: %s", group)
		}
		raw, err := os.ReadFile(filepath.Join(group, "memory.max")) //nolint:gosec // group is a clean kernel cgroup path under the cgroup mount
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		// At the root or when the memory controller is not delegated,
		// memory.max may not exist. Ancestors still constrain this process.
		if limitText := strings.TrimSpace(string(raw)); err == nil && limitText != "max" {
			limit, err := strconv.ParseUint(limitText, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid cgroup memory.max: %w", err)
			}
			current, err := os.ReadFile(filepath.Join(group, "memory.current")) //nolint:gosec // group is a clean kernel cgroup path under the cgroup mount
			if err != nil {
				return 0, err
			}
			used, err := strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid cgroup memory.current: %w", err)
			}
			available = min(available, limit-min(limit, used))
		}
		if group == root {
			return available, nil
		}
		group = filepath.Dir(group)
	}
}

func linuxCompactPolicyBlockSize(st unix.Statfs_t) uint64 {
	if st.Frsize > 0 {
		return uint64(st.Frsize)
	}
	if st.Bsize > 0 {
		return uint64(st.Bsize)
	}
	return 0
}

func compactHostAvailableMemory() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		value, found := strings.CutPrefix(s.Text(), "MemAvailable:")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 2 && fields[1] == "kB" {
			kb, err := strconv.ParseUint(fields[0], 10, 64)
			if err == nil && kb <= math.MaxUint64/1024 {
				return kb * 1024, nil
			}
		}
		return 0, fmt.Errorf("invalid MemAvailable in /proc/meminfo")
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemAvailable missing from /proc/meminfo")
}
