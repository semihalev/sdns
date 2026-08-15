package server

import (
	"os"
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
	return si.Totalram * uint64(si.Unit)
}

// containerMemoryLimit is what the cgroup allows, which on a container
// host is the only number that matters: the machine may have 64GB and
// this process 128MB of it.
func containerMemoryLimit() uint64 {
	// cgroup v2 first, then v1. "max" means no limit.
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if value == "max" {
			return 0
		}
		limit, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			continue
		}
		// v1 spells "unlimited" as a number so large it is really a
		// sentinel; anything at that scale is not a limit.
		if limit == 0 || limit > 1<<62 {
			return 0
		}
		return limit
	}
	return 0
}
