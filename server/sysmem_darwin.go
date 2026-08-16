package server

import "golang.org/x/sys/unix"

// systemMemoryBytes is what the machine has.
func systemMemoryBytes() uint64 {
	mem, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return mem
}

// containerMemoryLimit has no meaning here: this platform is where the
// server is developed, not where it is packed into a cgroup.
func containerMemoryLimit() uint64 { return 0 }
