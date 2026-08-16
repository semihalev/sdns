//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package server

import "golang.org/x/sys/unix"

// fdSoftLimit is how many descriptors this process may hold open.
func fdSoftLimit() uint64 {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	// Cur is uint64 on Darwin and int64 on the BSDs, so it goes through
	// int64 rather than being assumed: every platform's RLIM_INFINITY
	// fits, anything negative reads as "no bound", and this is the field
	// that has to compile for the FreeBSD release target as well.
	cur := int64(rl.Cur) //nolint:unconvert,gosec // identity on the BSDs, bounded on Darwin
	if cur < 0 {
		return 0
	}
	return uint64(cur)
}
