//go:build linux || darwin

package blocklist

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func init() {
	compactPolicyDisk = compactPolicyDiskUnix
	openCompactStateFile = openCompactStateFileUnix
	openCompactLocalFile = openCompactLocalFileUnix
	openCompactFeedDirectory = openCompactFeedDirectoryUnix
	lockCompactDirectory = lockCompactDirectoryUnix
}

var compactPolicyBlockSize = func(st unix.Statfs_t) uint64 { return uint64(st.Bsize) }

func compactPolicyDiskUnix(dir string) (compactAdmissionDisk, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return compactAdmissionDisk{}, err
	}
	block := compactPolicyBlockSize(st)
	if block == 0 || st.Bavail > st.Bfree || st.Bfree > st.Blocks {
		return compactAdmissionDisk{}, fmt.Errorf("invalid policy filesystem block counts")
	}
	// Reserved blocks (free but not available to ordinary writers) do not
	// belong in the capacity against which the ten-percent gate is computed.
	usable := st.Blocks - (st.Bfree - st.Bavail)
	if usable > math.MaxUint64/block {
		return compactAdmissionDisk{}, fmt.Errorf("policy filesystem capacity overflows bytes")
	}
	return compactAdmissionDisk{st.Bavail * block, usable * block, block}, nil
}

func openCompactStateFileUnix(path string, flags int) (*os.File, error) {
	f, _, err := openCompactRegularFile(path, flags|unix.O_NOFOLLOW, 0)
	if err == nil && f == nil {
		err = fmt.Errorf("compact blocklist requires regular file %s", path)
	}
	return f, err
}

func openCompactLocalFileUnix(path string) (*os.File, os.FileInfo, error) {
	return openCompactRegularFile(path, unix.O_NOFOLLOW, 0)
}

func openCompactRegularFile(path string, flags int, mode uint32) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_NONBLOCK|unix.O_CLOEXEC|flags, mode)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, f.Close()
	}
	return f, st, nil
}

func openCompactFeedDirectoryUnix(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func lockCompactDirectoryUnix(dir string) (*os.File, error) {
	path := filepath.Join(dir, compactLockName)
	f, _, err := openCompactRegularFile(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("lock compact directory %q: %w", dir, err)
	}
	if f == nil {
		return nil, fmt.Errorf("lock compact directory %q: %w", dir, errCompactLockFile)
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("compact directory %q already in use: %w", dir, err)
		}
		return nil, fmt.Errorf("lock compact directory %q: %w", dir, err)
	}
	return f, nil
}
