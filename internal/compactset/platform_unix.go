//go:build unix

package compactset

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// The linux and darwin build constraints also include android and ios.
const rollingMmapSupported = runtime.GOOS == "linux" || runtime.GOOS == "android" ||
	runtime.GOOS == "darwin" || runtime.GOOS == "ios"

func openRollingArtifact(path string) (*os.File, error) {
	if !rollingMmapSupported {
		return nil, errMmapUnsupported
	}
	// Nonblocking open lets fstat reject a substituted FIFO without waiting
	// for a writer. Regular files need read access for mmap, not O_NONBLOCK.
	return os.OpenFile(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) //nolint:gosec // G304: generated or validated artifact basename in the store directory.
}

func mapFile(f *os.File, n int) ([]byte, error) {
	b, e := unix.Mmap(int(f.Fd()), 0, n, unix.PROT_READ, unix.MAP_SHARED)
	if e == nil {
		_ = unix.Madvise(b, unix.MADV_RANDOM)
	}
	return b, e
}

func unmapFile(b []byte) error {
	if !rollingMmapSupported {
		return nil
	}
	return unix.Munmap(b)
}

func rollingDevice(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil //nolint:gosec,unconvert // Dev's type varies by platform; compare the ID without interpreting its sign.
}
