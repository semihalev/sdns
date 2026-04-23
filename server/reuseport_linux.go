//go:build linux

package server

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// kernelLoadBalances reports that the platform's SO_REUSEPORT
// implementation distributes incoming UDP datagrams across sockets.
// The udpListener opens N independent sockets when this is true and
// the kernel hashes each datagram by its 4-tuple to one of them.
const kernelLoadBalances = true

func reusePortControl(_, _ string, c syscall.RawConn) error {
	var opErr error
	ctrlErr := c.Control(func(fd uintptr) {
		// File descriptors are small non-negative ints on Linux, so
		// the uintptr -> int conversion is always safe. gosec G115
		// can't prove that on its own.
		sockfd := int(fd) //nolint:gosec // G115 — kernel FDs always fit in int
		if err := unix.SetsockoptInt(sockfd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			opErr = err
			return
		}
		if err := unix.SetsockoptInt(sockfd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			opErr = err
		}
	})
	if opErr != nil {
		return opErr
	}
	return ctrlErr
}

func defaultUDPWorkers() int {
	n := runtime.NumCPU()
	if n > 16 {
		n = 16
	}
	if n < 1 {
		n = 1
	}
	return n
}
