package server

import "golang.org/x/sys/unix"

// udpReaderReserve is how many slabs each reader may hold at once. The
// batched Linux reader arms a full recvmmsg batch.
const udpReaderReserve = udpBatchSize

// fdSoftLimit is how many descriptors this process may hold open.
func fdSoftLimit() uint64 {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return rl.Cur
}
