//go:build !linux || !(amd64 || arm64)

package server

// The batched recvmmsg/sendmmsg layer is built only for the Linux
// architectures whose descriptor layout and byte order it was verified
// against (see udp_batch_linux.go); everywhere else the portable reader
// serves.

func (e *udpEngine) startBatched() bool { return false }
