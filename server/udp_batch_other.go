//go:build !linux

package server

// The batched recvmmsg/sendmmsg layer is Linux-only; elsewhere the
// portable reader serves and the sender type exists solely so the job and
// engine fields compile.

type udpBatchSender struct{}

func (s *udpBatchSender) send(j *udpJob, b []byte) (int, error) {
	// Unreachable: nothing arms j.sender off Linux.
	return 0, nil
}

func (e *udpEngine) startBatched() bool { return false }

func (e *udpEngine) stopBatchSenders() {}
