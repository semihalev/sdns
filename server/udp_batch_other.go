//go:build !linux

package server

// The batched recvmmsg/sendmmsg layer is Linux-only; elsewhere the
// portable reader serves and the sender type exists solely so the job and
// engine fields compile.

func (e *udpEngine) startBatched() bool { return false }
