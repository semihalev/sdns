//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package server

// udpReaderReserve is how many slabs each reader may hold at once: the
// portable reader arms one datagram at a time.
const udpReaderReserve = 1

// fdSoftLimit is unknowable here; zero means "no descriptor bound".
func fdSoftLimit() uint64 { return 0 }
