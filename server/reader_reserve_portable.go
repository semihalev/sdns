//go:build !(linux && (amd64 || arm64))

package server

// udpReaderReserve is how many slabs each reader may hold at once: the
// portable reader arms one datagram at a time.
const udpReaderReserve = 1
