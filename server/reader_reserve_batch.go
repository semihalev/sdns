//go:build linux && (amd64 || arm64)

package server

// udpReaderReserve is how many slabs each reader may hold at once: the
// batched reader (udp_batch_linux.go) arms a full recvmmsg batch. The
// build expression here is deliberately identical to that file's — a
// platform that takes the portable reader must not be charged for a
// batch it will never arm.
const udpReaderReserve = udpBatchSize
