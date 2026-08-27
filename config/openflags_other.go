//go:build !unix

package config

// nonBlockingOpen has no counterpart here: Windows has no FIFO that an open
// can wait on the way a unix one does.
const nonBlockingOpen = 0
