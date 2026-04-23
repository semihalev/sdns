//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package server

import "syscall"

// kernelLoadBalances is false on Darwin / BSDs. SO_REUSEPORT here
// lets sockets bind but does not distribute incoming UDP datagrams
// across them — measured both with N sockets and with a single
// shared socket under N ReadFrom goroutines, the extra workers only
// add scheduler overhead. The Darwin UDP recv path saturates at the
// single-socket ceiling (~130k QPS on an M4) regardless of how many
// goroutines drain it, so we stop at one worker.
const kernelLoadBalances = false

// reusePortControl is a no-op: one socket means nothing to reuse.
func reusePortControl(_, _ string, _ syscall.RawConn) error { return nil }

// defaultUDPWorkers returns 1. Multiple readers on a shared socket
// do not parallelise on Darwin's kernel recv path — benchmarks show
// a 2–3% regression from the extra goroutines.
func defaultUDPWorkers() int { return 1 }
