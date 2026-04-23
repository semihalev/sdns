//go:build windows

package server

import "syscall"

// kernelLoadBalances is false on Windows. SO_REUSE_UNICASTPORT exists
// but does not distribute incoming UDP datagrams across bound sockets,
// and running N concurrent ReadFrom goroutines on a single socket does
// not give the throughput boost it gives on Unix because the Windows
// IOCP model already multiplexes recv calls. One socket, one reader.
const kernelLoadBalances = false

func reusePortControl(_, _ string, _ syscall.RawConn) error { return nil }

func defaultUDPWorkers() int { return 1 }
