//go:build !linux

package server

import "syscall"

// Non-Linux platforms run the owned UDP engine without the pktinfo
// machinery: a wildcard bind replies from the kernel-default source for
// the destination, which is correct on single-homed hosts. Multihomed
// wildcard deployments should bind specific addresses (the production
// posture); Linux — the deployment target — carries the full machinery.
// The engine's control-truncation drop path never fires here because no
// control data is requested.

const msgTrunc = 0

const pktinfoSpace = 32

func pktinfoControl(_ string, _ bool) func(network, address string, c syscall.RawConn) error {
	return reusePortControl
}

func preparePktinfoReply(_ []byte, _ *udpJob) bool {
	// Without requested control data this is unreachable; refusing keeps
	// the contract explicit if it ever is.
	return false
}
