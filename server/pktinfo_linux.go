//go:build linux

package server

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Wildcard-bind source-address correctness, allocation-free: the kernel
// tells us which local address a datagram arrived on (IP_PKTINFO /
// IPV6_PKTINFO), and the reply carries a control message pinning that
// address as the source. The control messages are parsed and built by
// hand into job-owned scratch — the portable parsers allocate per
// datagram, which is exactly the cost this path exists to remove.

// msgTrunc is the kernel's datagram-truncation flag.
const msgTrunc = unix.MSG_TRUNC

// pktinfoSpace bounds one pktinfo control message: the cmsg header (16
// bytes on 64-bit, 12 on 32-bit) plus the v6 pktinfo payload (20 bytes),
// aligned. 64 covers every Linux ABI with room to spare.
const pktinfoSpace = 64

// pktinfoControl returns the ListenConfig control hook enabling receive
// pktinfo on a wildcard socket, composed with the reuse-port hook.
func pktinfoControl(network string, v6 bool) func(network, address string, c syscall.RawConn) error {
	return func(net, addr string, c syscall.RawConn) error {
		if err := reusePortControl(net, addr, c); err != nil {
			return err
		}
		var serr error
		err := c.Control(func(fd uintptr) {
			if v6 {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1) //nolint:gosec // fd from RawConn
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1) //nolint:gosec // fd from RawConn
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// preparePktinfoReply walks the received control data and builds the reply
// control message in the job's scratch: the reply's source address is the
// query's destination address. Unknown or truncated control data refuses —
// the caller drops rather than misattribute.
func preparePktinfoReply(oob []byte, j *udpJob) bool {
	for len(oob) >= unix.SizeofCmsghdr {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0])) //nolint:gosec // bounded cmsg walk
		l := int(h.Len)
		if l < unix.SizeofCmsghdr || l > len(oob) {
			return false
		}
		data := oob[unix.SizeofCmsghdr:l]
		switch {
		case h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO &&
			len(data) >= unix.SizeofInet4Pktinfo:
			recv := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0])) //nolint:gosec // size-checked above
			out := buildCmsg(j, unix.IPPROTO_IP, unix.IP_PKTINFO, unix.SizeofInet4Pktinfo)
			info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&out[0])) //nolint:gosec // scratch-owned
			*info = unix.Inet4Pktinfo{Spec_dst: recv.Addr}
			return true
		case h.Level == unix.IPPROTO_IPV6 && h.Type == unix.IPV6_PKTINFO &&
			len(data) >= unix.SizeofInet6Pktinfo:
			recv := (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0])) //nolint:gosec // size-checked above
			out := buildCmsg(j, unix.IPPROTO_IPV6, unix.IPV6_PKTINFO, unix.SizeofInet6Pktinfo)
			info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&out[0])) //nolint:gosec // scratch-owned
			// Link-local scopes need the interface pinned; global scopes
			// tolerate it, and echoing the receive interface matches the
			// reply route the client used.
			*info = unix.Inet6Pktinfo{Addr: recv.Addr, Ifindex: recv.Ifindex}
			return true
		}
		adv := cmsgAlign(l)
		if adv <= 0 || adv > len(oob) {
			return false
		}
		oob = oob[adv:]
	}
	// No recognizable pktinfo: on a wildcard bind the destination is
	// unknowable.
	return false
}

// buildCmsg writes a cmsg header into the job's reply scratch and returns
// the data region for the caller to fill.
func buildCmsg(j *udpJob, level, typ int32, dataLen int) []byte {
	total := unix.CmsgSpace(dataLen)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&j.pktinfo[0])) //nolint:gosec // scratch-owned, fixed size
	h.Level = level
	h.Type = typ
	h.SetLen(unix.CmsgLen(dataLen))
	j.pktinfoLen = total
	return j.pktinfo[unix.SizeofCmsghdr:total]
}

func cmsgAlign(l int) int {
	const align = unix.SizeofPtr
	return (l + align - 1) & ^(align - 1)
}
