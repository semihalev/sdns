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
// hand into job-owned scratch, the portable parsers allocate per
// datagram, which is exactly the cost this path exists to remove.

// msgTrunc is the kernel's datagram-truncation flag.
const msgTrunc = unix.MSG_TRUNC

// pktinfoSpace bounds the control data a datagram can carry, and it has
// to hold *both* pktinfo messages: a dual-stack socket armed for each
// family delivers an IPv4 one (16 + 12, aligned to 32) and an IPv6 one
// (16 + 20, aligned to 40) for the same v4-mapped datagram. Sized for one
// of them, the kernel truncates the control data, sets MSG_CTRUNC, and
// the wildcard path drops every datagram it cannot place. 128 covers both
// on every Linux ABI with room to spare, and costs a job slab nothing
// worth counting.
const pktinfoSpace = 128

// pktinfoControl returns the ListenConfig control hook enabling receive
// pktinfo on a wildcard socket, composed with the reuse-port hook.
// Both families are armed, and the socket decides which one applies.
// Guessing from the bind string does not work: a plain ":53" asks Go for
// a dual-stack socket, which carries IPv6 datagrams as well as
// v4-mapped ones, and a socket armed for IPv4 alone hands those v6
// datagrams over with no control message at all. The reply path cannot
// know which local address they arrived on, so it refuses them, and
// IPv6 service disappears on the most ordinary configuration there is,
// counted as a drop and otherwise silent.
//
// Arming the option a socket does not support fails harmlessly, so the
// bind succeeds when at least one applies: IPv4-only sockets take
// IP_PKTINFO, IPv6-only take IPV6_RECVPKTINFO, dual-stack take both.
func pktinfoControl(network string) func(network, address string, c syscall.RawConn) error {
	return func(net, addr string, c syscall.RawConn) error {
		if err := reusePortControl(net, addr, c); err != nil {
			return err
		}
		var v4err, v6err error
		if err := c.Control(func(fd uintptr) {
			v4err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)         //nolint:gosec // fd from RawConn
			v6err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1) //nolint:gosec // fd from RawConn
		}); err != nil {
			return err
		}
		if v4err != nil && v6err != nil {
			// Neither family took it: this socket cannot tell us where a
			// datagram landed, and a wildcard bind that cannot answer
			// from the right source address is worse than one that
			// refuses to start.
			return v4err
		}
		return nil
	}
}

// preparePktinfoReply walks the received control data and builds the reply
// control message in the job's scratch: the reply's source address is the
// query's destination address. Unknown or truncated control data refuses,
// the caller drops rather than misattribute.
func preparePktinfoReply(oob []byte, j *udpJob) bool {
	// Both may be present, and then the IPv4 one is used: a v4-mapped
	// datagram arriving on a dual-stack socket is answered from an IPv4
	// source, which is the shape that was already proven on the wire.
	// The walk therefore completes rather than returning at the first
	// match, remembering an IPv6 candidate only until an IPv4 one turns
	// up.
	var v6 *unix.Inet6Pktinfo
	for len(oob) >= unix.SizeofCmsghdr {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0])) //nolint:gosec // bounded cmsg walk
		l := int(h.Len)                               //nolint:gosec // G115, validated against the buffer bound on the next line
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
			v6 = (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0])) //nolint:gosec // size-checked above
		}
		adv := cmsgAlign(l)
		if adv <= 0 || adv > len(oob) {
			return false
		}
		oob = oob[adv:]
	}
	if v6 != nil {
		out := buildCmsg(j, unix.IPPROTO_IPV6, unix.IPV6_PKTINFO, unix.SizeofInet6Pktinfo)
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&out[0])) //nolint:gosec // scratch-owned
		// Link-local scopes need the interface pinned; global scopes
		// tolerate it, and echoing the receive interface matches the
		// reply route the client used.
		*info = unix.Inet6Pktinfo{Addr: v6.Addr, Ifindex: v6.Ifindex}
		return true
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
