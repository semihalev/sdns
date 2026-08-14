//go:build linux && (amd64 || arm64)

package server

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestRawMmsgProbe exercises the exact recvmmsg/sendmmsg arming this
// package uses, one message end to end, with errno visibility. It exists
// to localize kernel-interface regressions away from the engine plumbing.
func TestRawMmsgProbe(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	server := pc.(*net.UDPConn)
	rc, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	var (
		buf   [64]byte
		name  [unix.SizeofSockaddrInet6]byte
		iov   = unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
		hdrs  [1]mmsgHdr
		recvN int
		rerrn unix.Errno
	)
	hdrs[0].hdr = unix.Msghdr{
		Name:    &name[0],
		Namelen: unix.SizeofSockaddrInet6,
		Iov:     &iov,
		Iovlen:  1,
	}
	err = rc.Read(func(fd uintptr) bool {
		n, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&hdrs[0])), //nolint:gosec // probe
			1, 0, 0, 0,
		)
		if errno == unix.EAGAIN {
			return false
		}
		recvN, rerrn = int(n), errno //nolint:gosec // G115 — one-message probe
		return true
	})
	if err != nil || rerrn != 0 {
		t.Fatalf("recvmmsg: err=%v errno=%v", err, rerrn)
	}
	if recvN != 1 || hdrs[0].dlen != 5 || string(buf[:5]) != "hello" {
		t.Fatalf("recvmmsg delivered n=%d len=%d payload=%q namelen=%d",
			recvN, hdrs[0].dlen, buf[:5], hdrs[0].hdr.Namelen)
	}
	family := uint16(name[0]) | uint16(name[1])<<8
	if family != unix.AF_INET {
		t.Fatalf("sockaddr family %d", family)
	}

	// Echo it back through sendmmsg with the captured sockaddr.
	reply := []byte("world")
	siov := unix.Iovec{Base: &reply[0], Len: uint64(len(reply))}
	var shdrs [1]mmsgHdr
	shdrs[0].hdr = unix.Msghdr{
		Name:    &name[0],
		Namelen: hdrs[0].hdr.Namelen,
		Iov:     &siov,
		Iovlen:  1,
	}
	var (
		sentN int
		serrn unix.Errno
	)
	err = rc.Write(func(fd uintptr) bool {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&shdrs[0])), //nolint:gosec // probe
			1, 0, 0, 0,
		)
		if errno == unix.EAGAIN {
			return false
		}
		sentN, serrn = int(n), errno //nolint:gosec // G115 — one-message probe
		return true
	})
	if err != nil || serrn != 0 || sentN != 1 {
		t.Fatalf("sendmmsg: err=%v errno=%v n=%d", err, serrn, sentN)
	}

	got := make([]byte, 64)
	n, err := client.Read(got)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got[:n]) != "world" {
		t.Fatalf("client got %q", got[:n])
	}
}
