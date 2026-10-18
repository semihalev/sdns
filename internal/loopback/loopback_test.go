package loopback

import (
	"net"
	"testing"
)

// TestListenDualSharesOnePort pins the contract: both sockets are open,
// on loopback, at the same port.
func TestListenDualSharesOnePort(t *testing.T) {
	pc, ln := ListenDual(t)
	defer func() { _ = pc.Close() }()
	defer func() { _ = ln.Close() }()

	udp := pc.LocalAddr().(*net.UDPAddr)
	tcp := ln.Addr().(*net.TCPAddr)
	if udp.Port == 0 || udp.Port != tcp.Port {
		t.Fatalf("UDP port %d, TCP port %d, want one nonzero port", udp.Port, tcp.Port)
	}
	if !udp.IP.IsLoopback() || !tcp.IP.IsLoopback() {
		t.Fatalf("UDP %v, TCP %v, want loopback", udp.IP, tcp.IP)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial the TCP listener: %v", err)
	}
	_ = conn.Close()
}
