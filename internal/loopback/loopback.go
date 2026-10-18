// Package loopback opens test listeners on the loopback interface. It is
// imported only by tests.
package loopback

import (
	"net"
	"testing"
)

// ListenDual opens a UDP socket and a TCP listener on one loopback port,
// for a test server that has to answer both transports at a single
// address. Both stay open and are the caller's to close.
//
// Only one of the two can draw the port from :0, and the other binds the
// number it was given. Windows keeps per-protocol excluded port ranges,
// so a port one protocol is given is not necessarily one the other may
// bind; the bind fails there with a permission error rather than "in
// use". A refused port is given back and a fresh one drawn.
//
// Which side draws is alternated rather than fixed. Ten consecutive
// TCP-first draws failed on a CI runner, which is what a fixed choice
// looks like when the allocator hands out a sequential run inside one
// exclusion block: every redraw lands in the same place. The two
// protocols allocate from different state, so letting each take a turn
// means a block that swallows one side's run does not swallow the
// other's.
func ListenDual(tb testing.TB) (net.PacketConn, net.Listener) {
	tb.Helper()
	const attempts = 64
	var err error
	for attempt := range attempts {
		if attempt%2 == 0 {
			var ln net.Listener
			if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
				tb.Fatalf("listen TCP: %v", err)
			}
			var pc net.PacketConn
			if pc, err = net.ListenPacket("udp", ln.Addr().String()); err == nil {
				return pc, ln
			}
			_ = ln.Close()
		} else {
			var pc net.PacketConn
			if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
				tb.Fatalf("listen UDP: %v", err)
			}
			var ln net.Listener
			if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
				return pc, ln
			}
			_ = pc.Close()
		}
	}
	tb.Fatalf("no loopback port both transports would accept in %d attempts: %v", attempts, err)
	return nil, nil
}
