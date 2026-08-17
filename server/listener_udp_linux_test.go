//go:build linux

package server

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestUDPListener_ZeroPortFanoutSharesOnePort pins the fix for
// Bind rebinding ":0" to a different kernel-picked port per worker.
// With the fix, the first worker resolves the ephemeral port and
// every subsequent worker binds to that same port via SO_REUSEPORT —
// so all PacketConns report the same LocalAddr.
func TestUDPListener_ZeroPortFanoutSharesOnePort(t *testing.T) {
	h := rawHandlerFunc(func(middleware.Transport, []byte, time.Time) bool { return true })
	l := newUDPListener("127.0.0.1:0", h, time.Second, 0, 0, defaultResourcePlan(1))
	// Force multi-socket even on single-CPU runners.
	if l.sockets < 2 {
		l.sockets = 4
	}

	if err := l.Bind(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	// One PacketConn per socket. The engine's handler workers are a
	// separate, independently sized pool — asserting against them was a
	// leftover from when the two counts were the same field.
	if len(l.pcs) != l.sockets {
		t.Fatalf("%s: len(l.pcs) = %d, want %d", "one PacketConn per socket", len(l.pcs), l.sockets)
	}

	want := l.pcs[0].LocalAddr().String()
	if strings.Contains(want, ":0") {
		t.Fatalf("%s: %q contains %q", "kernel should have assigned a real port", want, ":0")
	}

	for i, pc := range l.pcs[1:] {
		got := pc.LocalAddr().String()
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: got = %v, want %v", fmt.Sprintf("worker %d bound to %s, expected shared %s", i+1, got, want), got, want)
		}
	}
}

// TestUDPWildcardReplySourceAddress pins the pktinfo machinery: a query
// sent to a wildcard-bound engine over loopback must be answered from the
// loopback address it was sent to, and the reply must reach the connected
// client socket (a connected UDP socket discards replies from any other
// source, so receipt itself is the source-address assertion).
func TestUDPWildcardReplySourceAddress(t *testing.T) {
	h := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	})
	l := newUDPListener("0.0.0.0:0", h, time.Second, 2, 16, defaultResourcePlan(1))
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve(context.Background()) }()
	defer func() { _ = l.Shutdown(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for !l.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	_, port, err := net.SplitHostPort(l.pcs[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	q := new(dns.Msg)
	q.SetQuestion("wildcard.example.", dns.TypeA)
	q.Id = 4321
	wire, _ := q.Pack()
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no reply through the connected socket — wrong source address? %v", err)
	}
	var r dns.Msg
	if err := r.Unpack(buf[:n]); err != nil || r.Id != q.Id {
		t.Fatalf("bad reply: %v %v", err, r.Id)
	}
}

// TestUDPDualStackBindServesIPv6 pins the default configuration.
//
// A bind with no host — ":53", which is what ships — asks Go for one
// dual-stack socket, and that socket carries IPv6 datagrams as well as
// v4-mapped ones. A wildcard bind answers from the address the query
// arrived on, which it learns from a pktinfo control message; a socket
// armed for IPv4 alone hands the v6 datagrams over without one. The reply
// path then cannot tell where they landed and refuses them, so IPv6
// service disappears on the most ordinary configuration there is —
// counted as a drop, and otherwise completely silent.
func TestUDPDualStackBindServesIPv6(t *testing.T) {
	if c, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback on this host")
	} else {
		_ = c.Close()
	}

	h := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	})

	// No host: the shipped shape, and the one that yields a dual-stack
	// socket rather than a family the bind string names.
	l := newUDPListener(":0", h, time.Second, 2, 16, defaultResourcePlan(1))
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve(context.Background()) }()
	defer func() { _ = l.Shutdown(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for !l.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	_, port, err := net.SplitHostPort(l.pcs[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{"127.0.0.1:" + port, "[::1]:" + port} {
		conn, err := net.Dial("udp", target)
		if err != nil {
			t.Fatalf("dial %s: %v", target, err)
		}
		q := new(dns.Msg)
		q.SetQuestion("dualstack.example.", dns.TypeA)
		q.Id = 5150
		wire, err := q.Pack()
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if _, err := conn.Write(wire); err != nil {
			_ = conn.Close()
			t.Fatalf("write %s: %v", target, err)
		}
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("no reply to a query from %s: %v — a wildcard bind that "+
				"cannot recover the destination address drops the datagram, "+
				"and this is what the shipped configuration does to every "+
				"IPv6 client", target, err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			t.Fatalf("reply from %s: %v", target, err)
		}
		if resp.Id != 5150 || !resp.Response {
			t.Fatalf("reply from %s has id %d response=%v", target, resp.Id, resp.Response)
		}
	}
}
