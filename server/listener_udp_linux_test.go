//go:build linux

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUDPListener_ZeroPortFanoutSharesOnePort pins the fix for
// Bind rebinding ":0" to a different kernel-picked port per worker.
// With the fix, the first worker resolves the ephemeral port and
// every subsequent worker binds to that same port via SO_REUSEPORT —
// so all PacketConns report the same LocalAddr.
func TestUDPListener_ZeroPortFanoutSharesOnePort(t *testing.T) {
	h := dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
	l := newUDPListener("127.0.0.1:0", h, time.Second, 0, 0)
	// Force multi-socket even on single-CPU runners.
	if l.sockets < 2 {
		l.sockets = 4
	}

	require.NoError(t, l.Bind(context.Background()))
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	require.Len(t, l.pcs, l.workers, "one PacketConn per worker")

	want := l.pcs[0].LocalAddr().String()
	require.NotContains(t, want, ":0", "kernel should have assigned a real port")

	for i, pc := range l.pcs[1:] {
		got := pc.LocalAddr().String()
		assert.Equalf(t, want, got,
			"worker %d bound to %s, expected shared %s", i+1, got, want)
	}
}

// TestUDPWildcardReplySourceAddress pins the pktinfo machinery: a query
// sent to a wildcard-bound engine over loopback must be answered from the
// loopback address it was sent to, and the reply must reach the connected
// client socket (a connected UDP socket discards replies from any other
// source, so receipt itself is the source-address assertion).
func TestUDPWildcardReplySourceAddress(t *testing.T) {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	l := newUDPListener("0.0.0.0:0", h, time.Second, 2, 16)
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
