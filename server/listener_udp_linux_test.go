//go:build linux

package server

import (
	"context"
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
	l := newUDPListener("127.0.0.1:0", h, time.Second)
	// Force multi-worker even on single-CPU runners.
	if l.workers < 2 {
		l.workers = 4
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
