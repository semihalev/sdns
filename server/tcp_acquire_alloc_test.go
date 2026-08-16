//go:build !race

package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestTCPAcquireUnderContentionAllocatesNothing pins the saturated
// acquisition path.
//
// Saturation is exactly when allocating is worst: the ring is empty
// because every slab is busy, the machine is at its limit, and this is
// the path that decides whether the queries still queued get served or
// dropped. A timer allocated per wait puts the allocator on the hot path
// precisely under the load the whole design exists to survive — and the
// request that waits and then succeeds is a served hit like any other,
// so it has to cost nothing too.
//
// The wait state belongs to the connection, which already owns framing
// buffers for the same reason.
func TestTCPAcquireUnderContentionAllocatesNothing(t *testing.T) {
	echo := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	})

	e := newTCPEngine(echo, "tcp", 1, defaultResourcePlan(1))

	// A stream as a connection gets one: through reset, which is where
	// connection setup happens and where anything the connection owns for
	// the life of the session has to be built.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	stream := e.streams.Get().(*tcpStream)
	stream.reset(server)

	// Take the class's one token, so every acquisition below takes the
	// waiting path.
	<-e.smallTokens
	defer func() { e.smallTokens <- struct{}{} }()

	// The cold property first, asserted structurally: the wait timer must
	// exist the moment reset returns, before the first contended wait ever
	// runs. AllocsPerRun runs the body once before it starts counting, so
	// a timer built lazily on the first wait would be created inside that
	// unmeasured call and never appear — which is exactly how one stayed
	// hidden. A process-wide MemStats delta catches it but also counts
	// every background goroutine's allocations, and flaked for exactly
	// that reason; the invariant is about where the timer lives, so assert
	// that directly.
	if stream.wait == nil {
		t.Fatal("connection setup did not build the wait timer; the first " +
			"contended wait would allocate it on the acquisition path")
	}

	allocs := testing.AllocsPerRun(200, func() {
		// An already-passed deadline: the wait resolves immediately and
		// deterministically, exercising the allocation site without
		// spending the wall-clock a real contended wait would.
		if j := e.acquire(stream, time.Now(), 64); j != nil {
			t.Fatal("acquired a slab from an empty ring")
		}
	})
	if allocs != 0 {
		t.Fatalf("a contended acquisition allocated %.2f objects; the wait "+
			"state must be owned by the connection, not built per wait", allocs)
	}
}
