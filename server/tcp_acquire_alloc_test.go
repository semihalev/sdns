//go:build !race

package server

import (
	"net"
	"runtime"
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

	e := newTCPEngine(echo, "tcp", 1)

	// A stream as a connection gets one: through reset, which is where
	// connection setup happens and where anything the connection owns for
	// the life of the session has to be built.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	stream := e.streams.Get().(*tcpStream)
	stream.reset(server)

	// Empty the ring, so every acquisition below takes the waiting path.
	held := make([]*tcpJob, 0, len(e.free))
	for len(e.free) > 0 {
		held = append(held, <-e.free)
	}
	defer func() {
		for _, j := range held {
			e.free <- j
		}
	}()

	// The cold one first, and measured raw. AllocsPerRun runs the body
	// once before it starts counting, so anything a connection builds on
	// its first contended wait is created inside that unmeasured call and
	// never appears — which is exactly how a timer allocated on this path
	// stayed hidden. The first wait a connection ever makes is a served
	// query like any other.
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if j := e.acquire(stream, time.Now()); j != nil {
		t.Fatal("acquired a slab from an empty ring")
	}
	runtime.ReadMemStats(&after)
	if cold := after.Mallocs - before.Mallocs; cold != 0 {
		t.Fatalf("a connection's first contended acquisition allocated %d objects; "+
			"the wait state belongs to connection setup, not to the query that "+
			"first has to wait", cold)
	}

	allocs := testing.AllocsPerRun(200, func() {
		// An already-passed deadline: the wait resolves immediately and
		// deterministically, exercising the allocation site without
		// spending the wall-clock a real contended wait would.
		if j := e.acquire(stream, time.Now()); j != nil {
			t.Fatal("acquired a slab from an empty ring")
		}
	})
	if allocs != 0 {
		t.Fatalf("a contended acquisition allocated %.2f objects; the wait "+
			"state must be owned by the connection, not built per wait", allocs)
	}
}
