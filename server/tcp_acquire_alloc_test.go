//go:build !race

package server

import (
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
	stream := new(tcpStream)

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
