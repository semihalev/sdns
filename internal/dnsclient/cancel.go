package dnsclient

import (
	"context"
	"runtime"
	"sync"
	"time"
)

const (
	cancelInterruptIdle uint32 = iota
	cancelInterruptActive
	cancelInterruptStopping
)

type cancelInterruptState struct {
	mu           sync.Mutex
	done         sync.WaitGroup
	generation   uint64
	phase        uint32
	participants uint32
	stop         func() bool
}

// CancelInterrupt identifies one connection-cancellation registration.
// Stop must complete before the Conn or its underlying connection is reused.
type CancelInterrupt struct {
	state      *cancelInterruptState
	generation uint64
}

// BeginCancelInterrupt makes a synchronous connection operation observe
// context cancellation after dialing has completed. It captures the current
// underlying connection rather than the reusable wrapper, and Stop joins an
// already-started callback before reuse is allowed.
//
// A Conn supports one active interrupt registration at a time. The zero handle
// returned for a context without a Done channel has no allocation or cleanup
// cost.
func (co *Conn) BeginCancelInterrupt(ctx context.Context) CancelInterrupt {
	if ctx.Done() == nil {
		return CancelInterrupt{}
	}

	state := &co.cancelInterrupt
	state.mu.Lock()
	if state.phase != cancelInterruptIdle {
		state.mu.Unlock()
		panic("dnsclient: overlapping cancellation interrupts")
	}

	state.generation++
	generation := state.generation
	state.phase = cancelInterruptActive
	state.done.Add(1)
	conn := co.Conn
	state.stop = context.AfterFunc(ctx, func() {
		defer state.done.Done()
		if conn != nil {
			_ = conn.SetDeadline(time.Now())
		}
	})
	state.mu.Unlock()

	return CancelInterrupt{state: state, generation: generation}
}

// Stop detaches the cancellation callback and waits if it has already started.
// Concurrent repeated calls join the same cleanup; stale-generation calls are
// no-ops.
func (h CancelInterrupt) Stop() {
	state := h.state
	if state == nil {
		return
	}

	state.mu.Lock()
	if state.generation != h.generation || state.phase == cancelInterruptIdle {
		state.mu.Unlock()
		return
	}
	leader := state.phase == cancelInterruptActive
	if leader {
		state.phase = cancelInterruptStopping
	}
	state.participants++
	stop := state.stop
	state.mu.Unlock()

	if leader && stop != nil && stop() {
		state.done.Done()
	}
	state.done.Wait()

	// Keep every same-generation Stop joined through the final idle
	// transition. The wait group has already reached zero here, so the only
	// remaining window is another Stop completing its bookkeeping; yielding
	// avoids adding a per-Conn condition variable to this transport hot path.
	state.mu.Lock()
	state.participants--
	if state.participants == 0 {
		state.stop = nil
		state.phase = cancelInterruptIdle
	} else {
		for state.phase != cancelInterruptIdle {
			state.mu.Unlock()
			runtime.Gosched()
			state.mu.Lock()
		}
	}
	state.mu.Unlock()
}

func (s *cancelInterruptState) active() bool {
	s.mu.Lock()
	active := s.phase == cancelInterruptActive
	s.mu.Unlock()
	return active
}
