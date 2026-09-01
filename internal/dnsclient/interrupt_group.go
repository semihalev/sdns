package dnsclient

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// interruptGroupSlots bounds the connections one group can watch at a time.
// A lookup's in-flight exchanges rarely exceed its parallel fan-out; an
// exchange that finds the group full falls back to its own registration.
const interruptGroupSlots = 8

// InterruptGroup makes a set of synchronous connection operations observe one
// context's cancellation through a single registration. Each per-exchange
// context.AfterFunc costs an afterFuncCtx, a closure and a children-map entry;
// a group pays that once per cancellation domain and hands out array slots.
//
// The reuse contract matches CancelInterrupt.Stop: once Disarm returns, the
// group never touches that connection again, and a fire already touching it
// has finished, both guaranteed by the group mutex.
type InterruptGroup struct {
	mu    sync.Mutex
	fired bool
	stop  func() bool
	conns [interruptGroupSlots]net.Conn
}

// NewInterruptGroup registers one cancellation callback on ctx and returns
// the group armed connections are interrupted through. A context without a
// Done channel needs no interruption; the nil group it returns makes
// ExchangeInterruptible take the ordinary path.
func NewInterruptGroup(ctx context.Context) *InterruptGroup {
	if ctx.Done() == nil {
		return nil
	}
	g := &InterruptGroup{}
	g.stop = context.AfterFunc(ctx, g.fire)
	return g
}

func (g *InterruptGroup) fire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fired = true
	now := time.Now()
	for _, conn := range g.conns {
		if conn != nil {
			_ = conn.SetDeadline(now)
		}
	}
}

// arm registers conn for interruption and reports the slot to disarm. When
// the group already fired, the operation about to start must still observe
// the cancellation, mirroring context.AfterFunc on an already-canceled
// context, so the deadline is applied here and now. ok is false only when
// every slot is taken (or conn is nil); the caller falls back to its own
// registration.
func (g *InterruptGroup) arm(conn net.Conn) (slot int, ok bool) {
	if conn == nil {
		return 0, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.conns {
		if g.conns[i] == nil {
			g.conns[i] = conn
			if g.fired {
				_ = conn.SetDeadline(time.Now())
			}
			return i, true
		}
	}
	return 0, false
}

// disarm releases a slot. The mutex doubles as the join barrier: a fire
// holding the lock finishes every SetDeadline before disarm proceeds, so the
// connection is free for reuse the moment disarm returns.
func (g *InterruptGroup) disarm(slot int) {
	g.mu.Lock()
	g.conns[slot] = nil
	g.mu.Unlock()
}

// Close detaches the context registration. It does not join a fire already
// in flight: any connection still armed belongs to an operation that has not
// disarmed yet, and interrupting it remains correct, per-connection reuse
// safety is disarm's guarantee, not Close's. Callers cancel their domain
// before closing, so stragglers are interrupted, not stranded.
func (g *InterruptGroup) Close() {
	if g == nil {
		return
	}
	if g.stop != nil {
		g.stop()
	}
}

// ExchangeInterruptible performs Exchange bound to g's cancellation domain,
// falling back to the per-operation ExchangeContext registration when the
// group is nil or full. The caller still owns dialing and the ordinary
// network deadline.
func (co *Conn) ExchangeInterruptible(ctx context.Context, g *InterruptGroup, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	if g != nil {
		if slot, ok := g.arm(co.Conn); ok {
			defer g.disarm(slot)
			return co.Exchange(m)
		}
	}
	return co.ExchangeContext(ctx, m)
}
