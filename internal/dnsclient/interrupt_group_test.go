package dnsclient

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// recordingConn records SetDeadline calls. A non-nil entered/gate pair makes
// SetDeadline announce itself and then block until the gate closes, so tests
// can hold a fire in flight at a known point.
type recordingConn struct {
	net.Conn
	entered   chan struct{}
	gate      chan struct{}
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *recordingConn) SetDeadline(t time.Time) error {
	if c.entered != nil {
		c.entered <- struct{}{}
	}
	if c.gate != nil {
		<-c.gate
	}
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return nil
}

func (c *recordingConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.deadlines)
}

func waitForCount(t *testing.T, c *recordingConn, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for c.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("SetDeadline count stuck at %d, want %d", c.count(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInterruptGroup_NoDoneChannel(t *testing.T) {
	g := NewInterruptGroup(context.Background())
	if g != nil {
		t.Fatal("a context without a Done channel must not build a group")
	}
	g.Close() // nil receiver must be safe
}

func TestInterruptGroup_CancelInterruptsArmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := NewInterruptGroup(ctx)
	defer g.Close()

	conn := &recordingConn{}
	if _, ok := g.arm(conn); !ok {
		t.Fatal("arm on a fresh group must succeed")
	}

	cancel()
	waitForCount(t, conn, 1)
}

func TestInterruptGroup_DisarmedConnNeverTouched(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := NewInterruptGroup(ctx)
	defer g.Close()

	released := &recordingConn{}
	sentinel := &recordingConn{}
	slot, ok := g.arm(released)
	if !ok {
		t.Fatal("arm failed")
	}
	if _, ok := g.arm(sentinel); !ok {
		t.Fatal("arm failed")
	}
	g.disarm(slot)

	cancel()
	// The sentinel proves the fire ran; the disarmed conn must stay clean.
	waitForCount(t, sentinel, 1)
	if released.count() != 0 {
		t.Fatal("a disarmed connection was interrupted")
	}
}

func TestInterruptGroup_ArmAfterFire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := NewInterruptGroup(ctx)
	defer g.Close()

	sentinel := &recordingConn{}
	if _, ok := g.arm(sentinel); !ok {
		t.Fatal("arm failed")
	}
	cancel()
	waitForCount(t, sentinel, 1) // the fire has run to completion

	// An operation arming after the domain died must still observe the
	// cancellation, context.AfterFunc on a canceled context runs its
	// callback too; the group applies the deadline right in arm.
	late := &recordingConn{}
	if _, ok := g.arm(late); !ok {
		t.Fatal("arm after fire must still hand out a slot")
	}
	if late.count() != 1 {
		t.Fatal("arming after the fire must interrupt immediately")
	}
}

// TestInterruptGroup_DisarmJoinsFire pins the reuse contract: disarm may not
// return while a fire is still touching connections, because the caller
// releases the connection to a pool the moment disarm returns.
func TestInterruptGroup_DisarmJoinsFire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := NewInterruptGroup(ctx)
	defer g.Close()

	gate := make(chan struct{})
	blocked := &recordingConn{entered: make(chan struct{}, 1), gate: gate}
	other := &recordingConn{}
	if _, ok := g.arm(blocked); !ok {
		t.Fatal("arm failed")
	}
	otherSlot, ok := g.arm(other)
	if !ok {
		t.Fatal("arm failed")
	}

	cancel()          // the fire starts and blocks inside blocked.SetDeadline
	<-blocked.entered // the fire now holds the group lock

	disarmed := make(chan struct{})
	go func() {
		g.disarm(otherSlot)
		close(disarmed)
	}()

	select {
	case <-disarmed:
		t.Fatal("disarm returned while the fire was still running")
	case <-time.After(50 * time.Millisecond):
		// expected: disarm is blocked on the group lock
	}

	close(gate) // let the fire finish
	select {
	case <-disarmed:
	case <-time.After(2 * time.Second):
		t.Fatal("disarm never returned after the fire completed")
	}
	if other.count() != 1 {
		t.Fatal("a conn armed throughout the fire must have been interrupted")
	}
}

func TestInterruptGroup_SlotExhaustionFallsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := NewInterruptGroup(ctx)
	defer g.Close()

	conns := make([]*recordingConn, interruptGroupSlots)
	for i := range conns {
		conns[i] = &recordingConn{}
		if _, ok := g.arm(conns[i]); !ok {
			t.Fatalf("slot %d must be free", i)
		}
	}
	if _, ok := g.arm(&recordingConn{}); ok {
		t.Fatal("a full group must refuse to arm")
	}
	if _, ok := g.arm(nil); ok {
		t.Fatal("a nil conn must not be armed")
	}
}

func TestInterruptGroup_ArmDisarmAllocsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := NewInterruptGroup(ctx)
	defer g.Close()

	conn := &recordingConn{}
	allocs := testing.AllocsPerRun(100, func() {
		slot, ok := g.arm(conn)
		if !ok {
			t.Fatal("arm failed")
		}
		g.disarm(slot)
	})
	if allocs != 0 {
		t.Fatalf("arm/disarm allocated %.0f times per cycle, want 0", allocs)
	}
}

func TestExchangeInterruptible_ServesAndReleasesSlot(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 0x2222

	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Response = true
	resp.Id = 0x2222
	wire, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := NewInterruptGroup(ctx)
	defer g.Close()

	co := &Conn{
		Conn:    &fakeSeqPacketConn{datagrams: [][]byte{wire}},
		UDPSize: 512,
	}
	got, _, err := co.ExchangeInterruptible(ctx, g, req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got.Id != req.Id {
		t.Fatalf("wrong response id %#x", got.Id)
	}

	// The exchange must have released its slot: all slots arm again.
	for i := 0; i < interruptGroupSlots; i++ {
		if _, ok := g.arm(&recordingConn{}); !ok {
			t.Fatalf("slot %d still held after ExchangeInterruptible returned", i)
		}
	}
}

func TestExchangeInterruptible_NilGroupFallsBack(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 0x3333

	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Response = true
	resp.Id = 0x3333
	wire, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	co := &Conn{
		Conn:    &fakeSeqPacketConn{datagrams: [][]byte{wire}},
		UDPSize: 512,
	}
	got, _, err := co.ExchangeInterruptible(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got.Id != req.Id {
		t.Fatalf("wrong response id %#x", got.Id)
	}
}
