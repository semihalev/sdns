package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestUDPAdmissionOutlivesTheSteadyState pins what the lease cap is and
// is not.
//
// A slab is held for the whole request. On a hit that is microseconds —
// but a miss holds one for an upstream resolution, so a cap at the
// steady-state formula (queue + workers + readers) would be a hard
// ceiling on how many queries the server can have in flight, and
// throughput would settle at slab-count over resolution latency no
// matter how many clients were asking. That ceiling is what cold
// traffic measures. The plan's burst headroom exists so admission
// outlives the formula.
func TestUDPAdmissionOutlivesTheSteadyState(t *testing.T) {
	// A small, known headroom: the point is admission past the formula,
	// not standing up thousands of blocked requests. The plan is a
	// value, so the test simply builds its own.
	plan := defaultResourcePlan(1)
	plan.udpSpareSlabs = 8

	var inHandler atomic.Int64
	block := make(chan struct{})
	handler := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		inHandler.Add(1)
		<-block
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	})

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	const (
		workers = 1
		queue   = 1
	)
	e := newUDPEngine(handler, []*net.UDPConn{pc}, false, workers, queue, plan)
	steady := int64(queue + workers + udpReaderReserve)
	if e.slabCap != steady+8 {
		t.Fatalf("slab cap = %d, want steady %d plus the headroom 8", e.slabCap, steady)
	}
	e.start()
	defer func() {
		close(block)
		_ = pc.SetReadDeadline(time.Now())
		_ = e.stopAndDrain(time.Now().Add(5 * time.Second))
	}()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Every one of these sticks in the handler, holding its slab the way
	// an upstream resolution would.
	q := new(dns.Msg)
	q.SetQuestion("stuck.example.", dns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for range e.slabCap * 2 {
		if _, err := client.Write(raw); err != nil {
			t.Fatal(err)
		}
	}

	// More queries than the steady-state formula must be in flight at
	// once. UDP on loopback may still lose a datagram under its own
	// buffer, so the bar is between the formula and the cap.
	deadline := time.Now().Add(5 * time.Second)
	for inHandler.Load() <= steady && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := inHandler.Load(); got <= steady {
		t.Fatalf("%d queries in flight with a steady-state formula of %d; "+
			"admission must not be capped at the formula", got, steady)
	}
	// Fetch-add admission may transiently overshoot by the number of
	// concurrent takers — each rolls back before returning — so the
	// at-rest bound only holds with the reader slack added.
	if leased, slack := e.leased.Load(), int64(len(e.pcs)); leased > e.slabCap+slack {
		t.Fatalf("leased %d slabs past the cap %d (+%d reader slack)", leased, e.slabCap, slack)
	}
}

// TestUDPSlabsParkInTheCache pins the ownership loop: allocation on
// demand, reuse from the cache, and an explicit trim that empties it.
func TestUDPSlabsParkInTheCache(t *testing.T) {
	e := newUDPEngine(rawHandlerFunc(func(middleware.Transport, []byte, time.Time) bool { return true }),
		nil, false, 1, 1, defaultResourcePlan(1))

	// Nothing exists until a query needs it.
	if got := e.cache.size(); got != 0 {
		t.Fatalf("a fresh engine parked %d slabs before any query", got)
	}

	j := e.take(0)
	if j == nil {
		t.Fatal("an idle engine refused a lease")
	}
	if got := e.leased.Load(); got != 1 {
		t.Fatalf("leased = %d, want 1", got)
	}

	j.state = udpJobReading
	j.release(udpJobReading)
	if got := e.leased.Load(); got != 0 {
		t.Fatalf("leased = %d after release, want 0", got)
	}
	if got := e.cache.size(); got != 1 {
		t.Fatalf("cache holds %d slabs after release, want the released one", got)
	}

	// The next lease reuses the parked slab rather than allocating.
	j2 := e.take(0)
	if j2 != j {
		t.Fatal("a parked slab was not reused")
	}
	j2.state = udpJobReading
	j2.release(udpJobReading)

	// Trim drops the parked slab; admission is untouched.
	if dropped := e.trimIdle(); dropped != 1 {
		t.Fatalf("trim dropped %d slabs, want 1", dropped)
	}
	if got := e.cache.size(); got != 0 {
		t.Fatalf("cache holds %d slabs after trim", got)
	}
	j3 := e.take(0)
	if j3 == nil {
		t.Fatal("a lease was refused after trim; trim must only cost an allocation")
	}
	j3.state = udpJobReading
	j3.release(udpJobReading)
}
