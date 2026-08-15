package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestUDPRingStretchesPastItself pins what the ring is and is not.
//
// A slab is held for the whole request. On a hit that is microseconds and
// the ring is never short — but a miss holds one for an upstream
// resolution, so a ring that could not stretch would be a hard ceiling on
// how many queries the server can have in flight, and throughput would
// settle at ring size over resolution latency no matter how many clients
// were asking. That ceiling is what cold traffic measures.
func TestUDPRingStretchesPastItself(t *testing.T) {
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
	e := newUDPEngine(handler, []*net.UDPConn{pc}, false, workers, queue)
	ring := cap(e.free)
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

	// Every one of these is stuck in the handler, so each holds its slab
	// for as long as the test wants it to — an upstream resolution, in
	// miniature.
	want := ring * 2
	q := new(dns.Msg)
	q.SetQuestion("stuck.example.", dns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < want; i++ {
		if _, err := client.Write(raw); err != nil {
			t.Fatal(err)
		}
	}

	// More than the ring holds must be in flight at once. UDP on loopback
	// may still lose a datagram under its own buffer, so the bar is above
	// the ring rather than at everything sent.
	target := int64(ring + ring/2)
	deadline := time.Now().Add(5 * time.Second)
	for inHandler.Load() < target && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := inHandler.Load(); got < target {
		t.Fatalf("%d queries in flight with a ring of %d; the ring sizes the "+
			"steady state, it does not cap how many queries may be resolving "+
			"at once", got, ring)
	}
	if borrowed := e.borrowed.Load(); borrowed == 0 {
		t.Fatal("nothing was borrowed, so the ring cannot have been the thing that ran out")
	}
}

// TestUDPSpareSlabsReturnToThePool pins the other half: the stretch is
// borrowed, not kept. A spare that stayed out would turn a single burst
// into a permanent resident set.
func TestUDPSpareSlabsReturnToThePool(t *testing.T) {
	e := newUDPEngine(rawHandlerFunc(func(middleware.Transport, []byte, time.Time) bool { return true }),
		nil, false, 1, 1)

	held := make([]*udpJob, 0, cap(e.free))
	for len(e.free) > 0 {
		held = append(held, <-e.free)
	}

	j := e.take()
	if j == nil {
		t.Fatal("an empty ring with the stretch untouched handed out nothing")
	}
	if !j.spare {
		t.Fatal("an empty ring handed out a ring slab")
	}
	if got := e.borrowed.Load(); got != 1 {
		t.Fatalf("borrowed = %d, want 1", got)
	}

	j.state = udpJobReading
	j.release(udpJobReading)
	if got := e.borrowed.Load(); got != 0 {
		t.Fatalf("borrowed = %d after release, want 0; a spare that is never "+
			"given back is a leak the bound cannot see", got)
	}
	if len(e.free) != 0 {
		t.Fatal("a spare went back into the ring, which would grow it past its size")
	}

	for _, j := range held {
		e.free <- j
	}
}
