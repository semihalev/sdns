package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestUDPDrainWaitsForOverflow pins the other half of the shutdown
// barrier.
//
// A query the pool cannot take is served on its own goroutine, that is
// what keeps a miss-heavy resolver from being capped at one query per
// worker. It is still an accepted query, so the drain deadline owes it an
// answer like any other. Joining only the workers let the drain report
// itself finished while such a query was mid-flight, and the caller
// closes the sockets the moment it returns: the reply was written into a
// socket that no longer existed.
func TestUDPDrainWaitsForOverflow(t *testing.T) {
	slow := make(chan struct{})
	held := make(chan struct{})
	entered := make(chan string, 8)

	handler := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		name := r.Question[0].Name
		entered <- name
		switch name {
		case "slow.":
			<-slow
		case "hold.":
			<-held
		}
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

	// One worker and one queue slot, so what lands where is not a guess:
	// the first query occupies the worker, the second fills the queue, the
	// third has nowhere to go but a goroutine of its own.
	e := newUDPEngine(handler, []*net.UDPConn{pc}, false, 1, 1, defaultResourcePlan(1))
	e.start()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	send := func(name string) {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	await := func(want string) {
		t.Helper()
		select {
		case got := <-entered:
			if got != want {
				t.Fatalf("handler entered for %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q never reached the handler", want)
		}
	}

	send("slow.")
	await("slow.") // the worker is now occupied
	send("slow.")  // fills the single queue slot
	send("hold.")  // no room left: served on its own goroutine
	await("hold.")

	// Let the pool finish everything it holds, and wait for the proof,
	// both replies on the wire, so that what the drain is still waiting
	// for below can only be the overflow query.
	close(slow)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	for i := 0; i < 2; i++ {
		if _, err := client.Read(buf); err != nil {
			t.Fatalf("pooled reply %d: %v", i+1, err)
		}
	}
	await("slow.") // the queued one entered the handler on its way through

	// Stop admission exactly as the listener does: an expired read
	// deadline, sockets still open for the replies still owed.
	if err := pc.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	drained := make(chan error, 1)
	go func() { drained <- e.stopAndDrain(time.Now().Add(5 * time.Second)) }()

	select {
	case err := <-drained:
		t.Fatalf("the drain finished (%v) while an accepted query was still "+
			"being served off the pool; the sockets close as soon as it returns",
			err)
	case <-time.After(250 * time.Millisecond):
	}

	close(held)
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain never finished after the overflow query completed")
	}

	// The answer it was waiting for did go out.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("overflow reply: %v", err)
	}
}
