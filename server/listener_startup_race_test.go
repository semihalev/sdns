package server

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestListenerServeShutdownRace drives Serve and Shutdown at each other
// with no ordering between them, the state a process asked to stop
// while it is still coming up is in, and the one macOS CI found.
//
// The accept barrier is a WaitGroup, and an Add that races its own Wait
// is a race whether or not the counter happens to be at zero. At zero it
// is also worse than a warning: the drain waits on an empty barrier,
// decides the accept loop is finished, and closes the sockets under a
// loop that is still admitting connections.
func TestListenerServeShutdownRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		tcp := newTCPListener("127.0.0.1:0", echoHandler(), time.Second, 8, defaultResourcePlan(1))
		if err := tcp.Bind(context.Background()); err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- tcp.Serve(context.Background()) }()
		go func() { _ = tcp.Shutdown(context.Background()) }()
		select {
		case err := <-served:
			if err != nil {
				t.Fatalf("serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("Serve did not return after a concurrent Shutdown")
		}
	}
}

// The same for the engine directly: a listener that starts accepting
// after the drain has begun must be refused rather than joined, because
// the barrier it would join is already being waited on.
func TestAcceptRefusedAfterShutdown(t *testing.T) {
	e := newTCPEngine(echoHandler(), "tcp", 8, defaultResourcePlan(1))
	if err := e.shutdown(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if e.startAccepting(ln, func() {}) {
		t.Fatal("the engine joined an accept loop to a barrier it had already waited on")
	}
	// Refusing means closing: the caller handed the listener over.
	if _, err := ln.Accept(); err == nil {
		t.Fatal("a refused listener was left open")
	}
}
