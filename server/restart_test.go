package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
)

// TestStoppedMeansTheAddressIsFree pins what Stopped() is used for.
//
// sdns.go polls it to decide that a shutdown is complete. The only thing
// that decision is ever used for is doing something else with the
// resources the server held — above all, binding the same address again.
// If Stopped() can be true while a socket is still open, an in-process
// restart fails on "address already in use", and it fails intermittently,
// which is the worst way for it to fail.
func TestStoppedMeansTheAddressIsFree(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := new(config.Config)
	cfg.Bind = addr
	cfg.QueryTimeout.Duration = time.Second

	for i := range 25 {
		srv := New(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		if err := srv.Run(ctx); err != nil {
			cancel()
			t.Fatalf("restart %d: %v", i, err)
		}

		deadline := time.Now().Add(2 * time.Second)
		for !srv.HasListener("udp") || !srv.HasListener("tcp") {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("restart %d: listeners never came up", i)
			}
			time.Sleep(time.Millisecond)
		}

		cancel()
		deadline = time.Now().Add(5 * time.Second)
		for !srv.Stopped() {
			if time.Now().After(deadline) {
				t.Fatalf("restart %d: never reported stopped", i)
			}
			time.Sleep(time.Millisecond)
		}
		srv.Stop()
	}
}

// TestStoppedIsNotAheadOfTheSockets is the same property stated directly:
// the moment the server calls itself stopped, both of its addresses must
// be bindable by somebody else.
func TestStoppedIsNotAheadOfTheSockets(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := new(config.Config)
	cfg.Bind = addr
	cfg.QueryTimeout.Duration = time.Second

	for i := range 25 {
		srv := New(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		if err := srv.Run(ctx); err != nil {
			cancel()
			t.Fatalf("round %d: %v", i, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for !srv.HasListener("udp") || !srv.HasListener("tcp") {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("round %d: listeners never came up", i)
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		for !srv.Stopped() {
			time.Sleep(time.Millisecond)
		}
		srv.Stop()

		// Stopped() has just said the server is done with them.
		var held []string
		if pc, err := net.ListenPacket("udp", addr); err != nil {
			held = append(held, fmt.Sprintf("udp: %v", err))
		} else {
			_ = pc.Close()
		}
		if ln, err := net.Listen("tcp", addr); err != nil {
			held = append(held, fmt.Sprintf("tcp: %v", err))
		} else {
			_ = ln.Close()
		}
		if len(held) > 0 {
			t.Fatalf("round %d: the server reported stopped while it still held "+
				"%s — an in-process restart binds these next", i, strings.Join(held, ", "))
		}
	}
}
