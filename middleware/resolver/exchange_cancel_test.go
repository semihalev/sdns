package resolver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
)

func TestExchangeCancellationInterruptsInFlightUDPRead(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	received := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		_, _, readErr := packet.ReadFrom(buf)
		if readErr == nil {
			close(received)
		}
	}()

	r := &Resolver{
		cfg:        new(config.Config),
		netTimeout: 5 * time.Second,
	}
	server := authority.NewServer(packet.LocalAddr().String(), authority.IPv4)
	req := new(dns.Msg)
	req.SetQuestion("cancel.example.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, exchangeErr := r.exchange(ctx, &resolveState{}, nil, "udp", req, server, 0)
		result <- exchangeErr
	}()

	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive the in-flight resolver query")
	}
	cancel()
	select {
	case exchangeErr := <-result:
		if !errors.Is(exchangeErr, context.Canceled) {
			t.Fatalf("exchange error = %v, want context.Canceled", exchangeErr)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("resolver UDP read ignored context cancellation")
	}
	// A cancellation is not the authority's fault, but it is not nothing
	// either: the server was still silent when the caller gave up, and
	// that lower bound is what the ranking records. Discarding it was how
	// a server that never wins a race stayed unmeasured — and unmeasured
	// used to rank ahead of every server that had answered.
	if got := atomic.LoadInt64(&server.Count); got != 1 {
		t.Fatalf("canceled exchange recorded %d samples, want the lower bound", got)
	}
	if got := server.Fails(); got != 0 {
		t.Fatalf("canceled exchange counted %d failures against the server", got)
	}
}

// TestExchangeCancellationInterruptsThroughGroup covers the same in-flight
// interruption through the lookup's shared InterruptGroup instead of the
// per-exchange fallback registration.
func TestExchangeCancellationInterruptsThroughGroup(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	received := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		_, _, readErr := packet.ReadFrom(buf)
		if readErr == nil {
			close(received)
		}
	}()

	r := &Resolver{
		cfg:        new(config.Config),
		netTimeout: 5 * time.Second,
	}
	server := authority.NewServer(packet.LocalAddr().String(), authority.IPv4)
	req := new(dns.Msg)
	req.SetQuestion("cancel-group.example.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	interrupts := NewInterruptGroup(ctx)
	defer interrupts.Close()
	result := make(chan error, 1)
	go func() {
		_, exchangeErr := r.exchange(ctx, &resolveState{}, interrupts, "udp", req, server, 0)
		result <- exchangeErr
	}()

	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive the in-flight resolver query")
	}
	cancel()
	select {
	case exchangeErr := <-result:
		if !errors.Is(exchangeErr, context.Canceled) {
			t.Fatalf("exchange error = %v, want context.Canceled", exchangeErr)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("group-armed resolver UDP read ignored context cancellation")
	}
	// A cancellation is not the authority's fault, but it is not nothing
	// either: the server was still silent when the caller gave up, and
	// that lower bound is what the ranking records. Discarding it was how
	// a server that never wins a race stayed unmeasured — and unmeasured
	// used to rank ahead of every server that had answered.
	if got := atomic.LoadInt64(&server.Count); got != 1 {
		t.Fatalf("canceled exchange recorded %d samples, want the lower bound", got)
	}
	if got := server.Fails(); got != 0 {
		t.Fatalf("canceled exchange counted %d failures against the server", got)
	}
}
