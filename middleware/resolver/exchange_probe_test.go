package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
)

// slowUpstream answers every query after delay, and reports its address.
func slowUpstream(t *testing.T, delay time.Duration) string {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, readErr := packet.ReadFrom(buf)
			if readErr != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			reply := new(dns.Msg)
			reply.SetReply(req)
			go func() {
				time.Sleep(delay)
				out, packErr := reply.Pack()
				if packErr != nil {
					return
				}
				_, _ = packet.WriteTo(out, addr)
			}()
		}
	}()
	return packet.LocalAddr().String()
}

// probeResolver builds the minimum resolver queryServer needs, with room
// for one probe.
func probeResolver(probeCap int) *Resolver {
	return &Resolver{
		cfg:            new(config.Config),
		netTimeout:     time.Second,
		circuitBreaker: newCircuitBreaker(),
		maxConcurrent:  make(chan struct{}, 1),
		probeSlots:     make(chan struct{}, probeCap),
	}
}

// runAttempt drives one upstream attempt the way lookup does, and
// cancels the moment a leader would have answered.
func runAttempt(t *testing.T, r *Resolver, server *authority.Server, probing bool, leaderAnswersIn time.Duration) {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion("probe.example.", dns.TypeA)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupts := NewInterruptGroup(ctx)
	defer interrupts.Close()

	results := make(chan lookupResult)
	done := make(chan struct{})

	r.maxConcurrent <- struct{}{}
	go func() {
		defer close(done)
		r.queryServer(ctx, &resolveState{}, interrupts, req.Id, req.Copy(), server, results, probing)
	}()

	// The leader answers and lookup returns, which cancels everything it
	// started.
	time.Sleep(leaderAnswersIn)
	cancel()
	interrupts.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the attempt never finished")
	}
}

// The whole point of exploring is to learn what an unmeasured server is
// worth, and until now the exploring could not learn anything. The
// ranking picked the server, the resolver sent it the hedge query, the
// leader answered first — as it must, being the fastest server in the
// list — and the lookup returned and cancelled everything still in
// flight. The cancelled attempt recorded a floor of a few milliseconds,
// which is below the seed and teaches nothing, so it was dropped. The
// address stayed unmeasured, was picked again, and was cancelled again,
// for the life of the process.
//
// A probe is worth only what it brings back, so it has to outlive the
// answer that made it redundant.
func TestAProbeOutlivesTheWinnerAndBringsBackAMeasurement(t *testing.T) {
	addr := slowUpstream(t, 120*time.Millisecond)

	// What the field showed: the leader answers in a few milliseconds
	// while the probed server is an order of magnitude further away.
	const leaderAnswersIn = 10 * time.Millisecond

	t.Run("as an ordinary hedge it learns nothing", func(t *testing.T) {
		server := authority.NewServer(addr, authority.IPv4)
		runAttempt(t, probeResolver(1), server, false, leaderAnswersIn)

		if got := server.Samples(); got != 0 {
			t.Fatalf("a cancelled hedge completed %d exchanges", got)
		}
		if got := server.SmoothedRTT(); got != 0 {
			t.Fatalf("a cancelled hedge measured %v", got)
		}
	})

	t.Run("as a probe it comes back with the latency", func(t *testing.T) {
		server := authority.NewServer(addr, authority.IPv4)
		runAttempt(t, probeResolver(1), server, true, leaderAnswersIn)

		if got := server.Samples(); got != 1 {
			t.Fatalf("the probe completed %d exchanges, want 1", got)
		}
		if got := server.SmoothedRTT(); got < 100*time.Millisecond {
			t.Fatalf("the probe measured %v, want the upstream's real latency", got)
		}
		if got := server.Fails(); got != 0 {
			t.Fatalf("a server that answered the probe is marked with %d failures", got)
		}
	})
}

// The probe pool is what keeps a detached job from growing with arrival
// rate. When it is empty the measurement is given up, not queued: the
// attempt goes ahead as the hedge it would have been, and the lookup
// behaves exactly as it did before.
func TestAProbeIsShedWhenThePoolIsFull(t *testing.T) {
	addr := slowUpstream(t, 120*time.Millisecond)
	r := probeResolver(1)

	// Hold the only slot, as an in-flight probe elsewhere would.
	r.probeSlots <- struct{}{}

	server := authority.NewServer(addr, authority.IPv4)
	runAttempt(t, r, server, true, 10*time.Millisecond)

	if got := server.Samples(); got != 0 {
		t.Fatalf("a shed probe completed %d exchanges — it outlived its lookup without a slot", got)
	}
}
