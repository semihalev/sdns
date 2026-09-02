package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/dnsutil"
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

// probeResolver builds the minimum queryServer needs, with room for the
// given number of probes.
func probeResolver(probeCap int) *Resolver {
	return &Resolver{
		cfg:            new(config.Config),
		netTimeout:     time.Second,
		circuitBreaker: newCircuitBreaker(),
		maxConcurrent:  make(chan struct{}, 1),
		probeSlots:     make(chan struct{}, probeCap),
	}
}

// runAttempt drives one upstream attempt the way lookup does, and cancels
// the moment a leader would have answered.
func runAttempt(t *testing.T, r *Resolver, server *authority.Server, probing bool, leaderAnswersIn time.Duration) {
	t.Helper()
	runAttemptWith(t, r, server, probing, leaderAnswersIn, false)
}

// runAttemptWith is runAttempt with a say in whether the query carries
// EDNS, which is what decides whether a FORMERR reaches the fallback that
// strips it.
func runAttemptWith(t *testing.T, r *Resolver, server *authority.Server, probing bool, leaderAnswersIn time.Duration, edns bool) {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion("probe.example.", dns.TypeA)
	if edns {
		req.SetEdns0(dnsutil.DefaultMsgSize, false)
	}

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

// Exploring is worth only what it brings back, and until now it brought
// back nothing. The ranking picked an address whose worth was out of
// date, the resolver sent it the second query, the leader answered first,
// as it must, being the fastest server in the list, and the lookup
// returned and cancelled it before it could reply. So an address was only
// ever measured by winning the race outright, which on a production
// delegation meant one new address a minute with seventeen waiting, and
// the ones slower than the leader waiting forever.
func TestAProbeOutlivesTheWinnerAndBringsBackAMeasurement(t *testing.T) {
	addr := slowUpstream(t, 120*time.Millisecond)

	// What the field showed: the leader answers in a few milliseconds
	// while the probed address is an order of magnitude further away.
	const leaderAnswersIn = 10 * time.Millisecond

	t.Run("as an ordinary hedge it learns nothing", func(t *testing.T) {
		server := authority.NewServer(addr, authority.IPv4)
		runAttempt(t, probeResolver(1), server, false, leaderAnswersIn)

		if got := server.SmoothedRTT(); got != 0 {
			t.Fatalf("a cancelled hedge measured %v", got)
		}
	})

	t.Run("as a probe it comes back with the latency", func(t *testing.T) {
		server := authority.NewServer(addr, authority.IPv4)
		runAttempt(t, probeResolver(1), server, true, leaderAnswersIn)

		got := server.SmoothedRTT()
		if got < 100*time.Millisecond {
			t.Fatalf("the probe measured %v, want the upstream's real latency", got)
		}
		if !server.Answering() {
			t.Fatal("a server that answered the probe is marked as failing")
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

	if got := server.SmoothedRTT(); got != 0 {
		t.Fatalf("a shed probe measured %v, it outlived its lookup without a slot", got)
	}
}

// rcodeUpstream answers every query with the given rcode, optionally
// truncated, and reports its address.
func rcodeUpstream(t *testing.T, rcode int, truncated bool) string {
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
			reply.SetRcode(req, rcode)
			reply.Truncated = truncated
			out, packErr := reply.Pack()
			if packErr != nil {
				continue
			}
			_, _ = packet.WriteTo(out, addr)
		}
	}()
	return packet.LocalAddr().String()
}

// A probe stops before the fallbacks, so whatever it leaves behind is the
// whole record of that address until the next one. Leaving nothing is the
// case to watch: the address stays exactly as out of date as it was, so
// it is a candidate again, so it is probed again, and the loop has no end
// while the server keeps giving the same reply.
//
// FORMERR is where that bites. The lookup path answers it by asking again
// without EDNS and prices the first attempt at nothing, which is right
// there and wrong here.
func TestAProbeAlwaysLeavesAMeasurement(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rcode     int
		truncated bool
		fast      bool
	}{
		// It answered, and the answer says to come back over TCP. What the
		// probe measured is the round trip it made.
		{"truncated", dns.RcodeSuccess, true, true},
		// It answered, and the answer says it dislikes our EDNS. Also a
		// round trip, and not the authority's failing.
		{"format error", dns.RcodeFormatError, false, true},
		// It did not answer the question, and no fallback would have
		// helped. That is worth a timeout.
		{"refused", dns.RcodeRefused, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := rcodeUpstream(t, tc.rcode, tc.truncated)
			server := authority.NewServer(addr, authority.IPv4)
			// With EDNS on the query, so a FORMERR reaches the fallback
			// that would otherwise strip it and ask again.
			runAttemptWith(t, probeResolver(1), server, true, 10*time.Millisecond, true)

			got := server.SmoothedRTT()
			if got == 0 {
				t.Fatal("the probe recorded nothing; this address will be probed again forever")
			}
			if fast := got < 100*time.Millisecond; fast != tc.fast {
				t.Fatalf("%s measured %v, which reads as %s", tc.name, got,
					map[bool]string{true: "a prompt answer", false: "a timeout"}[fast])
			}
		})
	}
}

// A probe to something silent has to end as a failure rather than as a
// cancellation, which is what the grace on its deadline buys: the socket
// deadline fires first, so the address is recorded as not answering
// instead of leaving no trace at all.
func TestAProbeToASilentServerRecordsTheFailure(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, _, readErr := packet.ReadFrom(buf); readErr != nil {
				return
			}
		}
	}()

	r := probeResolver(1)
	r.netTimeout = 150 * time.Millisecond
	server := authority.NewServer(packet.LocalAddr().String(), authority.IPv4)
	runAttempt(t, r, server, true, 10*time.Millisecond)

	if server.Answering() {
		t.Fatal("a server that never replied to the probe is not marked as failing")
	}
	if got := server.SmoothedRTT(); got == 0 {
		t.Fatal("a probe that timed out recorded nothing at all")
	}
}
