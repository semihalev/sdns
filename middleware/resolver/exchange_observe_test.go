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

// A server that does not answer must never be scored by how quickly it
// failed to. The exchange reports the elapsed time whatever the outcome,
// and a refused connection comes back in microseconds — faster than any
// authority on earth — so recording it as a latency made the one address
// in the delegation that serves nothing into its permanent leader: ranked
// first, queried first, refused again, and re-recorded as instant.
//
// A stale glue record pointing at a host that is up but not serving DNS
// is all it takes, and the ranking has no way back out on its own.
func TestAServerThatRefusesIsNotTheFastest(t *testing.T) {
	// A closed port on loopback: the write lands, the kernel answers with
	// ICMP port-unreachable, and the read fails in microseconds.
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := packet.LocalAddr().String()
	_ = packet.Close()

	r := &Resolver{cfg: new(config.Config), netTimeout: time.Second}
	server := authority.NewServer(addr, authority.IPv4)
	req := new(dns.Msg)
	req.SetQuestion("refused.example.", dns.TypeA)

	if _, err := r.exchange(context.Background(), &resolveState{}, nil, "udp", req, server, 0); err == nil {
		t.Skip("the platform accepted a query to a closed port; nothing to measure here")
	}

	got := server.SmoothedRTT()
	if got != 0 && got < 500*time.Millisecond {
		t.Fatalf("a server that refused the query is measured at %v — it now leads the delegation", got)
	}
}

// The same rule from the other side: a server that answers is measured by
// what it actually took.
func TestAServerThatAnswersIsMeasuredByItsLatency(t *testing.T) {
	addr := answeringUpstream(t, dns.RcodeSuccess)

	r := &Resolver{cfg: new(config.Config), netTimeout: time.Second}
	server := authority.NewServer(addr, authority.IPv4)
	req := new(dns.Msg)
	req.SetQuestion("answer.example.", dns.TypeA)

	if _, err := r.exchange(context.Background(), &resolveState{}, nil, "udp", req, server, 0); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := server.SmoothedRTT(); got == 0 || got > 100*time.Millisecond {
		t.Fatalf("a loopback answer measured %v", got)
	}
}

// answeringUpstream starts a UDP server that replies to every query with
// the given rcode, and returns its address.
func answeringUpstream(t *testing.T, rcode int) string {
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
			out, packErr := reply.Pack()
			if packErr != nil {
				continue
			}
			_, _ = packet.WriteTo(out, addr)
		}
	}()
	return packet.LocalAddr().String()
}

// A refusal is the fastest answer an authority can give, so scoring it by
// the clock taught the ranking to prefer the servers that turn us away.
// What counts is whether the question was answered — while a negative
// answer is still an answer, and a zone that mostly says no must not cost
// its authorities their standing.
func TestRcodeDecidesWhetherAnAnswerCounts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rcode   int
		counted bool
	}{
		{"refused", dns.RcodeRefused, false},
		{"servfail", dns.RcodeServerFailure, false},
		{"not authoritative", dns.RcodeNotAuth, false},
		{"not implemented", dns.RcodeNotImplemented, false},
		{"format error", dns.RcodeFormatError, false},
		{"not zone", dns.RcodeNotZone, false},
		{"nxdomain", dns.RcodeNameError, true},
		{"noerror", dns.RcodeSuccess, true},
		// RFC 6672 §2.2: a DNAME substitution past 255 octets is answered
		// YXDOMAIN. It reads like an UPDATE prerequisite failure and is not
		// one — the authority answered, and the answer is that the question
		// cannot have one.
		{"yxdomain", dns.RcodeYXDomain, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := answeringUpstream(t, tc.rcode)
			r := &Resolver{cfg: new(config.Config), netTimeout: time.Second}
			server := authority.NewServer(addr, authority.IPv4)
			req := new(dns.Msg)
			req.SetQuestion("rcode.example.", dns.TypeA)

			if _, err := r.exchange(context.Background(), &resolveState{}, nil, "udp", req, server, 0); err != nil {
				t.Fatalf("exchange: %v", err)
			}

			// Counted means "measured by what it took"; the rest are priced
			// at the timeout, which is what not answering is worth.
			fast := server.SmoothedRTT() < 100*time.Millisecond
			if fast != tc.counted {
				t.Fatalf("%s: measured %v, counted as an answer = %v, want %v",
					tc.name, server.SmoothedRTT(), fast, tc.counted)
			}
		})
	}
}
