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

// A retry recurses into exchange, so the frame that failed returns after
// the frame that succeeded. Recording each attempt on the way out
// therefore delivered them backwards: the retry's success landed first and
// the earlier failure overwrote it, leaving a server that had just
// answered marked as failing — and carrying the ranking penalty that goes
// with it for as long as it took to work the mark off.
func TestSuccessfulRetryLeavesNoFailureMark(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	// An upstream that swallows the first query and answers the second.
	go func() {
		buf := make([]byte, 1024)
		for attempt := 0; ; attempt++ {
			n, addr, readErr := packet.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if attempt == 0 {
				continue
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			reply := new(dns.Msg)
			reply.SetReply(req)
			out, packErr := reply.Pack()
			if packErr != nil {
				continue
			}
			_, _ = packet.WriteTo(out, addr)
		}
	}()

	r := &Resolver{
		cfg:        new(config.Config),
		netTimeout: 200 * time.Millisecond,
	}
	server := authority.NewServer(packet.LocalAddr().String(), authority.IPv4)
	req := new(dns.Msg)
	req.SetQuestion("retry.example.", dns.TypeA)

	resp, err := r.exchange(context.Background(), &resolveState{}, nil, "udp", req, server, 0)
	if err != nil {
		t.Fatalf("the retry never succeeded: %v", err)
	}
	if resp == nil {
		t.Fatal("the retry returned no response")
	}
	if got := server.Fails(); got != 0 {
		t.Fatalf("a server that answered is marked with %d failures", got)
	}
	// Both attempts are still on the record — the failure happened, and
	// the latency it cost is part of what this server is worth.
	if got := server.Samples(); got != 2 {
		t.Fatalf("attempts recorded = %d, want the failure and the success", got)
	}
}

// The fallbacks hand a query to another exchange rather than return, and
// that one recurses — so the frame that answered returns last. Leaving
// its outcome to the defer wrote a success after the failure the fallback
// had just found, which cleared the failure counter and left an authority
// that had stopped answering over TCP looking freshly healthy.
func TestFallbackFailureSurvivesTheAnswerBeforeIt(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	// The same address over TCP: accepted, then silence. The fallback
	// gets a connection and no answer, which is the failure under test.
	stream, err := net.Listen("tcp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			conn, acceptErr := stream.Accept()
			if acceptErr != nil {
				return
			}
			held = append(held, conn)
		}
	}()

	// Over UDP the server answers, truncated — the referral to TCP.
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
			reply.Truncated = true
			out, packErr := reply.Pack()
			if packErr != nil {
				continue
			}
			_, _ = packet.WriteTo(out, addr)
		}
	}()

	r := &Resolver{
		cfg:        new(config.Config),
		netTimeout: 150 * time.Millisecond,
	}
	server := authority.NewServer(packet.LocalAddr().String(), authority.IPv4)
	req := new(dns.Msg)
	req.SetQuestion("fallback.example.", dns.TypeA)

	if _, err := r.exchange(context.Background(), &resolveState{}, nil, "udp", req, server, 0); err == nil {
		t.Fatal("the silent TCP fallback returned success")
	}
	if got := server.Fails(); got == 0 {
		t.Fatal("the TCP failure was erased by the truncated answer that preceded it")
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

// A refusal is the fastest answer an authority can give, so scoring it as
// health taught the ranking to prefer the servers that refuse us. What
// counts is whether the question was answered, not how quickly something
// came back — while a negative answer is still an answer, and a zone that
// mostly says no must not cost its authorities their standing.
func TestRcodeDecidesWhetherAnAnswerCounts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rcode    int
		wantFail bool
	}{
		{"refused", dns.RcodeRefused, true},
		{"servfail", dns.RcodeServerFailure, true},
		{"not authoritative", dns.RcodeNotAuth, true},
		{"not implemented", dns.RcodeNotImplemented, true},
		{"format error", dns.RcodeFormatError, true},
		{"not zone", dns.RcodeNotZone, true},
		{"nxdomain", dns.RcodeNameError, false},
		{"noerror", dns.RcodeSuccess, false},
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
			if got := server.Fails() > 0; got != tc.wantFail {
				t.Fatalf("%s: server marked failing = %v, want %v", tc.name, got, tc.wantFail)
			}
		})
	}
}
