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
	if got := server.Count; got != 2 {
		t.Fatalf("attempts recorded = %d, want the failure and the success", got)
	}
}
