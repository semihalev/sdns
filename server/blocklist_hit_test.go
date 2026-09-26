package server

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/zlog/v2"
)

// hitServerWithBlocklist is the hit-path server with a loaded blocklist: n
// generated entries, none of which the probe name falls under.
func hitServerWithBlocklist(tb testing.TB, n int) *Server {
	tb.Helper()
	s := newHitChainServer(tb)
	logger := zlog.NewStructured()
	logger.SetWriter(io.Discard)
	zlog.SetDefault(logger)
	bl, ok := middleware.Get("blocklist").(*blocklist.BlockList)
	if !ok {
		tb.Fatal("no blocklist in the hit-path chain")
	}
	keys := make([]string, 0, n)
	for i := range n {
		keys = append(keys, fmt.Sprintf("ads%d.tracker%d.example.", i, i%97))
	}
	bl.SetBatch(keys)
	return s
}

func warmHitQuery(tb testing.TB, s *Server, name string) (*strictTestJob, []byte) {
	tb.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.SetEdns0(1232, true)
	raw, err := m.Pack()
	if err != nil {
		tb.Fatal(err)
	}
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 60), Port: 4242}}
	for range 2 {
		if !s.ServeRaw(job, raw, time.Now()) {
			tb.Fatal("warm serve not handled")
		}
	}
	return job, raw
}

// A loaded blocklist must not take a cache hit off the byte path: a name
// it does not hold is looked up from the wire and passed on undecoded, and
// the hit costs what it costs without a blocklist, nothing.
func TestServeRawHitWithBlocklistAllocatesNothing(t *testing.T) {
	s := hitServerWithBlocklist(t, 1000)
	job, raw := warmHitQuery(t, s, "clean.zero.test.")
	if allocs := leastAllocsPerRun(200, func() {
		if !s.ServeRaw(job, raw, time.Now()) {
			t.Fatal("hit serve not handled")
		}
	}); allocs != 0 {
		t.Fatalf("a warm hit with a loaded blocklist allocated %.2f objects per serve; the contract is none", allocs)
	}
}

// BenchmarkServeRawHitWithBlocklist is a cache hit through the whole chain
// with 100k blocklist entries loaded, the name not among them.
func BenchmarkServeRawHitWithBlocklist(b *testing.B) {
	s := hitServerWithBlocklist(b, 100000)
	job, raw := warmHitQuery(b, s, "clean.bench.test.")
	b.ReportAllocs()
	for b.Loop() {
		s.ServeRaw(job, raw, time.Now())
	}
}
