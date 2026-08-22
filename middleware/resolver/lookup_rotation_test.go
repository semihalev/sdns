package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
)

// countingUpstream is a loopback authority that records how many queries
// reached it. When answer is false it reads and drops, which is what an
// address slower than the leader looks like from here: the lookup returns
// on the leader's answer and cancels this attempt before it could reply.
func countingUpstream(t *testing.T, answer bool) (string, *atomic.Int64) {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })

	hits := new(atomic.Int64)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, readErr := packet.ReadFrom(buf)
			if readErr != nil {
				return
			}
			hits.Add(1)
			if !answer {
				continue
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 5},
				A: net.IPv4(192, 0, 2, 1),
			})
			out, packErr := reply.Pack()
			if packErr != nil {
				continue
			}
			_, _ = packet.WriteTo(out, addr)
		}
	}()
	return packet.LocalAddr().String(), hits
}

// The shape a delegation actually settles into, which is not the one
// above: the parallel head is two, so two addresses get measured and
// every other address in the zone is left behind the seed. Nothing is
// then level with the second slot, so rotation has nothing to rotate, and
// a TLD's remaining ten or eleven authorities are never contacted again.
//
// Measured on a production resolver running this branch: two of thirteen
// in use for com., net. and org. alike. This is that, in a fixture — two
// authorities answering at similar speeds, eight silent — and it is the
// case the exploration exists for. Without it, all eight take zero
// queries across two hundred lookups.
func TestUnknownsAreExploredOnceTheDelegationHasSettled(t *testing.T) {
	// The lookup count is set by the odds, not by taste: exploration fires
	// on one lookup in thirty-two and then picks among the eight, so this
	// is about fifteen turns each. Enough that a zero is not something
	// this test will ever see by luck.
	const answering, silentCount, lookups = 2, 8, 4000

	servers := &authority.Servers{Zone: "example."}
	for range answering {
		addr, _ := countingUpstream(t, true)
		servers.List = append(servers.List, authority.NewServer(addr, authority.IPv4))
	}
	silent := make(map[string]*atomic.Int64, silentCount)
	for range silentCount {
		addr, hits := countingUpstream(t, false)
		silent[addr] = hits
		servers.List = append(servers.List, authority.NewServer(addr, authority.IPv4))
	}

	cfg := &config.Config{
		RootServers:          []string{"198.41.0.4:53"},
		Timeout:              config.Duration{Duration: 2 * time.Second},
		MaxConcurrentQueries: 100,
	}
	r := newWiredTestResolver(cfg)
	req := new(dns.Msg)
	req.SetQuestion("settled.example.", dns.TypeA)

	runLookup := func() {
		t.Helper()
		if _, err := r.lookup(context.Background(), &resolveState{requestID: req.Id}, req, servers); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}

	// Let it settle the way production settles, then measure from there.
	for range 20 {
		runLookup()
	}
	measured := 0
	for _, s := range servers.List {
		if s.SmoothedRTT() != 0 {
			measured++
		}
	}
	if measured != answering {
		t.Fatalf("the delegation settled on %d measured addresses, want the %d that answer", measured, answering)
	}
	for _, hits := range silent {
		hits.Store(0)
	}

	for range lookups {
		runLookup()
	}

	untried, counts := 0, make([]int64, 0, silentCount)
	for _, hits := range silent {
		got := hits.Load()
		counts = append(counts, got)
		if got == 0 {
			untried++
		}
	}
	t.Logf("exploration queries across %d unmeasured addresses in %d lookups: %v",
		silentCount, lookups, counts)
	if untried > 0 {
		t.Fatalf("%d of %d addresses behind a settled delegation were never explored: %v",
			untried, silentCount, counts)
	}
}

// The ranking's decision has to reach the wire, and this is the shape it
// reaches it in: a delegation of ten addresses where one answers and the
// rest are unmeasured. The resolver starts the top two of every lookup in
// parallel, so each miss sends exactly one query to an unmeasured address
// — and that query is cancelled the moment the leader answers, so the
// address never comes back measured and stays tied with its peers.
//
// Which is the whole point. Nine addresses sharing one price is nine
// addresses the ranking has no reason to choose between, and the sort's
// stability chose the same one anyway: it took every one of those queries
// and the other eight were never contacted at all, for the life of the
// process. This drives real lookups against real sockets and counts what
// each address actually received.
func TestEveryUnmeasuredAuthorityIsEventuallyQueried(t *testing.T) {
	const unmeasured = 9
	const lookups = 200

	leaderAddr, leaderHits := countingUpstream(t, true)

	servers := &authority.Servers{Zone: "example."}
	silent := make(map[string]*atomic.Int64, unmeasured)
	for range unmeasured {
		addr, hits := countingUpstream(t, false)
		silent[addr] = hits
		servers.List = append(servers.List, authority.NewServer(addr, authority.IPv4))
	}
	// The leader goes in last, so the order it ends up in is the ranking's
	// doing rather than the order it was handed.
	servers.List = append(servers.List, authority.NewServer(leaderAddr, authority.IPv4))

	cfg := &config.Config{
		// Roots this test never reaches, but a resolver built without any
		// treats an empty list as a fatal misconfiguration and takes the
		// process down with it.
		RootServers:          []string{"198.41.0.4:53"},
		Timeout:              config.Duration{Duration: 2 * time.Second},
		MaxConcurrentQueries: 100,
	}
	r := newWiredTestResolver(cfg)

	req := new(dns.Msg)
	req.SetQuestion("rotate.example.", dns.TypeA)

	runLookup := func() {
		t.Helper()
		resp, err := r.lookup(context.Background(), &resolveState{requestID: req.Id}, req, servers)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if resp == nil || len(resp.Answer) == 0 {
			t.Fatal("lookup returned no answer")
		}
	}

	// One lookup to establish a leader. On the first one nothing is
	// measured, so the whole delegation is tied and the resolver walks
	// down it until something answers — which contacts every address once
	// and says nothing about how the slot behind the leader is chosen.
	runLookup()
	for _, hits := range silent {
		hits.Store(0)
	}
	leaderHits.Store(0)

	for range lookups {
		runLookup()
	}

	// The measured server leads every lookup, so it takes one query each.
	if got := leaderHits.Load(); got < lookups {
		t.Fatalf("the measured leader received %d of %d lookups", got, lookups)
	}

	// And the second slot has to have reached all of its equals. Without
	// rotation exactly one of these is at ~200 and the other eight are at
	// zero.
	untried := 0
	counts := make([]int64, 0, unmeasured)
	for _, hits := range silent {
		got := hits.Load()
		counts = append(counts, got)
		if got == 0 {
			untried++
		}
	}
	t.Logf("second-slot queries across %d unmeasured addresses: %v", unmeasured, counts)
	if untried > 0 {
		t.Fatalf("%d of %d unmeasured addresses were never queried across %d lookups: %v",
			untried, unmeasured, lookups, counts)
	}

	// None of them may be measured either — every one of those attempts
	// was cancelled when the leader answered, and what an attempt took to
	// be cancelled is not what the server is worth.
	for _, s := range servers.List {
		if s.Addr == leaderAddr {
			continue
		}
		if got := s.SmoothedRTT(); got != 0 {
			t.Fatalf("a cancelled attempt measured %s at %v", s.Addr, got)
		}
	}
}
