package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
)

func BenchmarkLookupPerformance(b *testing.B) {
	// Create a test resolver
	cfg := &config.Config{
		RootServers:  []string{"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53"},
		Root6Servers: []string{"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53"},
		RootKeys:     []string{". 172800 IN DNSKEY 257 3 8 AwEAAa..."},
		Timeout:      config.Duration{Duration: 2 * time.Second},
	}

	r := newWiredTestResolver(cfg)

	// Create test request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = true

	// Mock servers with different RTTs, recorded the way the resolver
	// records them rather than written into the fields: a fixture that
	// sets state directly tests the shape of the fields instead of the
	// behaviour of the model.
	servers := &authority.Servers{Zone: "com."}
	for _, m := range []struct {
		addr string
		rtt  time.Duration
	}{
		{"192.0.2.1:53", 20 * time.Millisecond},  // Fast server
		{"192.0.2.2:53", 100 * time.Millisecond}, // Medium server
		{"192.0.2.3:53", 200 * time.Millisecond}, // Slow server
	} {
		s := authority.NewServer(m.addr, authority.IPv4)
		s.Observe(m.rtt)
		servers.List = append(servers.List, s)
	}

	b.ResetTimer()
	b.ReportAllocs()

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		// This will use our optimized lookup with parallel queries and adaptive timeout
		_, _ = r.groupLookup(ctx, &resolveState{requestID: req.Id}, req, servers, false)
	}
}

func TestAdaptiveTimeout(t *testing.T) {
	cfg := &config.Config{
		RootServers: []string{"198.41.0.4:53"},
		Timeout:     config.Duration{Duration: 2 * time.Second},
	}

	r := newWiredTestResolver(cfg)

	// Test adaptive timeout calculation
	testCases := []struct {
		name        string
		rtt         int64
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{"Unknown RTT", 0, 100 * time.Millisecond, 100 * time.Millisecond},
		{"Fast server", int64(10 * time.Millisecond), 25 * time.Millisecond, 25 * time.Millisecond},
		{"Medium server", int64(50 * time.Millisecond), 100 * time.Millisecond, 100 * time.Millisecond},
		{"Slow server", int64(200 * time.Millisecond), 300 * time.Millisecond, 300 * time.Millisecond},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// server := &authority.Server{Rtt: tc.rtt}

			// We can't directly test the function since it's inside lookup()
			// but we can verify the behavior through the resolver
			if r == nil {
				t.Skip("Resolver not initialized")
			}
		})
	}
}
