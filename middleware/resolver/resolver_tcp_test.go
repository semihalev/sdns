package resolver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolverTCPPoolIntegration(t *testing.T) {
	// Create a test DNS server
	server := &testDNSServer{
		responses: make(map[string]*dns.Msg),
	}

	// Start test server
	addr, cleanup := startTestDNSServer(t, server)
	defer cleanup()

	// Create resolver with TCP pooling enabled
	cfg := &config.Config{
		TCPKeepalive:      true,
		RootTCPTimeout:    config.Duration{Duration: 2 * time.Second},
		TLDTCPTimeout:     config.Duration{Duration: 3 * time.Second},
		TCPMaxConnections: 10,
		Timeout:           config.Duration{Duration: 5 * time.Second},
		RootServers:       []string{addr},
	}

	r := &Resolver{
		cfg:         cfg,
		netTimeout:  2 * time.Second,
		rootservers: &authcache.AuthServers{},
	}
	r.rootservers.List = append(r.rootservers.List, authcache.NewAuthServer(addr, authcache.IPv4))
	r.tcpPool = NewTCPConnPool(cfg.RootTCPTimeout.Duration, cfg.TLDTCPTimeout.Duration, cfg.TCPMaxConnections)
	defer r.tcpPool.Close()

	// Test 1: First query should create new connection
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	resp, err := r.exchange(context.Background(), "tcp", req, r.rootservers.List[0], 0)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Wait briefly for connection to be returned to pool
	time.Sleep(10 * time.Millisecond)

	// Check pool stats
	hits, misses, active := r.tcpPool.Stats()
	assert.Equal(t, int64(0), hits)
	assert.Equal(t, int64(1), misses) // Get was called but missed
	assert.Equal(t, 1, active)        // Connection should be pooled

	// Test 2: Second query should reuse connection
	resp2, err := r.exchange(context.Background(), "tcp", req, r.rootservers.List[0], 0)
	require.NoError(t, err)
	require.NotNil(t, resp2)

	// Wait for connection to be returned to pool again
	time.Sleep(10 * time.Millisecond)

	// Should have one hit now
	hits, _, active = r.tcpPool.Stats()
	assert.Equal(t, int64(1), hits)
	assert.Equal(t, 1, active) // Connection should still be in pool

	// Verify we made two requests total
	server.mu.Lock()
	reqCount := server.requests
	server.mu.Unlock()
	assert.Equal(t, 2, reqCount)

	// The connection pool should have reused the connection,
	// so we should still have just one active connection
	_, _, active = r.tcpPool.Stats()
	assert.Equal(t, 1, active)
}

func TestResolverTCPPoolConcurrent(t *testing.T) {
	// Create resolver with small pool
	cfg := &config.Config{
		TCPKeepalive:      true,
		TCPMaxConnections: 2,
		Timeout:           config.Duration{Duration: 5 * time.Second},
	}

	r := &Resolver{
		cfg:        cfg,
		netTimeout: 2 * time.Second,
		tcpPool:    NewTCPConnPool(5*time.Second, 10*time.Second, 2),
	}
	defer r.tcpPool.Close()

	// Mock server that delays responses
	server := &testDNSServer{
		responses: make(map[string]*dns.Msg),
		delay:     50 * time.Millisecond,
	}
	addr, cleanup := startTestDNSServer(t, server)
	defer cleanup()

	authServer := authcache.NewAuthServer(addr, authcache.IPv4)

	// Run concurrent queries
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			req := new(dns.Msg)
			req.SetQuestion(".", dns.TypeNS)
			req.Id = uint16(id)

			_, err := r.exchange(context.Background(), "tcp", req, authServer, 0)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		assert.NoError(t, err)
	}

	// Pool should be at max capacity
	_, _, active := r.tcpPool.Stats()
	assert.LessOrEqual(t, active, 2)
}

func TestResolverTCPPoolWithEDNSKeepalive(t *testing.T) {
	// Create test server that responds with EDNS-Keepalive
	server := &testDNSServer{
		responses:        make(map[string]*dns.Msg),
		keepaliveTimeout: 30, // 3 seconds
	}

	addr, cleanup := startTestDNSServer(t, server)
	defer cleanup()

	cfg := &config.Config{
		TCPKeepalive:      true,
		RootTCPTimeout:    config.Duration{Duration: 10 * time.Second},
		TCPMaxConnections: 10,
		Timeout:           config.Duration{Duration: 5 * time.Second},
	}

	r := &Resolver{
		cfg:        cfg,
		netTimeout: 2 * time.Second,
		tcpPool:    NewTCPConnPool(cfg.RootTCPTimeout.Duration, cfg.TLDTCPTimeout.Duration, cfg.TCPMaxConnections),
	}
	defer r.tcpPool.Close()

	authServer := authcache.NewAuthServer(addr, authcache.IPv4)

	// Make query
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	resp, err := r.exchange(context.Background(), "tcp", req, authServer, 0)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check that EDNS-Keepalive was added to request
	assert.NotNil(t, req.IsEdns0())
	hasKeepalive := false
	for _, opt := range req.IsEdns0().Option {
		if _, ok := opt.(*dns.EDNS0_TCP_KEEPALIVE); ok {
			hasKeepalive = true
			break
		}
	}
	assert.True(t, hasKeepalive)

	// Sleep briefly to allow connection to be returned to pool
	time.Sleep(10 * time.Millisecond)

	// Check pool stats instead of direct access
	_, _, active := r.tcpPool.Stats()
	assert.Equal(t, 1, active)
}

// testDNSServer is a mock DNS server for testing.
type testDNSServer struct {
	mu               sync.Mutex
	responses        map[string]*dns.Msg
	requests         int
	delay            time.Duration
	keepaliveTimeout uint16
}

func (s *testDNSServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}

	// Track requests
	s.mu.Lock()
	s.requests++
	s.mu.Unlock()

	// Create response
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &dns.NS{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "a.root-servers.net.",
	})

	// Add EDNS-Keepalive if configured
	if s.keepaliveTimeout > 0 && req.IsEdns0() != nil {
		// Check if client sent keepalive
		for _, opt := range req.IsEdns0().Option {
			if _, ok := opt.(*dns.EDNS0_TCP_KEEPALIVE); ok {
				resp.SetEdns0(4096, false)
				ka := &dns.EDNS0_TCP_KEEPALIVE{
					Code:    dns.EDNS0TCPKEEPALIVE,
					Timeout: s.keepaliveTimeout,
				}
				resp.IsEdns0().Option = append(resp.IsEdns0().Option, ka)
				break
			}
		}
	}

	_ = w.WriteMsg(resp)
}

func startTestDNSServer(t *testing.T, handler dns.Handler) (string, func()) {
	// Start on random port
	pc, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		Net:      "tcp",
		Listener: pc,
		Handler:  handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	return pc.Addr().String(), func() {
		_ = server.Shutdown()
		_ = pc.Close()
	}
}
