package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestNewTCPConnPool(t *testing.T) {
	// Test with defaults
	pool := NewTCPConnPool(0, 0, 0)
	assert.NotNil(t, pool)
	assert.Equal(t, 5*time.Second, pool.rootTimeout)
	assert.Equal(t, 10*time.Second, pool.tldTimeout)
	assert.Equal(t, 100, pool.maxConns)

	// Test with custom values
	pool2 := NewTCPConnPool(3*time.Second, 7*time.Second, 50)
	assert.Equal(t, 3*time.Second, pool2.rootTimeout)
	assert.Equal(t, 7*time.Second, pool2.tldTimeout)
	assert.Equal(t, 50, pool2.maxConns)

	// Clean up
	pool.Close()
	pool2.Close()
}

func TestTCPConnPoolGetPut(t *testing.T) {
	pool := NewTCPConnPool(5*time.Second, 10*time.Second, 10)
	defer pool.Close()

	// Test getting from empty pool
	conn := pool.Get("192.5.5.241:53", true, false)
	assert.Nil(t, conn)

	// Test stats for miss
	hits, misses, active := pool.Stats()
	assert.Equal(t, int64(0), hits)
	assert.Equal(t, int64(1), misses)
	assert.Equal(t, 0, active)

	// Create a mock connection
	mockConn := &mockNetConn{remoteAddr: "192.5.5.241:53"}
	dnsConn := &dns.Conn{Conn: mockConn}

	// Put connection for root server
	pool.Put(dnsConn, "192.5.5.241:53", true, false, nil)

	// Check active connections
	_, _, active = pool.Stats()
	assert.Equal(t, 1, active)

	// Get the connection back
	conn = pool.Get("192.5.5.241:53", true, false)
	assert.NotNil(t, conn)

	// Check hit stats
	hits, _, active = pool.Stats()
	assert.Equal(t, int64(1), hits)
	assert.Equal(t, 0, active) // Connection removed from pool

	// Put it back
	pool.Put(&dns.Conn{Conn: mockConn}, "192.5.5.241:53", true, false, nil)

	// Test TLD server
	tldConn := &mockNetConn{remoteAddr: "192.5.6.30:53"}
	pool.Put(&dns.Conn{Conn: tldConn}, "192.5.6.30:53", false, true, nil)

	conn = pool.Get("192.5.6.30:53", false, true)
	assert.NotNil(t, conn)
}

func TestTCPConnPoolMaxConnections(t *testing.T) {
	pool := NewTCPConnPool(5*time.Second, 10*time.Second, 2)
	defer pool.Close()

	// Add 2 connections (max)
	conn1 := &mockNetConn{remoteAddr: "192.5.5.241:53"}
	conn2 := &mockNetConn{remoteAddr: "192.203.230.10:53"}

	pool.Put(&dns.Conn{Conn: conn1}, "192.5.5.241:53", true, false, nil)
	pool.Put(&dns.Conn{Conn: conn2}, "192.203.230.10:53", true, false, nil)

	_, _, active := pool.Stats()
	assert.Equal(t, 2, active)

	// Try to add third connection - should be rejected
	conn3 := &mockNetConn{remoteAddr: "192.33.4.12:53"}
	pool.Put(&dns.Conn{Conn: conn3}, "192.33.4.12:53", true, false, nil)

	// Should still have 2 connections
	_, _, active = pool.Stats()
	assert.Equal(t, 2, active)

	// Verify conn3 was closed
	assert.True(t, conn3.closed)
}

func TestTCPConnPoolKeepalive(t *testing.T) {
	pool := NewTCPConnPool(5*time.Second, 10*time.Second, 10)
	defer pool.Close()

	// Create mock response with EDNS-Keepalive
	msg := new(dns.Msg)
	msg.SetEdns0(4096, false)
	ka := &dns.EDNS0_TCP_KEEPALIVE{
		Code:    dns.EDNS0TCPKEEPALIVE,
		Timeout: 20, // 2 seconds
	}
	msg.IsEdns0().Option = append(msg.IsEdns0().Option, ka)

	conn := &mockNetConn{remoteAddr: "192.5.5.241:53"}
	pool.Put(&dns.Conn{Conn: conn}, "192.5.5.241:53", true, false, msg)

	// Verify the connection uses server's timeout
	pool.mu.RLock()
	pooledConn := pool.rootConns["192.5.5.241:53"]
	pool.mu.RUnlock()

	assert.NotNil(t, pooledConn)
	assert.True(t, pooledConn.supportsKA)
	assert.Equal(t, uint16(20), pooledConn.kaTimeout)
	assert.Equal(t, 2*time.Second, pooledConn.idleTime)
}

func TestTCPConnPoolCleanup(t *testing.T) {
	pool := NewTCPConnPool(50*time.Millisecond, 100*time.Millisecond, 10)
	defer pool.Close()

	// Add connections
	conn1 := &mockNetConn{remoteAddr: "192.5.5.241:53"}
	conn2 := &mockNetConn{remoteAddr: "192.5.6.30:53"}

	pool.Put(&dns.Conn{Conn: conn1}, "192.5.5.241:53", true, false, nil)
	pool.Put(&dns.Conn{Conn: conn2}, "192.5.6.30:53", false, true, nil)

	_, _, active := pool.Stats()
	assert.Equal(t, 2, active)

	// Wait for connections to expire
	time.Sleep(150 * time.Millisecond)

	// Manually trigger cleanup
	pool.cleanup()

	// All connections should be cleaned up
	_, _, active = pool.Stats()
	assert.Equal(t, 0, active)

	// Verify connections were closed
	assert.True(t, conn1.closed)
	assert.True(t, conn2.closed)
}

func TestIsRootServer(t *testing.T) {
	tests := []struct {
		server   string
		expected bool
	}{
		{"192.5.5.241:53", true},    // F.ROOT-SERVERS.NET
		{"192.203.230.10:53", true}, // H.ROOT-SERVERS.NET
		{"198.41.0.4:53", true},     // A.ROOT-SERVERS.NET
		{"127.0.0.1:53", true},      // Localhost (for testing)
		{"[::1]:53", true},          // IPv6 localhost (for testing)
		{"8.8.8.8:53", false},       // Google DNS
		{"1.1.1.1:53", false},       // Cloudflare
		{"192.5.5.241", false},      // Missing port
		{"invalid", false},          // Invalid format
	}

	for _, tc := range tests {
		t.Run(tc.server, func(t *testing.T) {
			result := isRootServer(tc.server)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsTLDServer(t *testing.T) {
	tests := []struct {
		qname    string
		expected bool
	}{
		{"example.com.", true},
		{"subdomain.example.com.", false},
		{"com.", false},
		{".", false},
		{"example.co.uk.", false}, // Actually 3 labels
	}

	for _, tc := range tests {
		t.Run(tc.qname, func(t *testing.T) {
			result := isTLDServer(tc.qname)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSetEDNSKeepalive(t *testing.T) {
	// Test adding to message without EDNS
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	SetEDNSKeepalive(msg, 50)

	assert.NotNil(t, msg.IsEdns0())
	assert.Equal(t, 1, len(msg.IsEdns0().Option))

	ka, ok := msg.IsEdns0().Option[0].(*dns.EDNS0_TCP_KEEPALIVE)
	assert.True(t, ok)
	assert.Equal(t, uint16(50), ka.Timeout)

	// Test adding to message with existing EDNS
	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)
	msg2.SetEdns0(4096, false)

	SetEDNSKeepalive(msg2, 100)

	assert.Equal(t, 1, len(msg2.IsEdns0().Option))

	// Test duplicate prevention
	SetEDNSKeepalive(msg2, 200)
	assert.Equal(t, 1, len(msg2.IsEdns0().Option))
}

// mockNetConn is a mock implementation of net.Conn for testing
type mockNetConn struct {
	remoteAddr string
	closed     bool
}

func (m *mockNetConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockNetConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockNetConn) Close() error                       { m.closed = true; return nil }
func (m *mockNetConn) LocalAddr() net.Addr                { return mockAddr{"127.0.0.1:0"} }
func (m *mockNetConn) RemoteAddr() net.Addr               { return mockAddr{m.remoteAddr} }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr struct {
	addr string
}

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return m.addr }
