package resolver

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewTCPConnPool(t *testing.T) {
	// Test with defaults
	pool := NewTCPConnPool(0, 0, 0)
	if pool == nil {
		t.Fatalf("pool is nil")
	}
	if !reflect.DeepEqual(5*time.Second, pool.rootTimeout) {
		t.Errorf("pool.rootTimeout = %v, want %v", pool.rootTimeout, 5*time.Second)
	}
	if !reflect.DeepEqual(10*time.Second, pool.tldTimeout) {
		t.Errorf("pool.tldTimeout = %v, want %v", pool.tldTimeout, 10*time.Second)
	}
	if !reflect.DeepEqual(100, pool.maxConns) {
		t.Errorf("pool.maxConns = %v, want %v", pool.maxConns, 100)
	}

	// Test with custom values
	pool2 := NewTCPConnPool(3*time.Second, 7*time.Second, 50)
	if !reflect.DeepEqual(3*time.Second, pool2.rootTimeout) {
		t.Errorf("pool2.rootTimeout = %v, want %v", pool2.rootTimeout, 3*time.Second)
	}
	if !reflect.DeepEqual(7*time.Second, pool2.tldTimeout) {
		t.Errorf("pool2.tldTimeout = %v, want %v", pool2.tldTimeout, 7*time.Second)
	}
	if !reflect.DeepEqual(50, pool2.maxConns) {
		t.Errorf("pool2.maxConns = %v, want %v", pool2.maxConns, 50)
	}

	// Clean up
	pool.Close()
	pool2.Close()
}

func TestTCPConnPoolGetPut(t *testing.T) {
	pool := NewTCPConnPool(5*time.Second, 10*time.Second, 10)
	defer pool.Close()

	// Test getting from empty pool
	conn := pool.Get("192.5.5.241:53", true, false)
	if conn != nil {
		t.Errorf("conn = %v, want nil", conn)
	}

	// Test stats for miss
	hits, misses, active := pool.Stats()
	if !reflect.DeepEqual(int64(0), hits) {
		t.Errorf("hits = %v, want %v", hits, int64(0))
	}
	if !reflect.DeepEqual(int64(1), misses) {
		t.Errorf("misses = %v, want %v", misses, int64(1))
	}
	if !reflect.DeepEqual(0, active) {
		t.Errorf("active = %v, want %v", active, 0)
	}

	// Create a mock connection
	mockConn := &mockNetConn{remoteAddr: "192.5.5.241:53"}
	dnsConn := &dns.Conn{Conn: mockConn}

	// Put connection for root server
	pool.Put(dnsConn, "192.5.5.241:53", true, false, nil)

	// Check active connections
	_, _, active = pool.Stats()
	if !reflect.DeepEqual(1, active) {
		t.Errorf("active = %v, want %v", active, 1)
	}

	// Get the connection back
	conn = pool.Get("192.5.5.241:53", true, false)
	if conn == nil {
		t.Fatalf("conn is nil")
	}

	// Check hit stats
	hits, _, active = pool.Stats()
	if !reflect.DeepEqual(int64(1), hits) {
		t.Errorf("hits = %v, want %v", hits, int64(1))
	}
	if !reflect.DeepEqual(0, active) {
		t.Errorf("active = %v, want %v", active, 0)
	} // Connection removed from pool

	// Put it back
	pool.Put(&dns.Conn{Conn: mockConn}, "192.5.5.241:53", true, false, nil)

	// Test TLD server
	tldConn := &mockNetConn{remoteAddr: "192.5.6.30:53"}
	pool.Put(&dns.Conn{Conn: tldConn}, "192.5.6.30:53", false, true, nil)

	conn = pool.Get("192.5.6.30:53", false, true)
	if conn == nil {
		t.Fatalf("conn is nil")
	}
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
	if !reflect.DeepEqual(2, active) {
		t.Errorf("active = %v, want %v", active, 2)
	}

	// Try to add third connection - should be rejected
	conn3 := &mockNetConn{remoteAddr: "192.33.4.12:53"}
	pool.Put(&dns.Conn{Conn: conn3}, "192.33.4.12:53", true, false, nil)

	// Should still have 2 connections
	_, _, active = pool.Stats()
	if !reflect.DeepEqual(2, active) {
		t.Errorf("active = %v, want %v", active, 2)
	}

	// Verify conn3 was closed
	if !(conn3.closed) {
		t.Errorf("conn3.closed is false")
	}
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

	if pooledConn == nil {
		t.Fatalf("pooledConn is nil")
	}
	if !(pooledConn.supportsKA) {
		t.Errorf("pooledConn.supportsKA is false")
	}
	if !reflect.DeepEqual(uint16(20), pooledConn.kaTimeout) {
		t.Errorf("pooledConn.kaTimeout = %v, want %v", pooledConn.kaTimeout, uint16(20))
	}
	if !reflect.DeepEqual(2*time.Second, pooledConn.idleTime) {
		t.Errorf("pooledConn.idleTime = %v, want %v", pooledConn.idleTime, 2*time.Second)
	}
}

// A keepalive timeout of zero is the server saying "close now"
// (RFC 7828 §3.2.2): no further queries may go out on that connection.
// Pooling it used to spend the next query on a socket the server was
// hanging up, observed as a send into the dead connection and a retry.
func TestTCPConnPoolRefusesKeepaliveZero(t *testing.T) {
	pool := NewTCPConnPool(5*time.Second, 10*time.Second, 10)
	defer pool.Close()

	msg := new(dns.Msg)
	msg.SetEdns0(4096, false)
	msg.IsEdns0().Option = append(msg.IsEdns0().Option, &dns.EDNS0_TCP_KEEPALIVE{
		Code:    dns.EDNS0TCPKEEPALIVE,
		Timeout: 0,
	})

	conn := &mockNetConn{remoteAddr: "192.5.5.241:53"}
	pool.Put(&dns.Conn{Conn: conn}, "192.5.5.241:53", true, false, msg)

	pool.mu.RLock()
	pooled := pool.rootConns["192.5.5.241:53"]
	active := pool.active
	pool.mu.RUnlock()

	if pooled != nil {
		t.Errorf("%s: pooled = %v, want nil", "a connection the server asked to close was pooled", pooled)
	}
	if !(conn.closed) {
		t.Errorf("%s: conn.closed is false", "the connection was neither pooled nor closed — leaked")
	}
	if !reflect.DeepEqual(0, active) {
		t.Errorf("active = %v, want %v", active, 0)
	}
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
	if !reflect.DeepEqual(2, active) {
		t.Errorf("active = %v, want %v", active, 2)
	}

	// Wait for connections to expire
	time.Sleep(150 * time.Millisecond)

	// Manually trigger cleanup
	pool.cleanup()

	// All connections should be cleaned up
	_, _, active = pool.Stats()
	if !reflect.DeepEqual(0, active) {
		t.Errorf("active = %v, want %v", active, 0)
	}

	// Verify connections were closed
	if !(conn1.closed) {
		t.Errorf("conn1.closed is false")
	}
	if !(conn2.closed) {
		t.Errorf("conn2.closed is false")
	}
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
			if !reflect.DeepEqual(tc.expected, result) {
				t.Errorf("result = %v, want %v", result, tc.expected)
			}
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
			if !reflect.DeepEqual(tc.expected, result) {
				t.Errorf("result = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestSetEDNSKeepalive(t *testing.T) {
	// Test adding to message without EDNS
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	SetEDNSKeepalive(msg, 50)

	if msg.IsEdns0() == nil {
		t.Fatalf("msg.IsEdns0() is nil")
	}
	if !reflect.DeepEqual(1, len(msg.IsEdns0().Option)) {
		t.Errorf("len(msg.IsEdns0().Option) = %v, want %v", len(msg.IsEdns0().Option), 1)
	}

	ka, ok := msg.IsEdns0().Option[0].(*dns.EDNS0_TCP_KEEPALIVE)
	if !(ok) {
		t.Errorf("ok is false")
	}
	if !reflect.DeepEqual(uint16(50), ka.Timeout) {
		t.Errorf("ka.Timeout = %v, want %v", ka.Timeout, uint16(50))
	}

	// Test adding to message with existing EDNS
	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)
	msg2.SetEdns0(4096, false)

	SetEDNSKeepalive(msg2, 100)

	if !reflect.DeepEqual(1, len(msg2.IsEdns0().Option)) {
		t.Errorf("len(msg2.IsEdns0().Option) = %v, want %v", len(msg2.IsEdns0().Option), 1)
	}

	// Test duplicate prevention
	SetEDNSKeepalive(msg2, 200)
	if !reflect.DeepEqual(1, len(msg2.IsEdns0().Option)) {
		t.Errorf("len(msg2.IsEdns0().Option) = %v, want %v", len(msg2.IsEdns0().Option), 1)
	}
}

// mockNetConn is a mock implementation of net.Conn for testing.
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
