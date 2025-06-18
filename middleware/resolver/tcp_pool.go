package resolver

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog"
)

// TCPConnPool manages persistent TCP connections to DNS servers.
type TCPConnPool struct {
	mu sync.RWMutex

	// Separate pools for different server levels
	rootConns map[string]*pooledConn // Level 0 - root servers
	tldConns  map[string]*pooledConn // Level 1 - TLD servers

	// Configuration
	rootTimeout time.Duration
	tldTimeout  time.Duration
	maxConns    int

	// Metrics
	hits   int64
	misses int64
	active int
}

// pooledConn wraps a DNS connection with metadata.
type pooledConn struct {
	*dns.Conn
	server     string
	lastUsed   time.Time
	idleTime   time.Duration
	supportsKA bool // Supports EDNS-Keepalive
	kaTimeout  uint16
}

// NewTCPConnPool creates a new TCP connection pool.
func NewTCPConnPool(rootTimeout, tldTimeout time.Duration, maxConns int) *TCPConnPool {
	if rootTimeout == 0 {
		rootTimeout = 5 * time.Second
	}
	if tldTimeout == 0 {
		tldTimeout = 10 * time.Second
	}
	if maxConns == 0 {
		maxConns = 100
	}

	pool := &TCPConnPool{
		rootConns:   make(map[string]*pooledConn),
		tldConns:    make(map[string]*pooledConn),
		rootTimeout: rootTimeout,
		tldTimeout:  tldTimeout,
		maxConns:    maxConns,
	}

	// Start cleanup goroutine
	go pool.cleanupLoop()

	return pool
}

// (*TCPConnPool).Get get retrieves a connection for the given server.
func (p *TCPConnPool) Get(server string, isRoot, isTLD bool) *dns.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	var conn *pooledConn
	var exists bool

	switch {
	case isRoot:
		conn, exists = p.rootConns[server]
	case isTLD:
		conn, exists = p.tldConns[server]
	default:
		// Don't pool connections for other servers
		return nil
	}

	if exists && conn != nil {
		// Check if connection is still valid
		if time.Since(conn.lastUsed) > conn.idleTime {
			// Connection expired
			conn.Close()
			delete(p.getPoolMap(isRoot, isTLD), server)
			p.active--
			return nil
		}

		// Connection appears valid based on time check

		// Update last used time
		conn.lastUsed = time.Now()
		p.hits++

		// Remove from pool (caller will return it if still valid)
		delete(p.getPoolMap(isRoot, isTLD), server)
		p.active--

		return conn.Conn
	}

	p.misses++
	return nil
}

// (*TCPConnPool).Put put returns a connection to the pool.
func (p *TCPConnPool) Put(conn *dns.Conn, server string, isRoot, isTLD bool, msg *dns.Msg) {
	if conn == nil || (!isRoot && !isTLD) {
		// Don't pool non-infrastructure connections
		if conn != nil {
			conn.Close()
		}
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check connection limit
	if p.active >= p.maxConns {
		// Pool is full, close the connection
		conn.Close()
		return
	}

	idleTime := p.tldTimeout
	if isRoot {
		idleTime = p.rootTimeout
	}

	pooled := &pooledConn{
		Conn:       conn,
		server:     server,
		lastUsed:   time.Now(),
		idleTime:   idleTime,
		supportsKA: false,
	}

	// Check if server supports EDNS-Keepalive
	if msg != nil && msg.IsEdns0() != nil {
		for _, opt := range msg.IsEdns0().Option {
			if ka, ok := opt.(*dns.EDNS0_TCP_KEEPALIVE); ok {
				pooled.supportsKA = true
				pooled.kaTimeout = ka.Timeout
				// Use server's suggested timeout if reasonable
				serverTimeout := time.Duration(ka.Timeout) * 100 * time.Millisecond
				if serverTimeout > 0 && serverTimeout < pooled.idleTime {
					pooled.idleTime = serverTimeout
				}
				break
			}
		}
	}

	// Store in appropriate pool
	poolMap := p.getPoolMap(isRoot, isTLD)
	poolMap[server] = pooled
	p.active++

	zlog.Debug("TCP connection pooled", "server", server, "idle_timeout", pooled.idleTime,
		"supports_keepalive", pooled.supportsKA, "active_conns", p.active)
}

// getPoolMap returns the appropriate pool map.
func (p *TCPConnPool) getPoolMap(isRoot, isTLD bool) map[string]*pooledConn {
	_ = isTLD // Avoid unused variable warning

	if isRoot {
		return p.rootConns
	}

	return p.tldConns
}

// cleanupLoop periodically removes expired connections.
func (p *TCPConnPool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanup()
	}
}

// cleanup removes expired connections.
func (p *TCPConnPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// Clean root connections
	for server, conn := range p.rootConns {
		if now.Sub(conn.lastUsed) > conn.idleTime {
			conn.Close()
			delete(p.rootConns, server)
			p.active--
			zlog.Debug("Cleaned up idle root connection", "server", server)
		}
	}

	// Clean TLD connections
	for server, conn := range p.tldConns {
		if now.Sub(conn.lastUsed) > conn.idleTime {
			conn.Close()
			delete(p.tldConns, server)
			p.active--
			zlog.Debug("Cleaned up idle TLD connection", "server", server)
		}
	}
}

// (*TCPConnPool).Stats stats returns pool statistics.
func (p *TCPConnPool) Stats() (hits, misses int64, active int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hits, p.misses, p.active
}

// (*TCPConnPool).Close close closes all connections in the pool.
func (p *TCPConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.rootConns {
		conn.Close()
	}
	for _, conn := range p.tldConns {
		conn.Close()
	}

	p.rootConns = make(map[string]*pooledConn)
	p.tldConns = make(map[string]*pooledConn)
	p.active = 0
}

// SetEDNSKeepalive adds EDNS-Keepalive option to a message.
func SetEDNSKeepalive(msg *dns.Msg, timeout uint16) {
	if msg.IsEdns0() == nil {
		msg.SetEdns0(4096, false)
	}

	// Check if keepalive already exists
	for _, opt := range msg.IsEdns0().Option {
		if _, ok := opt.(*dns.EDNS0_TCP_KEEPALIVE); ok {
			return
		}
	}

	// Add keepalive option
	ka := &dns.EDNS0_TCP_KEEPALIVE{
		Code:    dns.EDNS0TCPKEEPALIVE,
		Timeout: timeout,
	}
	msg.IsEdns0().Option = append(msg.IsEdns0().Option, ka)
}

// isRootServer checks if the server is a root server.
func isRootServer(server string) bool {
	// Root servers are typically at addresses like 192.5.5.241:53
	// This is a simplified check - in production, compare against known root server IPs
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return false
	}

	// For testing purposes, allow localhost to be considered a root server
	if host == "127.0.0.1" || host == "::1" || host == "[::1]" {
		return true
	}

	// Known root server IP prefixes (simplified)
	rootPrefixes := []string{
		"192.5.5.",     // F.ROOT-SERVERS.NET
		"192.203.230.", // H.ROOT-SERVERS.NET
		"192.33.4.",    // E.ROOT-SERVERS.NET
		"192.36.148.",  // G.ROOT-SERVERS.NET
		"192.41.0.",    // I.ROOT-SERVERS.NET
		"192.58.128.",  // J.ROOT-SERVERS.NET
		"192.0.47.",    // K.ROOT-SERVERS.NET
		"192.112.36.",  // L.ROOT-SERVERS.NET
		"193.0.14.",    // C.ROOT-SERVERS.NET
		"198.41.0.",    // A.ROOT-SERVERS.NET
		"198.97.190.",  // B.ROOT-SERVERS.NET
		"199.7.83.",    // D.ROOT-SERVERS.NET
		"199.7.91.",    // M.ROOT-SERVERS.NET
		"199.9.14.",    // M.ROOT-SERVERS.NET
		"202.12.27.",   // M.ROOT-SERVERS.NET
	}

	for _, prefix := range rootPrefixes {
		if len(host) >= len(prefix) && host[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}

// isTLDServer checks if this query is going to a TLD server.
func isTLDServer(qname string) bool {
	// Check if query is for a second-level domain
	labels := dns.CountLabel(qname)
	return labels == 2 // e.g., "example.com."
}
