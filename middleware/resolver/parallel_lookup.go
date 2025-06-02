package resolver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/authcache"
	"golang.org/x/sync/errgroup"
)

// parallelLookupV4Nss performs parallel IPv4 lookups for nameservers using modern errgroup
func (r *Resolver) parallelLookupV4Nss(ctx context.Context, q dns.Question, authservers *authcache.AuthServers, key uint64, parentdsrr []dns.RR, foundv4, nss nameservers, cd bool) {
	list := sortnss(nss, q.Name)

	// Collect all nameservers first
	authservers.Nss = append(authservers.Nss, list...)

	// Filter out already found nameservers
	var toLookup []string
	for _, name := range list {
		if _, ok := foundv4[name]; !ok {
			// Check for loops
			ctxCopy, loop := r.checkLoop(ctx, name, dns.TypeA)
			if loop {
				if _, ok := r.getIPv4Cache(name); !ok {
					log.Debug("Looping during ns ipv4 lookup", "query", formatQuestion(q), "ns", name)
					continue
				}
			}
			toLookup = append(toLookup, name)
			// Store context for later use
			ctx = ctxCopy
		}
	}

	if len(toLookup) == 0 {
		return
	}

	// Use errgroup for parallel lookups with concurrency limit
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5) // Maximum 5 concurrent lookups

	// Results storage
	type lookupResult struct {
		name  string
		addrs []string
	}

	resultsChan := make(chan lookupResult, len(toLookup))

	// Launch parallel lookups
	for _, name := range toLookup {
		name := name // Capture loop variable
		g.Go(func() error {
			addrs, err := r.lookupNSAddrV4(ctx, name, cd)
			if err != nil {
				log.Debug("Lookup NS ipv4 address failed",
					"query", formatQuestion(q),
					"ns", name,
					"error", err.Error())
				return nil // Don't fail the group
			}

			if len(addrs) > 0 {
				resultsChan <- lookupResult{name: name, addrs: addrs}
			}
			return nil
		})
	}

	// Wait for all lookups to complete
	go func() {
		_ = g.Wait() // Ignore error as we handle failures individually
		close(resultsChan)
	}()

	// Process results as they arrive
	nsipv4 := make(map[string][]string)
	firstResult := true

	for result := range resultsChan {
		nsipv4[result.name] = result.addrs

		// Update authservers with new addresses
		authservers.Lock()
		for _, addr := range result.addrs {
			raddr := net.JoinHostPort(addr, "53")
			found := false
			for _, s := range authservers.List {
				if s.Addr == raddr {
					found = true
					break
				}
			}
			if !found {
				authservers.List = append(authservers.List, authcache.NewAuthServer(raddr, authcache.IPv4))
			}
		}
		authservers.Unlock()

		// Update temporary cache after first successful lookup
		if firstResult && len(authservers.List) > 0 {
			r.ncache.Set(key, parentdsrr, authservers, time.Minute)
			firstResult = false
		}
	}

	// Batch update the IPv4 cache
	if len(nsipv4) > 0 {
		r.addIPv4Cache(nsipv4)
	}
}

// parallelLookupV6Nss performs parallel IPv6 lookups for nameservers using modern errgroup
func (r *Resolver) parallelLookupV6Nss(ctx context.Context, q dns.Question, authservers *authcache.AuthServers, key uint64, parentdsrr []dns.RR, foundv6, nss nameservers, cd bool) {
	list := sortnss(nss, q.Name)

	// Filter out already found nameservers
	var toLookup []string
	for _, name := range list {
		if _, ok := foundv6[name]; !ok {
			// Check for loops
			ctxCopy, loop := r.checkLoop(ctx, name, dns.TypeAAAA)
			if loop {
				if _, ok := r.getIPv6Cache(name); !ok {
					log.Debug("Looping during ns ipv6 lookup", "query", formatQuestion(q), "ns", name)
					continue
				}
			}
			toLookup = append(toLookup, name)
			ctx = ctxCopy
		}
	}

	if len(toLookup) == 0 {
		return
	}

	// Use errgroup for parallel lookups with concurrency limit
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(3) // Fewer concurrent IPv6 lookups as they may be slower

	// Results storage
	type lookupResult struct {
		name  string
		addrs []string
	}

	resultsChan := make(chan lookupResult, len(toLookup))

	// Launch parallel lookups
	for _, name := range toLookup {
		name := name // Capture loop variable
		g.Go(func() error {
			addrs, err := r.lookupNSAddrV6(ctx, name, cd)
			if err != nil {
				log.Debug("Lookup NS ipv6 address failed",
					"query", formatQuestion(q),
					"ns", name,
					"error", err.Error())
				return nil // Don't fail the group
			}

			if len(addrs) > 0 {
				resultsChan <- lookupResult{name: name, addrs: addrs}
			}
			return nil
		})
	}

	// Wait for all lookups to complete
	go func() {
		_ = g.Wait()
		close(resultsChan)
	}()

	// Process results as they arrive
	nsipv6 := make(map[string][]string)

	for result := range resultsChan {
		nsipv6[result.name] = result.addrs

		// Update authservers with new addresses
		authservers.Lock()
		for _, addr := range result.addrs {
			raddr := net.JoinHostPort(addr, "53")
			found := false
			for _, s := range authservers.List {
				if s.Addr == raddr {
					found = true
					break
				}
			}
			if !found {
				authservers.List = append(authservers.List, authcache.NewAuthServer(raddr, authcache.IPv6))
			}
		}
		authservers.Unlock()

		// Update cache after first few successful lookups
		if len(authservers.List) > 2 {
			r.ncache.Set(key, parentdsrr, authservers, time.Minute)
		}
	}

	// Batch update the IPv6 cache
	if len(nsipv6) > 0 {
		r.addIPv6Cache(nsipv6)
	}
}

// modernLookup performs parallel DNS queries to multiple servers with adaptive timeouts
func (r *Resolver) modernLookup(ctx context.Context, req *dns.Msg, servers *authcache.AuthServers) (*dns.Msg, error) {
	servers.RLock()
	serversList := make([]*authcache.AuthServer, len(servers.List))
	copy(serversList, servers.List)
	servers.RUnlock()

	if len(serversList) == 0 {
		return nil, errors.New("no servers available")
	}

	// Sort servers by performance
	authcache.Sort(serversList, atomic.AddUint64(&servers.Called, 1))

	// Use context with timeout
	ctx, cancel := context.WithTimeout(ctx, r.netTimeout)
	defer cancel()

	// Result channel
	type result struct {
		resp   *dns.Msg
		err    error
		server *authcache.AuthServer
	}

	resultChan := make(chan result, len(serversList))

	// Launch queries with adaptive concurrency
	g, ctx := errgroup.WithContext(ctx)

	// Start first batch immediately (fast start)
	fastStart := 2
	if len(serversList) < fastStart {
		fastStart = len(serversList)
	}

	// Launch fast start queries
	for i := 0; i < fastStart; i++ {
		server := serversList[i]
		g.Go(func() error {
			resp, err := r.exchangeWithTimeout(ctx, req, server)
			select {
			case resultChan <- result{resp: resp, err: err, server: server}:
			case <-ctx.Done():
			}
			return nil
		})
	}

	// Launch remaining queries with delays based on RTT
	for i := fastStart; i < len(serversList); i++ {
		server := serversList[i]
		delay := r.calculateDelay(server, i-fastStart)

		g.Go(func() error {
			select {
			case <-time.After(delay):
				resp, err := r.exchangeWithTimeout(ctx, req, server)
				select {
				case resultChan <- result{resp: resp, err: err, server: server}:
				case <-ctx.Done():
				}
			case <-ctx.Done():
			}
			return nil
		})
	}

	// Collect results
	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	// Process results
	var lastError error
	responseErrors := []*dns.Msg{}

	for res := range resultChan {
		if res.err != nil {
			lastError = res.err
			// Update server error count
			atomic.AddUint32(&servers.ErrorCount, 1)
			continue
		}

		if res.resp == nil {
			continue
		}

		// Check response validity
		if res.resp.Rcode == dns.RcodeSuccess || res.resp.Rcode == dns.RcodeNameError {
			// Update RTT for successful query
			if res.server != nil {
				// RTT calculation would go here
			}
			return res.resp, nil
		}

		// Collect error responses
		if res.resp.Rcode == dns.RcodeServerFailure || res.resp.Rcode == dns.RcodeRefused {
			responseErrors = append(responseErrors, res.resp)
		}
	}

	// Return best error response or last error
	if len(responseErrors) > 0 {
		return responseErrors[0], nil
	}

	if lastError != nil {
		return nil, lastError
	}

	return nil, errors.New("all servers failed")
}

// exchangeWithTimeout performs a DNS exchange with server-specific timeout
func (r *Resolver) exchangeWithTimeout(ctx context.Context, req *dns.Msg, server *authcache.AuthServer) (*dns.Msg, error) {
	// Anti-spoofing: use random ID
	orgID := req.Id
	req = req.Copy()
	req.Id = dns.Id()

	defer func() {
		if req != nil {
			req.Id = orgID
		}
	}()

	// Use server-specific timeout
	timeout := r.calculateTimeout(server)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := r.exchange(ctx, "udp", req, server, 0)
	if resp != nil {
		resp.Id = orgID
	}

	return resp, err
}

// calculateDelay returns delay before querying a server based on its position and RTT
func (r *Resolver) calculateDelay(server *authcache.AuthServer, position int) time.Duration {
	baseDelay := 50 * time.Millisecond

	// Add delay based on position
	delay := time.Duration(position) * baseDelay

	// Adjust based on server RTT if known
	if rtt := atomic.LoadInt64(&server.Rtt); rtt > 0 {
		serverDelay := time.Duration(rtt) / 2
		if serverDelay > delay {
			delay = serverDelay
		}
	}

	// Cap maximum delay
	if delay > 300*time.Millisecond {
		delay = 300 * time.Millisecond
	}

	return delay
}

// calculateTimeout returns timeout for a specific server based on its RTT
func (r *Resolver) calculateTimeout(server *authcache.AuthServer) time.Duration {
	// Get server RTT
	rtt := time.Duration(atomic.LoadInt64(&server.Rtt))

	if rtt <= 0 {
		// Unknown RTT, use default
		return 2 * time.Second
	}

	// Use 3x RTT with bounds
	timeout := rtt * 3

	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	} else if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}

	return timeout
}
