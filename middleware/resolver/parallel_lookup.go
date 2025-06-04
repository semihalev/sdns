package resolver

import (
	"context"
	"net"
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
	type lookupItem struct {
		name string
		ctx  context.Context
	}
	var toLookup []lookupItem
	for _, name := range list {
		if _, ok := foundv4[name]; !ok {
			// Check for loops with a fresh context copy for each nameserver
			ctxCopy, loop := r.checkLoop(ctx, name, dns.TypeA)
			if loop {
				if _, ok := r.getIPv4Cache(name); !ok {
					log.Debug("Looping during ns ipv4 lookup", "query", formatQuestion(q), "ns", name)
					continue
				}
			}
			toLookup = append(toLookup, lookupItem{name: name, ctx: ctxCopy})
		}
	}

	if len(toLookup) == 0 {
		return
	}

	// Use errgroup for parallel lookups with concurrency limit
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(5) // Maximum 5 concurrent lookups

	// Results storage
	type lookupResult struct {
		name  string
		addrs []string
	}

	resultsChan := make(chan lookupResult, len(toLookup))

	// Launch parallel lookups
	for _, item := range toLookup {
		item := item // Capture loop variable
		g.Go(func() error {
			addrs, err := r.lookupNSAddrV4(item.ctx, item.name, cd)
			if err != nil {
				log.Debug("Lookup NS ipv4 address failed",
					"query", formatQuestion(q),
					"ns", item.name,
					"error", err.Error())
				return nil // Don't fail the group
			}

			if len(addrs) > 0 {
				resultsChan <- lookupResult{name: item.name, addrs: addrs}
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
	type lookupItem struct {
		name string
		ctx  context.Context
	}
	var toLookup []lookupItem
	for _, name := range list {
		if _, ok := foundv6[name]; !ok {
			// Check for loops with a fresh context copy for each nameserver
			ctxCopy, loop := r.checkLoop(ctx, name, dns.TypeAAAA)
			if loop {
				if _, ok := r.getIPv6Cache(name); !ok {
					log.Debug("Looping during ns ipv6 lookup", "query", formatQuestion(q), "ns", name)
					continue
				}
			}
			toLookup = append(toLookup, lookupItem{name: name, ctx: ctxCopy})
		}
	}

	if len(toLookup) == 0 {
		return
	}

	// Use errgroup for parallel lookups with concurrency limit
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(3) // Fewer concurrent IPv6 lookups as they may be slower

	// Results storage
	type lookupResult struct {
		name  string
		addrs []string
	}

	resultsChan := make(chan lookupResult, len(toLookup))

	// Launch parallel lookups
	for _, item := range toLookup {
		item := item // Capture loop variable
		g.Go(func() error {
			addrs, err := r.lookupNSAddrV6(item.ctx, item.name, cd)
			if err != nil {
				log.Debug("Lookup NS ipv6 address failed",
					"query", formatQuestion(q),
					"ns", item.name,
					"error", err.Error())
				return nil // Don't fail the group
			}

			if len(addrs) > 0 {
				resultsChan <- lookupResult{name: item.name, addrs: addrs}
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

