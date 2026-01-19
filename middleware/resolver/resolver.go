package resolver

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
	"golang.org/x/sync/errgroup"
)

// Resolver type.
type Resolver struct {
	sync.RWMutex

	ncache *authcache.NSCache

	cfg *config.Config

	rootservers *authcache.AuthServers

	outboundipv4 []net.IP
	outboundipv6 []net.IP

	// glue addrs cache
	ipv4cache *cache.Cache
	ipv6cache *cache.Cache

	dnssec   bool
	rootkeys []dns.RR

	qnameMinLevel int
	netTimeout    time.Duration

	sfGroup *SingleflightWrapper

	// TCP connection pool for persistent connections
	tcpPool *TCPConnPool

	// Circuit breaker and goroutine limiter
	circuitBreaker *circuitBreaker
	maxConcurrent  chan struct{} // Semaphore for limiting concurrent queries
}

// resolveContext holds the state for a DNS resolution operation.
type resolveContext struct {
	req        *dns.Msg
	servers    *authcache.AuthServers
	depth      int
	level      int
	nomin      bool
	parentDSRR []dns.RR
	isRoot     bool
	extra      []bool
}

type nameservers map[string]struct{}

type fatalError error

// Error variables are defined in errors.go

const (
	rootzone         = "."
	maxUint16        = 1 << 16
	defaultCacheSize = 1024 * 256
	defaultTimeout   = 2 * time.Second
)

// NewResolver return a resolver.
func NewResolver(cfg *config.Config) *Resolver {
	r := &Resolver{
		cfg: cfg,

		ncache: authcache.NewNSCache(),

		rootservers: new(authcache.AuthServers),

		ipv4cache: cache.New(defaultCacheSize),

		dnssec: cfg.DNSSEC == "on",

		qnameMinLevel:  cfg.QnameMinLevel,
		netTimeout:     defaultTimeout,
		sfGroup:        NewSingleflightWrapper(),
		circuitBreaker: newCircuitBreaker(),
	}

	// Set default for MaxConcurrentQueries if not configured
	maxConcurrent := cfg.MaxConcurrentQueries
	if maxConcurrent == 0 {
		maxConcurrent = 1000 // Default to 1000 concurrent queries
	}
	r.maxConcurrent = make(chan struct{}, maxConcurrent)

	if r.cfg.IPv6Access {
		r.ipv6cache = cache.New(defaultCacheSize)
	}

	if r.cfg.Timeout.Duration > 0 {
		r.netTimeout = r.cfg.Timeout.Duration
	}

	r.parseRootServers(cfg)
	r.parseOutBoundAddrs(cfg)

	r.rootkeys = []dns.RR{}
	for _, k := range cfg.RootKeys {
		rr, err := dns.NewRR(k)
		if err != nil {
			zlog.Fatal("Root keys invalid", zlog.String("error", err.Error()))
		}
		r.rootkeys = append(r.rootkeys, rr)
	}

	// Initialize TCP connection pool if enabled
	if cfg.TCPKeepalive {
		r.tcpPool = NewTCPConnPool(
			cfg.RootTCPTimeout.Duration,
			cfg.TLDTCPTimeout.Duration,
			cfg.TCPMaxConnections,
		)
	}

	go r.run()

	return r
}

func (r *Resolver) parseRootServers(cfg *config.Config) {
	r.rootservers = &authcache.AuthServers{}
	r.rootservers.Zone = rootzone

	for _, s := range cfg.RootServers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			r.rootservers.List = append(r.rootservers.List, authcache.NewAuthServer(s, authcache.IPv4))
		}
	}

	if cfg.IPv6Access {
		for _, s := range cfg.Root6Servers {
			host, _, _ := net.SplitHostPort(s)

			if ip := net.ParseIP(host); ip != nil && ip.To16() != nil {
				r.rootservers.List = append(r.rootservers.List, authcache.NewAuthServer(s, authcache.IPv6))
			}
		}
	}
}

func (r *Resolver) parseOutBoundAddrs(cfg *config.Config) {
	for _, s := range cfg.OutboundIPs {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			if isLocalIP(ip) {
				r.outboundipv4 = append(r.outboundipv4, ip)
			} else {
				zlog.Fatal("Invalid local IPv4 address in config", zlog.String("ip", ip.String()))
			}
		}
	}

	if cfg.IPv6Access {
		for _, s := range cfg.OutboundIP6s {
			if ip := net.ParseIP(s); ip != nil && ip.To16() != nil {
				if isLocalIP(ip) {
					r.outboundipv6 = append(r.outboundipv6, ip)
				} else {
					zlog.Fatal("Invalid local IPv6 address in config", zlog.String("ip", ip.String()))
				}
			}
		}
	}
}

// (*Resolver).Resolve resolve starts a DNS resolution - public interface with old signature for compatibility.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg, servers *authcache.AuthServers, root bool, depth int, level int, nomin bool, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	rc := &resolveContext{
		req:        req,
		servers:    servers,
		depth:      depth,
		level:      level,
		nomin:      nomin,
		parentDSRR: parentdsrr,
		isRoot:     root,
		extra:      extra,
	}
	return r.resolve(ctx, rc)
}

// resolve performs the actual DNS resolution with cleaner parameters.
func (r *Resolver) resolve(ctx context.Context, rc *resolveContext) (*dns.Msg, error) {
	q := rc.req.Question[0]

	if rc.isRoot {
		rc.servers, rc.parentDSRR, rc.level = r.searchCache(q, rc.req.CheckingDisabled, q.Name)
	}

	// RFC 7816 query minimization. There are some concerns in RFC.
	// Current default minimize level 5, if we down to level 3, performance gain 20%
	minReq, minimized := r.minimize(rc.req, rc.level, rc.nomin)

	zlog.Debug("Query inserted", "reqid", minReq.Id, "zone", rc.servers.Zone, "query", formatQuestion(minReq.Question[0]), "cd", rc.req.CheckingDisabled, "qname-minimize", minimized)

	resp, err := r.groupLookup(ctx, minReq, rc.servers)
	if err != nil {
		return r.handleLookupError(ctx, err, rc, minReq, minimized)
	}

	resp = r.setTags(rc.req, resp)

	if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) == 0 && len(resp.Ns) == 0 {
		if minimized {
			rc.level++
			rc.isRoot = false
			return r.resolve(ctx, rc)
		}
		return resp, nil
	}

	if !minimized && len(resp.Answer) > 0 {
		// this is like auth server external cname error but this can be recover.
		if len(resp.Answer) > 0 && (resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeNameError) {
			resp.Rcode = dns.RcodeSuccess
		}

		if resp.Rcode == dns.RcodeNameError {
			return r.authority(ctx, rc.req, resp, rc.parentDSRR, rc.req.Question[0].Qtype) // handle NXDOMAIN with DNSSEC proof
		}

		return r.answer(ctx, rc.req, resp, rc.parentDSRR, rc.extra...)
	}

	if minimized && (len(resp.Answer) == 0 && len(resp.Ns) == 0) || len(resp.Answer) > 0 {
		rc.level++
		rc.isRoot = false
		return r.resolve(ctx, rc)
	}

	if len(resp.Ns) > 0 {
		return r.processAuthoritySection(ctx, rc, minReq, resp, minimized) // handle delegation or authority data
	}

	// no answer, no authority. create new msg safer, sometimes received weird responses
	m := new(dns.Msg) // return clean empty response instead of malformed data

	m.Question = rc.req.Question
	m.SetRcode(rc.req, dns.RcodeSuccess)
	m.RecursionAvailable = true
	m.Extra = rc.req.Extra

	return m, nil
}

func (r *Resolver) groupLookup(ctx context.Context, req *dns.Msg, servers *authcache.AuthServers) (resp *dns.Msg, err error) {
	q := req.Question[0]

	// Convert uint64 key to string for singleflight
	key := strconv.FormatUint(cache.Key(q), 10)

	// Use TimedDoChan for automatic timeout handling
	result, err := r.sfGroup.TimedDoChan(ctx, key, func() (any, error) {
		return r.lookup(ctx, req, servers)
	})

	if err != nil {
		return nil, err
	}

	resp = result.(*dns.Msg)
	if resp != nil {
		// Always copy for concurrent safety when result is shared
		resp = resp.Copy()
		resp.Id = req.Id
	}

	return resp, nil
}

func (r *Resolver) checkLoop(ctx context.Context, qname string, qtype uint16) (context.Context, bool) {
	key := contextKeyNSList + contextKey(qtype)

	if v := ctx.Value(key); v != nil {
		list := v.([]string)

		loopCount := 0
		for _, n := range list {
			if n == qname {
				loopCount++
				if loopCount > 1 {
					return ctx, true // detected NS lookup loop, prevent infinite recursion
				}
			}
		}

		list = append(list, qname)
		ctx = context.WithValue(ctx, key, list)
	} else {
		ctx = context.WithValue(ctx, key, []string{qname})
	}

	return ctx, false
}

func (r *Resolver) checkNss(ctx context.Context, servers *authcache.AuthServers) (ok bool) {
	// Quick check under read lock
	servers.RLock()
	oldsize := len(servers.List)
	if servers.Checked || dns.CountLabel(servers.Zone) < 2 {
		servers.RUnlock()
		return false
	}
	nssToCheck := make([]string, len(servers.Nss))
	copy(nssToCheck, servers.Nss)
	cd := servers.CheckingDisable
	servers.RUnlock()

	// Use errgroup for concurrent lookups
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Maximum 10 concurrent lookups

	type lookupResult struct {
		name   string
		addrs  []string
		isIPv6 bool
	}
	results := make(chan lookupResult, len(nssToCheck)*2)

	// Clear caches and start IPv4 lookups
	for _, name := range nssToCheck {
		name := name // Capture loop variable
		r.removeIPv4Cache(name)

		g.Go(func() error {
			addrs, err := r.lookupNSAddrV4(ctx, name, cd)
			if err == nil && len(addrs) > 0 {
				select {
				case results <- lookupResult{name: name, addrs: addrs, isIPv6: false}:
				case <-ctx.Done():
				}
			}
			return nil // Don't fail the group
		})
	}

	// Start IPv6 lookups if enabled
	if r.cfg.IPv6Access {
		for _, name := range nssToCheck {
			name := name // Capture loop variable
			r.removeIPv6Cache(name)

			g.Go(func() error {
				addrs, err := r.lookupNSAddrV6(ctx, name, cd)
				if err == nil && len(addrs) > 0 {
					select {
					case results <- lookupResult{name: name, addrs: addrs, isIPv6: true}:
					case <-ctx.Done():
					}
				}
				return nil // Don't fail the group
			})
		}
	}

	// Close results channel when all lookups complete
	go func() {
		_ = g.Wait()
		close(results)
	}()

	// Collect results
	nsipv4 := make(map[string][]string)
	nsipv6 := make(map[string][]string)
	var newServers []*authcache.AuthServer

	for result := range results {
		if result.isIPv6 {
			nsipv6[result.name] = result.addrs
			for _, addr := range result.addrs {
				newServers = append(newServers, authcache.NewAuthServer(net.JoinHostPort(addr, "53"), authcache.IPv6))
			}
		} else {
			nsipv4[result.name] = result.addrs
			for _, addr := range result.addrs {
				newServers = append(newServers, authcache.NewAuthServer(net.JoinHostPort(addr, "53"), authcache.IPv4))
			}
		}
	}

	// Update caches
	if len(nsipv4) > 0 {
		r.addIPv4Cache(nsipv4)
	}
	if len(nsipv6) > 0 {
		r.addIPv6Cache(nsipv6)
	}

	// Update server list
	servers.Lock()
	defer servers.Unlock()

	// Deduplicate and add new servers
	existing := make(map[string]bool)
	for _, s := range servers.List {
		existing[s.Addr] = true
	}

	for _, newServer := range newServers {
		if !existing[newServer.Addr] {
			servers.List = append(servers.List, newServer)
		}
	}

	servers.Checked = true
	return oldsize != len(servers.List)
}

func (r *Resolver) checkGlueRR(resp *dns.Msg, nss nameservers, level int) (*authcache.AuthServers, nameservers, nameservers) {
	authservers := &authcache.AuthServers{}

	foundv4 := make(nameservers)
	foundv6 := make(nameservers)

	if r.cfg.IPv6Access {
		nsipv6 := make(map[string][]string)
		for _, a := range resp.Extra {
			if extra, ok := a.(*dns.AAAA); ok {
				name := strings.ToLower(extra.Header().Name)
				qname := resp.Question[0].Name

				i, _ := dns.PrevLabel(qname, level)

				if dns.CompareDomainName(name, qname[i:]) < level {
					// we cannot trust that glue, out of bailiwick.
					continue
				}

				if _, ok := nss[name]; ok {
					if isLocalIP(extra.AAAA) {
						continue
					}

					if extra.AAAA.IsLoopback() {
						continue
					}

					foundv6[name] = struct{}{}

					nsipv6[name] = append(nsipv6[name], extra.AAAA.String())
					authservers.List = append(authservers.List, authcache.NewAuthServer(net.JoinHostPort(extra.AAAA.String(), "53"), authcache.IPv6))
				}
			}
		}
		r.addIPv6Cache(nsipv6)
	}

	nsipv4 := make(map[string][]string)
	for _, a := range resp.Extra {
		if extra, ok := a.(*dns.A); ok {
			name := strings.ToLower(extra.Header().Name)
			qname := resp.Question[0].Name

			i, _ := dns.PrevLabel(qname, level)

			if dns.CompareDomainName(name, qname[i:]) < level {
				// we cannot trust that glue, it doesn't cover in the origin name.
				continue
			}

			if _, ok := nss[name]; ok {
				if isLocalIP(extra.A) {
					continue
				}

				if extra.A.IsLoopback() {
					continue
				}

				foundv4[name] = struct{}{}

				nsipv4[name] = append(nsipv4[name], extra.A.String())
				authservers.List = append(authservers.List, authcache.NewAuthServer(net.JoinHostPort(extra.A.String(), "53"), authcache.IPv4))
			}
		}
	}
	r.addIPv4Cache(nsipv4)

	return authservers, foundv4, foundv6
}

func (r *Resolver) addIPv4Cache(nsipv4 map[string][]string) {
	for name, addrs := range nsipv4 {
		key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
		r.ipv4cache.Add(key, addrs)
	}
}

func (r *Resolver) getIPv4Cache(name string) ([]string, bool) {
	key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if v, ok := r.ipv4cache.Get(key); ok {
		return v.([]string), ok
	}

	return []string{}, false
}

func (r *Resolver) removeIPv4Cache(name string) {
	r.ipv4cache.Remove(cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}))
}

func (r *Resolver) addIPv6Cache(nsipv6 map[string][]string) {
	for name, addrs := range nsipv6 {
		key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
		r.ipv6cache.Add(key, addrs)
	}
}

func (r *Resolver) getIPv6Cache(name string) ([]string, bool) {
	key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	if v, ok := r.ipv6cache.Get(key); ok {
		return v.([]string), ok
	}

	return []string{}, false
}

func (r *Resolver) removeIPv6Cache(name string) {
	r.ipv6cache.Remove(cache.Key(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}))
}

func (r *Resolver) minimize(req *dns.Msg, level int, nomin bool) (*dns.Msg, bool) {
	if r.qnameMinLevel == 0 || nomin {
		return req, false
	}

	q := req.Question[0]

	minReq := req.Copy()
	minimized := false

	if level < r.qnameMinLevel && q.Name != rootzone {
		prev, end := dns.PrevLabel(q.Name, level+1)
		if !end {
			minimized = true
			minReq.Question[0].Name = q.Name[prev:]
			if minReq.Question[0].Name == q.Name {
				minimized = false
			} else {
				minReq.Question[0].Qtype = req.Question[0].Qtype
			}
		}
	}

	return minReq, minimized
}

func (r *Resolver) setTags(req, resp *dns.Msg) *dns.Msg {
	resp.RecursionAvailable = true
	resp.RecursionDesired = true
	resp.Authoritative = false
	resp.CheckingDisabled = req.CheckingDisabled
	resp.AuthenticatedData = false

	return resp
}

func (r *Resolver) checkDname(ctx context.Context, resp *dns.Msg) (*dns.Msg, bool) {
	if len(resp.Question) == 0 {
		return nil, false
	}

	q := resp.Question[0]

	if q.Qtype == dns.TypeCNAME {
		return nil, false
	}

	target := getDnameTarget(resp)
	if target != "" {
		req := new(dns.Msg)
		req.SetQuestion(target, q.Qtype)
		req.SetEdns0(util.DefaultMsgSize, true)

		msg, err := util.ExchangeInternal(ctx, req)
		if err != nil {
			return nil, false
		}

		return msg, true
	}

	return nil, false
}

func (r *Resolver) answer(ctx context.Context, req, resp *dns.Msg, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	if msg, ok := r.checkDname(ctx, resp); ok {
		// DNAME synthesis: resolve target and append answers
		resp.Answer = append(resp.Answer, msg.Answer...)
		resp.Rcode = msg.Rcode

		if len(msg.Answer) == 0 {
			return r.authority(ctx, req, resp, parentdsrr, req.Question[0].Qtype)
		}
	}

	if !req.CheckingDisabled {
		// Validate DNSSEC signatures when CD bit is not set
		var err error
		q := req.Question[0]

		signer, signerFound := r.findRRSIG(resp, q.Name, true)
		if !signerFound {
			// Fail closed when we already have a secure delegation but the response
			// lacks the required RRSIGs.
			if len(parentdsrr) > 0 {
				zlog.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", errNoSignatures.Error())
				return nil, errNoSignatures
			}
		} else {
			parentdsrr, err = r.findDS(ctx, signer, q.Name, parentdsrr)
			if err != nil {
				return nil, err
			}

			if len(parentdsrr) > 0 {
				// Verify entire DNSSEC chain from parent DS to answer
				resp.AuthenticatedData, err = r.verifyDNSSEC(ctx, signer, strings.ToLower(q.Name), resp, parentdsrr)
				if err != nil {
					zlog.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", err.Error())
					return nil, err
				}
			}
		}
	}

	resp = r.clearAdditional(req, resp, extra...)

	return resp, nil
}

func (r *Resolver) authority(ctx context.Context, req, resp *dns.Msg, parentdsrr []dns.RR, otype uint16) (*dns.Msg, error) {
	if !req.CheckingDisabled {
		var err error
		q := req.Question[0]

		signer, signerFound := r.findRRSIG(resp, q.Name, false)
		if !signerFound {
			if len(parentdsrr) > 0 {
				err = errNoSignatures
				zlog.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
				return nil, err
			}
		} else {
			parentdsrr, err = r.findDS(ctx, signer, q.Name, parentdsrr)
			if err != nil {
				return nil, err
			}

			if len(parentdsrr) > 0 {
				ok, err := r.verifyDNSSEC(ctx, signer, q.Name, resp, parentdsrr)
				if err != nil {
					zlog.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
					return nil, err
				}

				if ok && resp.Rcode == dns.RcodeNameError {
					nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
					if len(nsec3Set) > 0 {
						err = verifyNameError(resp, nsec3Set) // prove non-existence via NSEC3
						if err != nil {
							zlog.Warn("NSEC3 verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
							return nil, err
						}

					} else {
						// Try regular NSEC verification
						nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC)
						if len(nsecSet) > 0 {
							err = verifyNameErrorNSEC(resp, nsecSet)
							if err != nil {
								zlog.Warn("NSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
								return nil, err
							}
						}
					}
				}

				if ok && q.Qtype == dns.TypeDS {
					nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
					if len(nsec3Set) > 0 {
						err = verifyNODATA(resp, nsec3Set)
						if err != nil {
							zlog.Warn("NSEC3 verify failed (NODATA)", "query", formatQuestion(q), "error", err.Error())
							return nil, err
						}

					} else {
						// Try regular NSEC verification for NODATA
						nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC)
						if len(nsecSet) > 0 {
							err = verifyNODATANSEC(resp, nsecSet)
							if err != nil {
								zlog.Warn("NSEC verify failed (NODATA)", "query", formatQuestion(q), "error", err.Error())
								return nil, err
							}
						}
					}
				}

				// If DNSSEC verification passed and NSEC/NSEC3 verification passed, set AD flag
				if ok && !req.CheckingDisabled {
					resp.AuthenticatedData = true
				}
			}
		}
	}

	return resp, nil
}

func (r *Resolver) lookup(ctx context.Context, req *dns.Msg, servers *authcache.AuthServers) (resp *dns.Msg, err error) {
	var serversList []*authcache.AuthServer

	servers.RLock()
	serversList = append(serversList, servers.List...)
	level := dns.CountLabel(servers.Zone)
	servers.RUnlock()

	authcache.Sort(serversList, atomic.AddUint64(&servers.Called, 1)) // sort by RTT and failure rate

	responseErrors := []*dns.Msg{}
	configErrors := []*dns.Msg{}
	fatalErrors := []error{}

	returned := make(chan struct{})
	defer close(returned)

	// Result type for parallel queries
	type result struct {
		resp   *dns.Msg
		err    error
		server *authcache.AuthServer
	}

	results := make(chan result)

	// Start a DNS query to a server
	originalId := req.Id // Capture ID before goroutines start
	queryServer := func(ctx context.Context, reqCopy *dns.Msg, server *authcache.AuthServer) {
		// Ensure we release the slot when done
		defer func() { <-r.maxConcurrent }()
		defer ReleaseMsg(reqCopy)

		// Check circuit breaker
		if !r.circuitBreaker.canQuery(server.Addr) {
			select {
			case results <- result{err: fatalError(errConnectionFailed), server: server}:
			case <-returned:
			}
			return
		}

		// Check context first
		if ctx.Err() != nil {
			return
		}

		// Anti-spoofing: use random ID
		reqCopy.Id = dns.Id()

		resp, err := r.exchange(ctx, "udp", reqCopy, server, 0)
		if resp != nil {
			resp.Id = originalId // Restore original ID using captured value
		}

		// Record success or failure in circuit breaker
		if err != nil {
			r.circuitBreaker.recordFailure(server.Addr)
		} else if resp != nil && resp.Rcode == dns.RcodeSuccess {
			r.circuitBreaker.recordSuccess(server.Addr)
		}

		select {
		case results <- result{resp: resp, err: err, server: server}:
		case <-returned:
		}
	}

	// calculateTimeout returns adaptive timeout based on server RTT
	calculateTimeout := func(server *authcache.AuthServer) time.Duration {
		rtt := time.Duration(atomic.LoadInt64(&server.Rtt))
		if rtt <= 0 {
			// Unknown RTT, use conservative default
			return 100 * time.Millisecond
		}
		// Give server 2x its average RTT before trying next
		timeout := rtt * 2
		// Clamp timeout to reasonable bounds
		switch {
		case timeout < 25*time.Millisecond:
			return 25 * time.Millisecond
		case timeout > 300*time.Millisecond:
			return 300 * time.Millisecond
		default:
			return timeout
		}
	}

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(150 * time.Millisecond)
	defer fallbackTimer.Stop()

	left := len(serversList)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start queries to top 2 servers immediately for faster response
	parallelStart := 2
	if len(serversList) < parallelStart {
		parallelStart = len(serversList)
	}

mainloop:
	for index, server := range serversList {
		// Check if we're approaching the limit and log a warning
		activeQueries := len(r.maxConcurrent)
		maxQueries := cap(r.maxConcurrent)
		if activeQueries > maxQueries*9/10 { // Over 90% capacity
			zlog.Warn("Approaching max concurrent DNS queries limit",
				"active", activeQueries, "max", maxQueries,
				"query", formatQuestion(req.Question[0]))
		}

		// Make a copy for this server before launching goroutine
		// We do this serially to avoid concurrent CopyTo() which is not thread-safe
		serverReq := req.CopyTo(AcquireMsg())

		// Acquire semaphore slot before starting goroutine
		select {
		case r.maxConcurrent <- struct{}{}:
			// Got a slot, start the query
			go queryServer(ctx, serverReq, server)
		case <-ctx.Done():
			// Context cancelled while waiting for slot
			return nil, ctx.Err()
		}

		// For the first 3 servers, don't wait - query them in parallel
		if index < parallelStart-1 {
			continue
		}

		// Use adaptive timeout for subsequent servers
		fallbackTimeout := calculateTimeout(server)

	fallbackloop:
		for left != 0 {
			fallbackTimer.Reset(fallbackTimeout)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-fallbackTimer.C:
				if left > 0 && len(serversList)-1 == index {
					continue fallbackloop
				}
				continue mainloop
			case res := <-results:
				left--

				if res.err != nil {
					fatalErrors = append(fatalErrors, res.err)

					if left > 0 && len(serversList)-1 == index {
						continue fallbackloop
					}
					continue mainloop
				}

				resp = res.resp

				if resp.Rcode != dns.RcodeSuccess {
					responseErrors = append(responseErrors, resp)

					// we don't need to look all nameservers for that response
					// we trust name errors if return from root servers
					if (len(responseErrors) > 2 || level < 2) && resp.Rcode == dns.RcodeNameError {
						break mainloop
					}

					if left > 0 && len(serversList)-1 == index {
						continue fallbackloop
					}
					continue mainloop
				}

				if resp.Rcode == dns.RcodeSuccess && len(resp.Ns) > 0 && len(resp.Answer) == 0 {
					for _, rr := range resp.Ns {
						if nsrec, ok := rr.(*dns.NS); ok {
							// looks invalid configuration, try another server
							if dns.CountLabel(nsrec.Header().Name) <= level {
								configErrors = append(configErrors, resp)

								// lets move back this server in the list.
								atomic.AddInt64(&server.Rtt, 2*time.Second.Nanoseconds())
								atomic.AddInt64(&server.Count, 1)

								if left > 0 && len(serversList)-1 == index {
									continue fallbackloop
								}
								continue mainloop
							}
						}
					}
				}

				return resp, nil
			}
		}
	}

	if len(responseErrors) > 0 {
		for _, resp := range responseErrors {
			// if we have other errors, we can try choose nameerror first
			if resp.Rcode == dns.RcodeNameError {
				return resp, nil
			}
		}
		return responseErrors[0], nil
	}

	if len(configErrors) > 0 {
		return configErrors[0], nil
	}

	if len(fatalErrors) > 0 {
		return nil, fatalError(errConnectionFailed)
	}

	zlog.Fatal("Looks like no root servers, check your config")

	return nil, fatalError(errNoRootServers)
}

func (r *Resolver) exchange(ctx context.Context, proto string, req *dns.Msg, server *authcache.AuthServer, retried int) (*dns.Msg, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	q := req.Question[0]

	var resp *dns.Msg
	var err error

	// Track RTT for adaptive timeouts
	var rtt = r.netTimeout
	defer func() {
		atomic.AddInt64(&server.Rtt, rtt.Nanoseconds())
		atomic.AddInt64(&server.Count, 1)
	}()

	// Check if we should use TCP connection pooling
	var pooledConn *dns.Conn
	var isRoot, isTLD bool

	if proto == "tcp" && r.tcpPool != nil && r.cfg.TCPKeepalive {
		// Check if this is a root or TLD server
		isRoot = isRootServer(server.Addr)
		if !isRoot && len(req.Question) > 0 {
			isTLD = isTLDServer(req.Question[0].Name)
		}

		// Try to get a pooled connection
		if isRoot || isTLD {
			pooledConn = r.tcpPool.Get(server.Addr, isRoot, isTLD)
			if pooledConn != nil {
				zlog.Debug("Using pooled TCP connection", "server", server.Addr, "isRoot", isRoot, "isTLD", isTLD)
			}
		}
	}

	d := r.newDialer(ctx, proto, server.Version)

	co := AcquireConn()

	if pooledConn != nil {
		// Use the pooled connection
		co.Conn = pooledConn.Conn
	} else {
		// Create new connection
		co.Conn, err = d.DialContext(ctx, proto, server.Addr)
		if err != nil {
			zlog.Debug("Dial failed to upstream server", "query", formatQuestion(q), "upstream", server.Addr,
				"net", proto, "error", err.Error(), "retried", retried)
			ReleaseConn(co)
			return nil, err
		}
	}

	// Add EDNS-Keepalive option if using TCP pooling
	if proto == "tcp" && r.tcpPool != nil && r.cfg.TCPKeepalive && (isRoot || isTLD) {
		SetEDNSKeepalive(req, 0) // Request keepalive with no specific timeout
	}

	// Set deadline respecting both network timeout and context deadline
	deadline := time.Now().Add(r.netTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = co.SetDeadline(deadline)

	resp, rtt, err = co.Exchange(req)
	if err != nil {
		zlog.Debug("Exchange failed for upstream server", "query", formatQuestion(q), "upstream", server.Addr,
			"net", proto, "rtt", rtt.Round(time.Millisecond).String(), "error", err.Error(), "retried", retried)

		// Don't return connection to pool on error
		ReleaseConn(co)

		if retried < 2 {
			if retried == 1 && proto == "udp" {
				proto = "tcp"
			}
			// retry
			retried++
			return r.exchange(ctx, proto, req, server, retried)
		}

		return nil, err
	}

	// Handle connection pooling
	if proto == "tcp" && r.tcpPool != nil && r.cfg.TCPKeepalive && (isRoot || isTLD) {
		// Return connection to pool
		dnsConn := &dns.Conn{Conn: co.Conn, UDPSize: co.UDPSize}
		r.tcpPool.Put(dnsConn, server.Addr, isRoot, isTLD, resp)
		// Don't close the connection since it's pooled
		co.Conn = nil
	}

	ReleaseConn(co)

	if resp != nil && resp.Truncated && proto == "udp" {
		return r.exchange(ctx, "tcp", req, server, retried)
	}

	if resp != nil && !resp.Truncated && proto == "udp" && resp.Len() > util.DefaultMsgSize {
		// If response is too large, switch to TCP
		zlog.Debug("Response too large, switching to TCP", "query", formatQuestion(q), "upstream", server.Addr,
			"size", resp.Len(), "maxSize", util.DefaultMsgSize, "retried", retried)
		return r.exchange(ctx, "tcp", req, server, retried)
	}

	if resp != nil && resp.Rcode == dns.RcodeFormatError && req.IsEdns0() != nil {
		// try again without edns tags, some weird servers didn't implement that
		req = util.ClearOPT(req)
		return r.exchange(ctx, proto, req, server, retried)
	}

	return resp, nil
}

func (r *Resolver) newDialer(ctx context.Context, proto string, version authcache.Version) (d *net.Dialer) {
	// Calculate deadline respecting both network timeout and context deadline
	deadline := time.Now().Add(r.netTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	d = &net.Dialer{Deadline: deadline}

	reqid := 0
	if v := ctx.Value(contextKeyRequestID); v != nil {
		reqid = int(v.(uint16))
	}

	switch version {
	case authcache.IPv4:
		if len(r.outboundipv4) > 0 {
			// we will be select outbound ip address by request id.
			index := len(r.outboundipv4) * reqid / maxUint16

			// port number will automatically chosen
			switch proto {
			case "tcp":
				d.LocalAddr = &net.TCPAddr{IP: r.outboundipv4[index]}
			case "udp":
				d.LocalAddr = &net.UDPAddr{IP: r.outboundipv4[index]}
			}
		}
	case authcache.IPv6:
		if len(r.outboundipv6) > 0 {
			index := len(r.outboundipv6) * reqid / maxUint16

			// port number will automatically chosen
			switch proto {
			case "tcp":
				d.LocalAddr = &net.TCPAddr{IP: r.outboundipv6[index]}
			case "udp":
				d.LocalAddr = &net.UDPAddr{IP: r.outboundipv6[index]}
			}
		}
	}

	return d
}

func (r *Resolver) searchCache(q dns.Question, cd bool, origin string) (servers *authcache.AuthServers, parentdsrr []dns.RR, level int) {
	if q.Qtype == dns.TypeDS {
		// DS queries are answered by parent zone, move up one label
		next, end := dns.NextLabel(q.Name, 0)

		q.Name = q.Name[next:]
		if end {
			q.Name = rootzone
		}
	}

	q.Qtype = dns.TypeNS // we should search NS type in cache
	key := cache.Key(q, cd)

	ns, err := r.ncache.Get(key)

	if err == nil {
		if atomic.LoadUint32(&ns.Servers.ErrorCount) >= 10 {
			// we have fatal errors from all servers, lets clear cache and try again
			r.ncache.Remove(key)
			q.Name = origin
			return r.searchCache(q, cd, origin)
		}
		zlog.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", cd)
		return ns.Servers, ns.DSRR, dns.CompareDomainName(origin, q.Name)
	}

	if !cd {
		key := cache.Key(q, true)
		ns, err := r.ncache.Get(key)

		if err == nil && len(ns.DSRR) == 0 {
			if atomic.LoadUint32(&ns.Servers.ErrorCount) >= 10 {
				r.ncache.Remove(key)
				q.Name = origin
				return r.searchCache(q, cd, origin)
			}
			zlog.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", true)
			return ns.Servers, ns.DSRR, dns.CompareDomainName(origin, q.Name)
		}
	}

	next, end := dns.NextLabel(q.Name, 0)

	if end {
		return r.rootservers, nil, 0 // reached root zone, use root servers
	}

	q.Name = q.Name[next:]

	return r.searchCache(q, cd, origin) // recursive walk up DNS tree
}

func (r *Resolver) findRRSIG(resp *dns.Msg, qname string, inAnswer bool) (signer string, signerFound bool) {
	rrset := resp.Ns
	if inAnswer {
		rrset = resp.Answer
	}

	for _, r := range rrset {
		var sigrec *dns.RRSIG
		var dnameCover bool

		if sig, ok := r.(*dns.RRSIG); ok {
			sigrec = sig
			if sigrec.TypeCovered == dns.TypeDNAME {
				dnameCover = true
			}
		}

		if inAnswer && !strings.EqualFold(r.Header().Name, qname) && !dnameCover {
			continue
		}

		if sigrec != nil {
			signer = sigrec.SignerName
			signerFound = true
			break
		}
	}

	return
}

func (r *Resolver) findDS(ctx context.Context, signer, qname string, parentdsrr []dns.RR) (dsset []dns.RR, err error) {
	if signer == rootzone && len(parentdsrr) == 0 {
		parentdsrr = r.dsRRFromRootKeys()
	} else if len(parentdsrr) > 0 {
		dsrr := parentdsrr[0].(*dns.DS)
		dsname := strings.ToLower(dsrr.Header().Name)

		if signer == "" {
			// generally auth server directly return answer without DS records
			n := dns.CompareDomainName(dsname, qname)
			nsplit := dns.SplitDomainName(qname)

			for len(nsplit)-n > 0 {
				candidate := dns.Fqdn(strings.Join(nsplit[len(nsplit)-n-1:], "."))

				dsResp, err := r.lookupDS(ctx, candidate)
				if err != nil {
					return nil, err
				}

				parentdsrr = extractRRSet(dsResp.Answer, candidate, dns.TypeDS)
				if len(parentdsrr) == 0 {
					break
				}

				n = dns.CompareDomainName(candidate, qname)
			}

		} else if dsname != signer {
			// try lookup DS records
			dsResp, err := r.lookupDS(ctx, signer)
			if err != nil {
				return nil, err
			}

			parentdsrr = extractRRSet(dsResp.Answer, signer, dns.TypeDS)
		}
	}

	dsset = parentdsrr

	return
}

func (r *Resolver) lookupDS(ctx context.Context, qname string) (msg *dns.Msg, err error) {
	zlog.Debug("Lookup DS record", "qname", qname)

	dsReq := new(dns.Msg)
	dsReq.SetQuestion(qname, dns.TypeDS)
	dsReq.SetEdns0(util.DefaultMsgSize, true)

	dsres, err := util.ExchangeInternal(ctx, dsReq)
	if err != nil {
		return nil, err
	}

	if len(dsres.Answer) == 0 && len(dsres.Ns) == 0 {
		return nil, fmt.Errorf("DS or NSEC records not found")
	}

	return dsres, nil
}

func (r *Resolver) lookupNSAddrV4(ctx context.Context, qname string, cd bool) (addrs []string, err error) {
	zlog.Debug("Lookup NS ipv4 address", "qname", qname)

	if addrs, ok := r.getIPv4Cache(qname); ok {
		return addrs, nil
	}

	ctx = context.WithValue(ctx, contextKeyNSL, struct{}{})

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeA)
	nsReq.SetEdns0(util.DefaultMsgSize, true)
	nsReq.CheckingDisabled = cd

	nsres, err := util.ExchangeInternal(ctx, nsReq)
	if err != nil {
		return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s (%v)", qname, err)
	}

	if addrs, ok := searchAddrs(nsres); ok {
		return addrs, nil
	}

	// try look glue cache
	if addrs, ok := r.getIPv4Cache(qname); ok {
		return addrs, nil
	}

	return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s", qname)
}

func (r *Resolver) lookupNSAddrV6(ctx context.Context, qname string, cd bool) (addrs []string, err error) {
	zlog.Debug("Lookup NS ipv6 address", "qname", qname)

	if addrs, ok := r.getIPv6Cache(qname); ok {
		return addrs, nil
	}

	ctx = context.WithValue(ctx, contextKeyNSL, struct{}{})

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeAAAA)
	nsReq.SetEdns0(util.DefaultMsgSize, true)
	nsReq.CheckingDisabled = cd

	nsres, err := util.ExchangeInternal(ctx, nsReq)
	if err != nil {
		return addrs, fmt.Errorf("nameserver ipv6 address lookup failed for %s (%v)", qname, err)
	}

	if addrs, ok := searchAddrs(nsres); ok {
		return addrs, nil
	}

	// try look glue cache
	if addrs, ok := r.getIPv6Cache(qname); ok {
		return addrs, nil
	}

	return addrs, fmt.Errorf("nameserver ipv6 address lookup failed for %s", qname)
}

func (r *Resolver) lookupV4Nss(ctx context.Context, q dns.Question, authservers *authcache.AuthServers, key uint64, parentdsrr []dns.RR, foundv4, nss nameservers, cd bool) {
	list := sortnss(nss, q.Name)

	for _, name := range list {
		authservers.Nss = append(authservers.Nss, name)

		if _, ok := foundv4[name]; ok {
			continue
		}

		ctx, loop := r.checkLoop(ctx, name, dns.TypeA)
		if loop {
			if _, ok := r.getIPv4Cache(name); !ok {
				zlog.Debug("Looping during ns ipv4 lookup", "query", formatQuestion(q), "ns", name)
				continue
			}
		}

		if len(authservers.List) > 0 {
			// temprorary cache before lookup
			r.ncache.Set(key, parentdsrr, authservers, time.Minute) // cache partial results during NS lookups
		}

		addrs, err := r.lookupNSAddrV4(ctx, name, cd)
		nsipv4 := make(map[string][]string)

		if err != nil {
			zlog.Debug("Lookup NS ipv4 address failed", "query", formatQuestion(q), "ns", name, "error", err.Error())
			continue
		}

		if len(addrs) == 0 {
			continue
		}

		nsipv4[name] = addrs

		authservers.Lock()
	addrsloop:
		for _, addr := range addrs {
			raddr := net.JoinHostPort(addr, "53")
			for _, s := range authservers.List {
				if s.Addr == raddr {
					continue addrsloop
				}
			}
			authservers.List = append(authservers.List, authcache.NewAuthServer(raddr, authcache.IPv4))
		}
		authservers.Unlock()
		r.addIPv4Cache(nsipv4)
	}
}

func (r *Resolver) lookupV6Nss(ctx context.Context, q dns.Question, authservers *authcache.AuthServers, foundv6, nss nameservers, cd bool) {
	// we can give sometimes for that lookups because of rate limiting on auth servers
	time.Sleep(defaultTimeout)

	list := sortnss(nss, q.Name)

	for _, name := range list {
		if _, ok := foundv6[name]; ok {
			continue
		}

		ctx, loop := r.checkLoop(ctx, name, dns.TypeAAAA)
		if loop {
			if _, ok := r.getIPv6Cache(name); !ok {
				zlog.Debug("Looping during ns ipv6 lookup", "query", formatQuestion(q), "ns", name)
				continue
			}
		}

		addrs, err := r.lookupNSAddrV6(ctx, name, cd)
		nsipv6 := make(map[string][]string)

		if err != nil {
			zlog.Debug("Lookup NS ipv6 address failed", "query", formatQuestion(q), "ns", name, "error", err.Error())
			return
		}

		if len(addrs) == 0 {
			return
		}

		nsipv6[name] = addrs

		authservers.Lock()
	addrsloop:
		for _, addr := range addrs {
			raddr := net.JoinHostPort(addr, "53")
			for _, s := range authservers.List {
				if s.Addr == raddr {
					continue addrsloop
				}
			}
			authservers.List = append(authservers.List, authcache.NewAuthServer(raddr, authcache.IPv6))
		}
		authservers.Unlock()
		r.addIPv6Cache(nsipv6)
	}
}

func (r *Resolver) dsRRFromRootKeys() (dsset []dns.RR) {
	r.RLock()
	defer r.RUnlock()

	for _, rr := range r.rootkeys {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			dsset = append(dsset, dnskey.ToDS(dns.DH))
		}
	}

	if len(dsset) == 0 {
		zlog.Fatal("Root zone dsset empty")
	}

	return
}

func (r *Resolver) verifyRootKeys(msg *dns.Msg) (ok bool) {
	r.RLock()
	defer r.RUnlock()

	keys := make(map[uint16]*dns.DNSKEY)
	for _, rr := range r.rootkeys {
		dnskey := rr.(*dns.DNSKEY)
		tag := dnskey.KeyTag()
		if dnskey.Flags == 257 {
			keys[tag] = dnskey
		}
	}

	if len(keys) == 0 {
		zlog.Fatal("Root zone keys empty")
	}

	dsset := []dns.RR{}
	for _, rr := range r.rootkeys {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			dsset = append(dsset, dnskey.ToDS(dns.DH))
		}
	}

	if len(dsset) == 0 {
		zlog.Fatal("Root zone dsset empty")
	}

	if _, err := verifyDS(keys, dsset); err != nil {
		zlog.Fatal("Root zone DS not verified")
	}

	if _, err := verifyRRSIG(keys, msg); err != nil {
		zlog.Fatal("Root zone keys not verified")
	}

	return true
}

func (r *Resolver) verifyDNSSEC(ctx context.Context, signer, signed string, resp *dns.Msg, parentdsRR []dns.RR) (ok bool, err error) {
	keyReq := new(dns.Msg)
	keyReq.SetQuestion(signer, dns.TypeDNSKEY)
	keyReq.SetEdns0(util.DefaultMsgSize, true)

	var msg *dns.Msg

	q := resp.Question[0]

	if q.Qtype != dns.TypeDNSKEY || q.Name != signer {
		msg, err = util.ExchangeInternal(ctx, keyReq)
		if err != nil {
			return
		}
	} else if q.Qtype == dns.TypeDNSKEY {
		if q.Name == rootzone {
			if !r.verifyRootKeys(resp) {
				return false, fmt.Errorf("root zone keys not verified")
			}
			return true, nil
		}

		msg = resp
	}

	keys := make(map[uint16]*dns.DNSKEY)
	for _, a := range msg.Answer {
		if a.Header().Rrtype == dns.TypeDNSKEY {
			dnskey := a.(*dns.DNSKEY)
			tag := dnskey.KeyTag()
			if dnskey.Flags == 256 || dnskey.Flags == 257 {
				keys[tag] = dnskey
			}
		}
	}

	if len(keys) == 0 {
		return false, errNoDNSKEY
	}

	if len(parentdsRR) == 0 {
		return false, fmt.Errorf("DS RR set empty")
	}

	unsupportedDigest, err := verifyDS(keys, parentdsRR)
	if err != nil {
		zlog.Debug("DNSSEC DS verify failed", "signer", signer, "signed", signed, "error", err.Error(), "unsupported digest", unsupportedDigest)
		if unsupportedDigest {
			return false, nil
		}
		return
	}

	// we don't need to verify rrsig questions.
	if q.Qtype == dns.TypeRRSIG {
		return false, nil
	}

	if ok, err = verifyRRSIG(keys, resp); err != nil {
		return
	}

	// Cannot verify DNSSEC keys with RSA exponents > 2^31-1 due to Go crypto/rsa limitation
	// See https://github.com/golang/go/issues/3161
	if !ok {
		return false, nil
	}

	zlog.Debug("DNSSEC verified", "signer", signer, "signed", signed, "query", formatQuestion(resp.Question[0]))

	return true, nil
}

func (r *Resolver) clearAdditional(req, resp *dns.Msg, extra ...bool) *dns.Msg {
	// Always clear authority section
	resp.Ns = []dns.RR{}

	// Clear extra section unless told to keep it (default is to clear)
	shouldClearExtra := len(extra) == 0 || !extra[0]

	if shouldClearExtra {
		resp.Extra = []dns.RR{}

		// Preserve EDNS0 if present
		if opt := req.IsEdns0(); opt != nil {
			resp.Extra = append(resp.Extra, opt)
		}
	}

	return resp
}

func (r *Resolver) equalServers(s1, s2 *authcache.AuthServers) bool {
	var list1, list2 []string

	s1.RLock()
	for _, s := range s1.List {
		list1 = append(list1, s.Addr)
	}
	s1.RUnlock()

	s2.RLock()
	for _, s := range s2.List {
		list2 = append(list2, s.Addr)
	}
	s2.RUnlock()

	if len(list1) != len(list2) {
		return false
	}

	sort.Strings(list1)
	sort.Strings(list2)

	for i, v := range list1 {
		if list2[i] != v {
			return false
		}
	}

	return true
}

func (r *Resolver) checkPriming() {
	req := new(dns.Msg)
	req.SetQuestion(rootzone, dns.TypeNS)
	req.SetEdns0(util.DefaultMsgSize, true)
	req.CheckingDisabled = !r.dnssec

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(r.netTimeout))
	defer cancel()

	if len(r.rootservers.List) == 0 {
		zlog.Fatal("Root servers list empty. check your config file")
	}

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 5, 0, false, nil, true)
	if err != nil {
		zlog.Error("Root servers update failed", "error", err.Error())
		return
	}

	if r.dnssec && !resp.AuthenticatedData {
		zlog.Error("Root servers update failed", "error", "not authenticated")
		return
	}

	// Count NS records and build a map of root server names
	nsServers := make(map[string]bool)
	for _, r := range resp.Answer {
		if ns, ok := r.(*dns.NS); ok {
			nsServers[strings.ToLower(ns.Ns)] = true
		}
	}

	if len(nsServers) == 0 {
		zlog.Error("Root servers update failed", "error", "no NS records in response")
		return
	}

	zlog.Debug("Root priming response", "ns_count", len(nsServers), "answer", len(resp.Answer), "extra", len(resp.Extra))

	var tmpservers authcache.AuthServers
	foundServers := make(map[string]bool)

	// Process IPv6 addresses if enabled
	if r.cfg.IPv6Access {
		for _, r := range resp.Extra {
			if v6, ok := r.(*dns.AAAA); ok {
				serverName := strings.ToLower(v6.Header().Name)
				if nsServers[serverName] {
					foundServers[serverName] = true
					host := net.JoinHostPort(v6.AAAA.String(), "53")
					tmpservers.List = append(tmpservers.List, authcache.NewAuthServer(host, authcache.IPv6))
				}
			}
		}
	}

	// Process IPv4 addresses
	for _, r := range resp.Extra {
		if v4, ok := r.(*dns.A); ok {
			serverName := strings.ToLower(v4.Header().Name)
			if nsServers[serverName] {
				foundServers[serverName] = true
				host := net.JoinHostPort(v4.A.String(), "53")
				tmpservers.List = append(tmpservers.List, authcache.NewAuthServer(host, authcache.IPv4))
			}
		}
	}

	// Verify we got addresses for at least some nameservers
	if len(foundServers) == 0 {
		zlog.Error("Root servers update failed", "error", "no A/AAAA records found for NS records")
		return
	}

	// Log a warning if we didn't get addresses for all nameservers (but continue)
	if len(foundServers) < len(nsServers) {
		zlog.Debug("Some root servers missing addresses", "ns_count", len(nsServers), "found", len(foundServers))
	}

	if len(tmpservers.List) >= len(r.rootservers.List) {
		r.rootservers.Lock()
		r.rootservers.List = tmpservers.List
		r.rootservers.Checked = true
		r.rootservers.Unlock()
		return
	}

	zlog.Error("Root servers update failed", "error", "missing A/AAAA records")
}

func (r *Resolver) run() {
	for !middleware.Ready() {
		// wait middleware setup
		time.Sleep(50 * time.Millisecond)
	}

	r.checkPriming() // update root server list from priming query
	if r.dnssec {
		r.AutoTA() // RFC 5011 automated trust anchor updates
	}

	ticker := time.NewTicker(12 * time.Hour)

	for range ticker.C {
		r.checkPriming()
		if r.dnssec {
			r.AutoTA()
		}
	}
}

// handleLookupError processes errors from groupLookup.
func (r *Resolver) handleLookupError(ctx context.Context, err error, rc *resolveContext, minReq *dns.Msg, minimized bool) (*dns.Msg, error) {
	if minimized {
		// retry without minimization
		rc.nomin = true
		rc.isRoot = false
		return r.resolve(ctx, rc)
	}

	if _, ok := err.(fatalError); ok {
		// no check for nsaddrs lookups
		if v := ctx.Value(contextKeyNSL); v != nil {
			return nil, err
		}

		zlog.Debug("Received network error from all servers", "query", formatQuestion(minReq.Question[0]))

		if atomic.AddUint32(&rc.servers.ErrorCount, 1) == 5 {
			if ok := r.checkNss(ctx, rc.servers); ok {
				return r.resolve(ctx, rc)
			}
		}
	}
	return nil, err
}

// processAuthoritySection handles the authority section of the response.
func (r *Resolver) processAuthoritySection(ctx context.Context, rc *resolveContext, minReq *dns.Msg, resp *dns.Msg, minimized bool) (*dns.Msg, error) {
	q := rc.req.Question[0]

	if minimized {
		// Check if we need to continue with minimization
		for _, rr := range resp.Ns {
			switch rr.(type) {
			case *dns.SOA, *dns.CNAME:
				rc.level++
				rc.isRoot = false
				return r.resolve(ctx, rc)
			}
		}
	}

	// Extract nameserver information
	nsInfo := r.extractNameserverInfo(resp)
	if len(nsInfo.nameservers) == 0 {
		return r.authority(ctx, minReq, resp, rc.parentDSRR, q.Qtype)
	}

	// Handle SOA records
	if nsInfo.hasSOA {
		resp.Ns = r.filterAuthorityRecords(resp.Ns)
		return r.authority(ctx, minReq, resp, rc.parentDSRR, q.Qtype)
	}

	// Process delegation
	return r.processDelegation(ctx, rc, resp, nsInfo, minimized)
}

// nameserverInfo holds extracted nameserver information.
type nameserverInfo struct {
	nameservers map[string]struct{}
	nsRecord    *dns.NS
	hasSOA      bool
}

// extractNameserverInfo extracts nameserver information from response.
func (r *Resolver) extractNameserverInfo(resp *dns.Msg) nameserverInfo {
	info := nameserverInfo{
		nameservers: make(map[string]struct{}),
	}

	for _, rr := range resp.Ns {
		switch v := rr.(type) {
		case *dns.SOA:
			info.hasSOA = true
		case *dns.NS:
			info.nsRecord = v
			info.nameservers[strings.ToLower(v.Ns)] = struct{}{}
		}
	}

	return info
}

// filterAuthorityRecords filters authority records for SOA responses.
func (r *Resolver) filterAuthorityRecords(nsRecords []dns.RR) []dns.RR {
	filtered := []dns.RR{}
	for _, rr := range nsRecords {
		switch rr.(type) {
		case *dns.SOA, *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// processDelegation handles delegation processing.
func (r *Resolver) processDelegation(ctx context.Context, rc *resolveContext, resp *dns.Msg, nsInfo nameserverInfo, minimized bool) (*dns.Msg, error) {
	nsrr := nsInfo.nsRecord
	q := dns.Question{Name: nsrr.Header().Name, Qtype: nsrr.Header().Rrtype, Qclass: nsrr.Header().Class}

	// DNSSEC validation for delegation
	newParentDS, err := r.validateDelegation(ctx, rc.req, resp, q, rc.parentDSRR)
	if err != nil {
		return nil, err
	}
	rc.parentDSRR = newParentDS

	// Check for parent detection
	nlevel := dns.CountLabel(q.Name)
	if rc.level > nlevel {
		if r.qnameMinLevel > 0 && !rc.nomin {
			// Try without minimization
			newRC := &resolveContext{
				req:        rc.req,
				servers:    r.rootservers,
				depth:      rc.depth,
				level:      0,
				nomin:      true,
				parentDSRR: nil,
				isRoot:     true,
				extra:      rc.extra,
			}
			return r.resolve(ctx, newRC)
		}
		return resp, errParentDetection
	}

	// Determine checking disabled state
	cd := rc.req.CheckingDisabled || len(rc.parentDSRR) == 0

	// Try nameserver cache
	key := cache.Key(q, cd)
	if ncache, err := r.ncache.Get(key); err == nil {
		return r.resolveWithCachedNameservers(ctx, rc, ncache, key, q, cd)
	}

	zlog.Debug("Nameserver cache not found", "key", key, "query", formatQuestion(q), "cd", cd)

	// Check glue records and perform lookups
	authservers, foundv4, foundv6 := r.checkGlueRR(resp, nsInfo.nameservers, rc.level)
	authservers.CheckingDisable = cd
	authservers.Zone = q.Name

	r.lookupV4Nss(ctx, q, authservers, key, rc.parentDSRR, foundv4, nsInfo.nameservers, cd)

	if len(authservers.List) == 0 {
		if minimized && rc.level < nlevel {
			rc.level++
			rc.isRoot = false
			return r.resolve(ctx, rc)
		}
		return nil, errNoReachableAuth
	}

	// Cache nameservers
	r.ncache.Set(key, rc.parentDSRR, authservers, time.Duration(nsrr.Header().Ttl)*time.Second)
	zlog.Debug("Nameserver cache insert", "key", key, "query", formatQuestion(q), "cd", cd)

	// Start IPv6 lookups in background
	if r.cfg.IPv6Access {
		reqid := ctx.Value(contextKeyRequestID)
		v6ctx := context.WithValue(context.Background(), contextKeyRequestID, reqid)
		go r.lookupV6Nss(v6ctx, q, authservers, foundv6, nsInfo.nameservers, cd)
	}

	rc.depth--
	if rc.depth <= 0 {
		return nil, errMaxDepth
	}

	// Continue resolution with new servers
	rc.servers = authservers
	rc.level = nlevel
	rc.isRoot = false
	return r.resolve(ctx, rc)
}

// validateDelegation performs DNSSEC validation for delegation.
func (r *Resolver) validateDelegation(ctx context.Context, req, resp *dns.Msg, q dns.Question, parentdsrr []dns.RR) ([]dns.RR, error) {
	signer, signerFound := r.findRRSIG(resp, q.Name, false)

	if !signerFound && len(parentdsrr) > 0 && req.Question[0].Qtype == dns.TypeDS {
		zlog.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "error", errDSRecords.Error())
		return nil, errDSRecords
	}

	var err error
	parentdsrr, err = r.findDS(ctx, signer, q.Name, parentdsrr)
	if err != nil {
		return nil, err
	}

	if !signerFound && len(parentdsrr) > 0 {
		zlog.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "error", errDSRecords.Error())
		return nil, errDSRecords
	}

	if len(parentdsrr) > 0 && !req.CheckingDisabled {
		if _, err := r.verifyDNSSEC(ctx, signer, q.Name, resp, parentdsrr); err != nil {
			zlog.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "signer", signer, "signed", q.Name, "error", err.Error())
			return nil, err
		}

		parentdsrr = extractRRSet(resp.Ns, q.Name, dns.TypeDS)

		// Check NSEC3
		if nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3); len(nsec3Set) > 0 {
			if err := verifyDelegation(q.Name, nsec3Set); err != nil {
				zlog.Warn("NSEC3 verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())
				return nil, err
			}
			return []dns.RR{}, nil
		}

		// Check NSEC
		if nsecSet := extractRRSet(resp.Ns, q.Name, dns.TypeNSEC); len(nsecSet) > 0 {
			if !verifyNSEC(q, nsecSet) {
				zlog.Warn("NSEC verify failed (delegation)", "query", formatQuestion(q), "error", "NSEC verify failed")
				return nil, fmt.Errorf("NSEC verify failed")
			}
			return []dns.RR{}, nil
		}
	}

	return parentdsrr, nil
}

// resolveWithCachedNameservers handles resolution with cached nameservers.
func (r *Resolver) resolveWithCachedNameservers(ctx context.Context, rc *resolveContext, ncache *authcache.NS, key uint64, q dns.Question, cd bool) (*dns.Msg, error) {
	zlog.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", cd)

	if r.equalServers(ncache.Servers, rc.servers) {
		// Potential loop, decrease depth faster
		rc.depth -= 10
	} else {
		rc.depth--
	}

	if rc.depth <= 0 {
		return nil, errMaxDepth
	}

	rc.level++
	rc.servers = ncache.Servers
	rc.parentDSRR = ncache.DSRR
	rc.isRoot = false
	return r.resolve(ctx, rc)
}
