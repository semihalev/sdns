package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// Resolver type
type Resolver struct {
	ncache *authcache.NSCache

	cfg *config.Config

	rootservers *authcache.AuthServers

	outboundipv4 []net.IP
	outboundipv6 []net.IP

	// glue addrs cache
	ipv4cache *cache.Cache
	ipv6cache *cache.Cache

	rootkeys []dns.RR

	qnameMinLevel int
	netTimeout    time.Duration

	group singleflight
}

type nameservers map[string]struct{}

type fatalError error

var (
	errMaxDepth        = errors.New("maximum recursion depth for dns tree queried")
	errParentDetection = errors.New("parent servers detected")
	errDSRecords       = errors.New("DS records found on parent zone but no signatures")
)

const (
	rootzone         = "."
	maxUint16        = 1 << 16
	defaultCacheSize = 1024 * 256
	defaultTimeout   = 2 * time.Second
)

// NewResolver return a resolver
func NewResolver(cfg *config.Config) *Resolver {
	r := &Resolver{
		cfg: cfg,

		ncache: authcache.NewNSCache(),

		rootservers: new(authcache.AuthServers),

		ipv4cache: cache.New(defaultCacheSize),
		ipv6cache: cache.New(defaultCacheSize),

		qnameMinLevel: cfg.QnameMinLevel,
		netTimeout:    defaultTimeout,
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
			log.Crit("Root keys invalid", "error", err.Error())
		}
		r.rootkeys = append(r.rootkeys, rr)
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

	for _, s := range cfg.Root6Servers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To16() != nil {
			r.rootservers.List = append(r.rootservers.List, authcache.NewAuthServer(s, authcache.IPv6))
		}
	}
}

func (r *Resolver) parseOutBoundAddrs(cfg *config.Config) {
	for _, s := range cfg.OutboundIPs {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			if isLocalIP(ip) {
				r.outboundipv4 = append(r.outboundipv4, ip)
			} else {
				log.Crit(fmt.Sprintf("%s is not your local ipv4 address, check your config!", ip))
			}
		}
	}

	for _, s := range cfg.OutboundIP6s {
		if ip := net.ParseIP(s); ip != nil && ip.To16() != nil {
			if isLocalIP(ip) {
				r.outboundipv6 = append(r.outboundipv6, ip)
			} else {
				log.Crit(fmt.Sprintf("%s is not your local ipv6 address, check your config!", ip))
			}
		}
	}
}

// Resolve iterate recursively over the domains
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg, servers *authcache.AuthServers, root bool, depth int, level int, nomin bool, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	q := req.Question[0]

	if root {
		servers, parentdsrr, level = r.searchCache(q, req.CheckingDisabled, q.Name)
	}

	// RFC 7816 query minimization. There are some concerns in RFC.
	// Current default minimize level 5, if we down to level 3, performance gain 20%
	minReq, minimized := r.minimize(req, level, nomin)

	log.Debug("Query inserted", "reqid", minReq.Id, "zone", servers.Zone, "query", formatQuestion(minReq.Question[0]), "cd", req.CheckingDisabled, "qname-minimize", minimized)

	resp, err := r.groupLookup(ctx, minReq, servers)
	if err != nil {
		if minimized {
			// return without minimized
			return r.Resolve(ctx, req, servers, false, depth, level, true, parentdsrr, extra...)
		}

		if _, ok := err.(fatalError); ok {
			// no check for nsaddrs lookups
			if v := ctx.Value(ctxKey("nsl")); v != nil {
				return nil, err
			}

			log.Debug("Received network error from all servers", "query", formatQuestion(minReq.Question[0]))

			if atomic.AddUint32(&servers.ErrorCount, 1) == 5 {
				if ok := r.checkNss(ctx, servers); ok {
					return r.Resolve(ctx, req, servers, root, depth, level, nomin, parentdsrr, extra...)
				}
			}
		}
		return nil, err
	}

	resp = r.setTags(req, resp)

	if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) == 0 && len(resp.Ns) == 0 {
		if minimized {
			level++
			return r.Resolve(ctx, req, servers, false, depth, level, nomin, parentdsrr)
		}
		return resp, nil
	}

	if !minimized && len(resp.Answer) > 0 {
		// this is like auth server external cname error but this can be recover.
		if resp.Rcode == dns.RcodeServerFailure && len(resp.Answer) > 0 {
			resp.Rcode = dns.RcodeSuccess
		}

		if resp.Rcode == dns.RcodeNameError {
			return r.authority(ctx, req, resp, parentdsrr, req.Question[0].Qtype)
		}

		return r.answer(ctx, req, resp, parentdsrr, extra...)
	}

	if minimized && (len(resp.Answer) == 0 && len(resp.Ns) == 0) || len(resp.Answer) > 0 {
		level++
		return r.Resolve(ctx, req, servers, false, depth, level, nomin, parentdsrr)
	}

	if len(resp.Ns) > 0 {
		if minimized {
			for _, rr := range resp.Ns {
				if _, ok := rr.(*dns.SOA); ok {
					level++
					return r.Resolve(ctx, req, servers, false, depth, level, nomin, parentdsrr)
				}

				if _, ok := rr.(*dns.CNAME); ok {
					level++
					return r.Resolve(ctx, req, servers, false, depth, level, nomin, parentdsrr)
				}
			}
		}

		var nsrr *dns.NS

		soa := false
		nss := make(nameservers)
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.SOA); ok {
				soa = true
			}

			if nsrec, ok := rr.(*dns.NS); ok {
				nsrr = nsrec
				nss[strings.ToLower(nsrec.Ns)] = struct{}{}
			}
		}

		if len(nss) == 0 {
			return r.authority(ctx, minReq, resp, parentdsrr, q.Qtype)
		}

		if soa {
			var authrrs []dns.RR
			authrrs = append(authrrs, resp.Ns...)
			resp.Ns = []dns.RR{}
			for _, rr := range authrrs {
				switch rr.(type) {
				case *dns.SOA, *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
					resp.Ns = append(resp.Ns, rr)
				}
			}
			return r.authority(ctx, minReq, resp, parentdsrr, q.Qtype)
		}

		q = dns.Question{Name: nsrr.Header().Name, Qtype: nsrr.Header().Rrtype, Qclass: nsrr.Header().Class}

		signer, signerFound := r.findRRSIG(resp, q.Name, false)
		if !signerFound && len(parentdsrr) > 0 && req.Question[0].Qtype == dns.TypeDS {
			log.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "error", errDSRecords.Error())

			return nil, errDSRecords
		}
		parentdsrr, err = r.findDS(ctx, signer, q.Name, resp, parentdsrr)
		if err != nil {
			return nil, err
		}

		if !signerFound && len(parentdsrr) > 0 {
			err = errDSRecords
			log.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())

			return nil, err
		} else if len(parentdsrr) > 0 {
			if !req.CheckingDisabled {
				_, err := r.verifyDNSSEC(ctx, signer, nsrr.Header().Name, resp, parentdsrr)
				if err != nil {
					log.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "signer", signer, "signed", nsrr.Header().Name, "error", err.Error())
					return nil, err
				}
			}

			parentdsrr = extractRRSet(resp.Ns, nsrr.Header().Name, dns.TypeDS)

			nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
			if len(nsec3Set) > 0 {
				err = verifyDelegation(nsrr.Header().Name, nsec3Set)
				if err != nil {
					log.Warn("NSEC3 verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())
					return nil, err
				}
				parentdsrr = []dns.RR{}
			} else {
				nsecSet := extractRRSet(resp.Ns, nsrr.Header().Name, dns.TypeNSEC)
				if len(nsecSet) > 0 {
					if !verifyNSEC(q, nsecSet) {
						log.Warn("NSEC verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())
						return nil, fmt.Errorf("NSEC verify failed")
					}
					parentdsrr = []dns.RR{}
				}
			}
		}

		nlevel := dns.CountLabel(q.Name)
		if level > nlevel {
			if r.qnameMinLevel > 0 && !nomin {
				//try without minimization
				return r.Resolve(ctx, req, r.rootservers, true, depth, 0, true, nil, extra...)
			}
			return resp, errParentDetection
		}

		cd := req.CheckingDisabled
		if len(parentdsrr) == 0 {
			cd = true
		}

		key := cache.Hash(q, cd)

		ncache, err := r.ncache.Get(key)
		if err == nil {
			log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", cd)

			if r.equalServers(ncache.Servers, servers) {
				// it may loop, lets continue fast.
				depth = depth - 10
			} else {
				depth--
			}

			if depth <= 0 {
				return nil, errMaxDepth
			}

			level++
			return r.Resolve(ctx, req, ncache.Servers, false, depth, level, nomin, ncache.DSRR)
		}

		log.Debug("Nameserver cache not found", "key", key, "query", formatQuestion(q), "cd", cd)

		authservers, foundv4, foundv6 := r.checkGlueRR(resp, nss, level)
		authservers.CheckingDisable = cd
		authservers.Zone = q.Name

		r.lookupV4Nss(ctx, q, authservers, key, parentdsrr, foundv4, nss, cd)

		if len(authservers.List) == 0 {
			if minimized && level < nlevel {
				level++
				return r.Resolve(ctx, req, servers, false, depth, level, nomin, parentdsrr)
			}

			return nil, errors.New("nameservers are unreachable")
		}

		r.ncache.Set(key, parentdsrr, authservers, time.Duration(nsrr.Header().Ttl)*time.Second)
		log.Debug("Nameserver cache insert", "key", key, "query", formatQuestion(q), "cd", cd)

		//copy reqid
		reqid := ctx.Value(ctxKey("reqid"))
		v6ctx := context.WithValue(context.Background(), ctxKey("reqid"), reqid)

		go r.lookupV6Nss(v6ctx, q, authservers, key, parentdsrr, foundv6, nss, cd)

		depth--

		if depth <= 0 {
			return nil, errMaxDepth
		}

		return r.Resolve(ctx, req, authservers, false, depth, nlevel, nomin, parentdsrr)
	}

	// no answer, no authority. create new msg safer, sometimes received weird responses
	m := new(dns.Msg)

	m.Question = req.Question
	m.SetRcode(req, dns.RcodeSuccess)
	m.RecursionAvailable = true
	m.Extra = req.Extra

	return m, nil
}

func (r *Resolver) groupLookup(ctx context.Context, req *dns.Msg, servers *authcache.AuthServers) (resp *dns.Msg, err error) {
	q := req.Question[0]

	key := cache.Hash(q)
	resp, shared, err := r.group.Do(key, func() (*dns.Msg, error) {
		return r.lookup(ctx, req, servers)
	})

	if resp != nil && shared {
		resp = resp.Copy()
		resp.Id = req.Id
	}

	return resp, err
}

func (r *Resolver) checkLoop(ctx context.Context, qname string, qtype uint16) (context.Context, bool) {
	key := ctxKey("nslist:" + dns.TypeToString[qtype])

	if v := ctx.Value(key); v != nil {
		list := v.([]string)

		loopCount := 0
		for _, n := range list {
			if n == qname {
				loopCount++
				if loopCount > 1 {
					return ctx, true
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
				log.Debug("Looping during ns ipv4 lookup", "query", formatQuestion(q), "ns", name)
				continue
			}
		}

		if len(authservers.List) > 0 {
			// temprorary cache before lookup
			r.ncache.Set(key, parentdsrr, authservers, time.Minute)
		}

		addrs, err := r.lookupNSAddrV4(ctx, name, cd)
		nsipv4 := make(map[string][]string)

		if err != nil {
			log.Debug("Lookup NS ipv4 address failed", "query", formatQuestion(q), "ns", name, "error", err.Error())
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

func (r *Resolver) lookupV6Nss(ctx context.Context, q dns.Question, authservers *authcache.AuthServers, key uint64, parentdsrr []dns.RR, foundv6, nss nameservers, cd bool) {
	//we can give sometimes for that lookups because of rate limiting on auth servers
	time.Sleep(defaultTimeout)

	list := sortnss(nss, q.Name)

	for _, name := range list {
		if _, ok := foundv6[name]; ok {
			continue
		}

		ctx, loop := r.checkLoop(ctx, name, dns.TypeAAAA)
		if loop {
			if _, ok := r.getIPv6Cache(name); !ok {
				log.Debug("Looping during ns ipv6 lookup", "query", formatQuestion(q), "ns", name)
				continue
			}
		}

		addrs, err := r.lookupNSAddrV6(ctx, name, cd)
		nsipv6 := make(map[string][]string)

		if err != nil {
			log.Debug("Lookup NS ipv6 address failed", "query", formatQuestion(q), "ns", name, "error", err.Error())
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

func (r *Resolver) checkNss(ctx context.Context, servers *authcache.AuthServers) (ok bool) {
	servers.RLock()
	oldsize := len(servers.List)
	if servers.Checked || dns.CountLabel(servers.Zone) < 2 {
		servers.RUnlock()
		return false
	}
	servers.RUnlock()

	var raddrsv4 []string
	var raddrsv6 []string

	nsipv4 := make(map[string][]string)
	nsipv6 := make(map[string][]string)

	for _, name := range servers.Nss {
		r.removeIPv4Cache(name)
		addrs, err := r.lookupNSAddrV4(ctx, name, servers.CheckingDisable)
		if err != nil || len(addrs) == 0 {
			continue
		}

		raddrsv4 = append(raddrsv4, addrs...)

		nsipv4[name] = addrs
	}

	for _, name := range servers.Nss {
		r.removeIPv6Cache(name)
		addrs, err := r.lookupNSAddrV6(ctx, name, servers.CheckingDisable)
		if err != nil || len(addrs) == 0 {
			continue
		}

		raddrsv6 = append(raddrsv6, addrs...)

		nsipv6[name] = addrs
	}

	r.addIPv4Cache(nsipv4)
	r.addIPv6Cache(nsipv6)

	servers.Lock()
	defer servers.Unlock()

addrsloopv4:
	for _, addr := range raddrsv4 {
		raddr := net.JoinHostPort(addr, "53")
		for _, s := range servers.List {
			if s.Addr == raddr {
				continue addrsloopv4
			}
		}
		servers.List = append(servers.List, authcache.NewAuthServer(raddr, authcache.IPv4))
	}

addrsloopv6:
	for _, addr := range raddrsv6 {
		raddr := net.JoinHostPort(addr, "53")
		for _, s := range servers.List {
			if s.Addr == raddr {
				continue addrsloopv6
			}
		}
		servers.List = append(servers.List, authcache.NewAuthServer(raddr, authcache.IPv6))
	}

	servers.Checked = true

	return oldsize != len(servers.List)
}

func (r *Resolver) checkGlueRR(resp *dns.Msg, nss nameservers, level int) (*authcache.AuthServers, nameservers, nameservers) {
	authservers := &authcache.AuthServers{}

	foundv4 := make(nameservers)
	foundv6 := make(nameservers)

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

	// add glue records to cache
	r.addIPv4Cache(nsipv4)
	r.addIPv6Cache(nsipv6)

	return authservers, foundv4, foundv6
}

func (r *Resolver) addIPv4Cache(nsipv4 map[string][]string) {
	for name, addrs := range nsipv4 {
		key := cache.Hash(dns.Question{Name: name, Qtype: dns.TypeA})
		r.ipv4cache.Add(key, addrs)
	}
}

func (r *Resolver) getIPv4Cache(name string) ([]string, bool) {
	key := cache.Hash(dns.Question{Name: name, Qtype: dns.TypeA})
	if v, ok := r.ipv4cache.Get(key); ok {
		return v.([]string), ok
	}

	return []string{}, false
}

func (r *Resolver) removeIPv4Cache(name string) {
	r.ipv4cache.Remove(cache.Hash(dns.Question{Name: name, Qtype: dns.TypeA}))
}

func (r *Resolver) addIPv6Cache(nsipv6 map[string][]string) {
	for name, addrs := range nsipv6 {
		key := cache.Hash(dns.Question{Name: name, Qtype: dns.TypeAAAA})
		r.ipv6cache.Add(key, addrs)
	}
}

func (r *Resolver) getIPv6Cache(name string) ([]string, bool) {
	key := cache.Hash(dns.Question{Name: name, Qtype: dns.TypeAAAA})
	if v, ok := r.ipv6cache.Get(key); ok {
		return v.([]string), ok
	}

	return []string{}, false
}

func (r *Resolver) removeIPv6Cache(name string) {
	r.ipv6cache.Remove(cache.Hash(dns.Question{Name: name, Qtype: dns.TypeAAAA}))
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
				minReq.Question[0].Qtype = dns.TypeA
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
	q := resp.Question[0]

	if q.Qtype == dns.TypeCNAME {
		return nil, false
	}

	target := getDnameTarget(resp)
	if target != "" {
		req := new(dns.Msg)
		req.SetQuestion(target, q.Qtype)
		req.SetEdns0(dnsutil.DefaultMsgSize, true)

		msg, err := dnsutil.ExchangeInternal(ctx, req)
		if err != nil {
			return nil, false
		}

		return msg, true
	}

	return nil, false
}

func (r *Resolver) answer(ctx context.Context, req, resp *dns.Msg, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	if msg, ok := r.checkDname(ctx, resp); ok {
		resp.Answer = append(resp.Answer, msg.Answer...)
		resp.Rcode = msg.Rcode

		if len(msg.Answer) == 0 {
			return r.authority(ctx, req, resp, parentdsrr, req.Question[0].Qtype)
		}
	}

	if !req.CheckingDisabled {
		var err error
		q := req.Question[0]

		signer, signerFound := r.findRRSIG(resp, q.Name, true)
		if !signerFound && len(parentdsrr) > 0 && q.Qtype == dns.TypeDS {
			log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", errDSRecords.Error())
			return nil, errDSRecords
		}
		parentdsrr, err = r.findDS(ctx, signer, q.Name, resp, parentdsrr)
		if err != nil {
			return nil, err
		}

		if !signerFound && len(parentdsrr) > 0 {
			log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", errDSRecords.Error())
			return nil, errDSRecords
		} else if len(parentdsrr) > 0 {
			resp.AuthenticatedData, err = r.verifyDNSSEC(ctx, signer, strings.ToLower(q.Name), resp, parentdsrr)
			if err != nil {
				log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", err.Error())
				return nil, err
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
		if !signerFound && len(parentdsrr) > 0 && otype == dns.TypeDS {
			log.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", errDSRecords.Error())

			return nil, errDSRecords
		}

		parentdsrr, err = r.findDS(ctx, signer, q.Name, resp, parentdsrr)
		if err != nil {
			return nil, err
		}

		if !signerFound && len(parentdsrr) > 0 {
			err = errDSRecords
			log.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())

			return nil, err
		} else if len(parentdsrr) > 0 {
			ok, err := r.verifyDNSSEC(ctx, signer, q.Name, resp, parentdsrr)
			if err != nil {
				log.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
				return nil, err
			}

			if ok && resp.Rcode == dns.RcodeNameError {
				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if len(nsec3Set) > 0 {
					err = verifyNameError(resp, nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
						return nil, err
					}

					//TODO: verify NSEC name error??
					/*} else {

					nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC)
					if len(nsecSet) > 0 {

					}*/
				}
			}

			if ok && q.Qtype == dns.TypeDS {
				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if len(nsec3Set) > 0 {
					err = verifyNODATA(resp, nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (NODATA)", "query", formatQuestion(q), "error", err.Error())
						return nil, err
					}

					//TODO: verify NSEC nodata??
					/*} else {

					nsecSet := extractRRSet(resp.Ns, q.Name, dns.TypeNSEC)
					if len(nsecSet) > 0 {

					}*/
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

	authcache.Sort(serversList, atomic.AddUint64(&servers.Called, 1))

	responseErrors := []*dns.Msg{}
	configErrors := []*dns.Msg{}
	fatalErrors := []error{}

	returned := make(chan struct{})
	defer close(returned)

	// modified version of golang dialParallel func
	type exchangeResult struct {
		resp *dns.Msg
		error
		server *authcache.AuthServer
	}

	results := make(chan exchangeResult)

	startRacer := func(ctx context.Context, req *dns.Msg, server *authcache.AuthServer) {
		resp, err := r.exchange(ctx, "udp", req, server, 0)
		defer ReleaseMsg(req)

		select {
		case results <- exchangeResult{resp: resp, server: server, error: err}:
		case <-returned:
		}
	}

	fallbackTimeout := 150 * time.Millisecond

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(fallbackTimeout)
	defer fallbackTimer.Stop()

	left := len(serversList)

mainloop:
	for index, server := range serversList {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		go startRacer(ctx, req.CopyTo(AcquireMsg()), server)

	fallbackloop:
		for left != 0 {
			fallbackTimer.Reset(fallbackTimeout)

			select {
			case <-fallbackTimer.C:
				if left > 0 && len(serversList)-1 == index {
					continue fallbackloop
				}
				continue mainloop
			case res := <-results:
				left--

				if res.error != nil {
					fatalErrors = append(fatalErrors, res.error)

					if left > 0 && len(serversList)-1 == index {
						continue fallbackloop
					}
					continue mainloop
				}

				resp = res.resp

				if resp.Rcode != dns.RcodeSuccess {
					responseErrors = append(responseErrors, resp)

					//we don't need to look all nameservers for that response
					if len(responseErrors) > 2 && resp.Rcode == dns.RcodeNameError {
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
		return nil, fatalError(errors.New("connection failed to upstream servers"))
	}

	panic("looks like no root servers, check your config")
}

func (r *Resolver) exchange(ctx context.Context, proto string, req *dns.Msg, server *authcache.AuthServer, retried int) (*dns.Msg, error) {
	q := req.Question[0]

	var resp *dns.Msg
	var err error

	rtt := r.netTimeout
	defer func() {
		atomic.AddInt64(&server.Rtt, rtt.Nanoseconds())
		atomic.AddInt64(&server.Count, 1)
	}()

	d := r.newDialer(ctx, proto, server.Version)

	co := AcquireConn()
	defer ReleaseConn(co) // this will be close conn also

	co.Conn, err = d.DialContext(ctx, proto, server.Addr)
	if err != nil {
		log.Debug("Dial failed to upstream server", "query", formatQuestion(q), "upstream", server.Addr,
			"net", proto, "rtt", rtt.Round(time.Millisecond).String(), "error", err.Error(), "retried", retried)
		return nil, err
	}

	_ = co.SetDeadline(time.Now().Add(r.netTimeout))

	resp, rtt, err = co.Exchange(req)
	if err != nil {
		log.Debug("Exchange failed for upstream server", "query", formatQuestion(q), "upstream", server.Addr,
			"net", proto, "rtt", rtt.Round(time.Millisecond).String(), "error", err.Error(), "retried", retried)

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

	if resp != nil && resp.Truncated && proto == "udp" {
		return r.exchange(ctx, "tcp", req, server, retried)
	}

	if resp != nil && resp.Rcode == dns.RcodeFormatError && req.IsEdns0() != nil {
		// try again without edns tags, some weird servers didn't implement that
		req = dnsutil.ClearOPT(req)
		return r.exchange(ctx, proto, req, server, retried)
	}

	return resp, nil
}

func (r *Resolver) newDialer(ctx context.Context, proto string, version authcache.Version) (d *net.Dialer) {
	d = &net.Dialer{Deadline: time.Now().Add(r.netTimeout)}

	reqid := 0
	if v := ctx.Value(ctxKey("reqid")); v != nil {
		reqid = int(v.(uint16))
	}

	if version == authcache.IPv4 {
		if len(r.outboundipv4) > 0 {
			//we will be select outbound ip address by request id.
			index := len(r.outboundipv4) * reqid / maxUint16

			// port number will automatically chosen
			if proto == "tcp" {
				d.LocalAddr = &net.TCPAddr{IP: r.outboundipv4[index]}
			} else if proto == "udp" {
				d.LocalAddr = &net.UDPAddr{IP: r.outboundipv4[index]}
			}
		}
	} else if version == authcache.IPv6 {
		if len(r.outboundipv6) > 0 {
			index := len(r.outboundipv6) * reqid / maxUint16

			// port number will automatically chosen
			if proto == "tcp" {
				d.LocalAddr = &net.TCPAddr{IP: r.outboundipv6[index]}
			} else if proto == "udp" {
				d.LocalAddr = &net.UDPAddr{IP: r.outboundipv6[index]}
			}
		}
	}

	return d
}

func (r *Resolver) searchCache(q dns.Question, cd bool, origin string) (servers *authcache.AuthServers, parentdsrr []dns.RR, level int) {
	if q.Qtype == dns.TypeDS {
		next, end := dns.NextLabel(q.Name, 0)

		q.Name = q.Name[next:]
		if end {
			q.Name = rootzone
		}
	}

	q.Qtype = dns.TypeNS // we should search NS type in cache
	key := cache.Hash(q, cd)

	ns, err := r.ncache.Get(key)

	if err == nil {
		if atomic.LoadUint32(&ns.Servers.ErrorCount) >= 10 {
			// we have fatal errors from all servers, lets clear cache and try again
			r.ncache.Remove(key)
			q.Name = origin
			return r.searchCache(q, cd, origin)
		}
		log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", cd)
		return ns.Servers, ns.DSRR, dns.CompareDomainName(origin, q.Name)
	}

	if !cd {
		key := cache.Hash(q, true)
		ns, err := r.ncache.Get(key)

		if err == nil && len(ns.DSRR) == 0 {
			if atomic.LoadUint32(&ns.Servers.ErrorCount) >= 10 {
				r.ncache.Remove(key)
				q.Name = origin
				return r.searchCache(q, cd, origin)
			}
			log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", true)
			return ns.Servers, ns.DSRR, dns.CompareDomainName(origin, q.Name)
		}
	}

	next, end := dns.NextLabel(q.Name, 0)

	if end {
		return r.rootservers, nil, 0
	}

	q.Name = q.Name[next:]
	level++

	return r.searchCache(q, cd, origin)
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

func (r *Resolver) findDS(ctx context.Context, signer, qname string, resp *dns.Msg, parentdsrr []dns.RR) (dsset []dns.RR, err error) {
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
	log.Debug("Lookup DS record", "qname", qname)

	dsReq := new(dns.Msg)
	dsReq.SetQuestion(qname, dns.TypeDS)
	dsReq.SetEdns0(dnsutil.DefaultMsgSize, true)

	dsres, err := dnsutil.ExchangeInternal(ctx, dsReq)
	if err != nil {
		return nil, err
	}

	if len(dsres.Answer) == 0 && len(dsres.Ns) == 0 {
		return nil, fmt.Errorf("DS or NSEC records not found")
	}

	return dsres, nil
}

func (r *Resolver) lookupNSAddrV4(ctx context.Context, qname string, cd bool) (addrs []string, err error) {
	log.Debug("Lookup NS ipv4 address", "qname", qname)

	if addrs, ok := r.getIPv4Cache(qname); ok {
		return addrs, nil
	}

	ctx = context.WithValue(ctx, ctxKey("nsl"), struct{}{})

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeA)
	nsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	nsReq.CheckingDisabled = cd

	nsres, err := dnsutil.ExchangeInternal(ctx, nsReq)
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
	log.Debug("Lookup NS ipv6 address", "qname", qname)

	if addrs, ok := r.getIPv6Cache(qname); ok {
		return addrs, nil
	}

	ctx = context.WithValue(ctx, ctxKey("nsl"), struct{}{})

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeAAAA)
	nsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	nsReq.CheckingDisabled = cd

	nsres, err := dnsutil.ExchangeInternal(ctx, nsReq)
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

func (r *Resolver) dsRRFromRootKeys() (dsset []dns.RR) {
	for _, rr := range r.rootkeys {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			dsset = append(dsset, dnskey.ToDS(dns.RSASHA1))
		}
	}

	if len(dsset) == 0 {
		panic("root zone dsset empty")
	}

	return
}

func (r *Resolver) verifyRootKeys(msg *dns.Msg) (ok bool) {
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
		panic("root zone keys empty")
	}

	dsset := []dns.RR{}
	for _, a := range r.rootkeys {
		if dnskey, ok := a.(*dns.DNSKEY); ok {
			dsset = append(dsset, dnskey.ToDS(dns.RSASHA1))
		}
	}

	if len(dsset) == 0 {
		panic("root zone dsset empty")
	}

	if _, err := verifyDS(keys, dsset); err != nil {
		panic("root zone DS not verified")
	}

	if _, err := verifyRRSIG(keys, msg); err != nil {
		panic("root zone keys not verified")
	}

	return true
}

func (r *Resolver) verifyDNSSEC(ctx context.Context, signer, signed string, resp *dns.Msg, parentdsRR []dns.RR) (ok bool, err error) {
	keyReq := new(dns.Msg)
	keyReq.SetQuestion(signer, dns.TypeDNSKEY)
	keyReq.SetEdns0(dnsutil.DefaultMsgSize, true)

	var msg *dns.Msg

	q := resp.Question[0]

	if q.Qtype != dns.TypeDNSKEY || q.Name != signer {
		msg, err = dnsutil.ExchangeInternal(ctx, keyReq)
		if err != nil {
			return
		}
	} else if q.Qtype == dns.TypeDNSKEY {
		if q.Name == rootzone {
			if !r.verifyRootKeys(resp) {
				return false, fmt.Errorf("root zone keys not verified")
			}

			log.Debug("Good! root keys verified and set in cache")
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
		log.Debug("DNSSEC DS verify failed", "signer", signer, "signed", signed, "error", err.Error(), "unsupported digest", unsupportedDigest)
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

	//TODO (semih): there is exponent problem in golang lib, we can't verify this.
	if !ok {
		return false, nil
	}

	log.Debug("DNSSEC verified", "signer", signer, "signed", signed, "query", formatQuestion(resp.Question[0]))

	return true, nil
}

func (r *Resolver) clearAdditional(req, resp *dns.Msg, extra ...bool) *dns.Msg {
	resp.Ns = []dns.RR{}

	noclear := len(extra) == 0
	if len(extra) > 0 && !extra[0] {
		noclear = true
	}

	if noclear {
		resp.Extra = []dns.RR{}

		opt := req.IsEdns0()
		if opt != nil {
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
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(r.netTimeout))
	defer cancel()

	if len(r.rootservers.List) == 0 {
		panic("root servers list empty. check your config file")
	}

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 5, 0, false, nil, true)
	if err != nil {
		log.Error("root servers update failed", "error", err.Error())

		return
	}

	if len(resp.Extra) > 0 {
		var tmpservers authcache.AuthServers

		// don't want to mixed ip address list, so first ipv6 then ipv4
		for _, r := range resp.Extra {
			if r.Header().Rrtype == dns.TypeAAAA {
				if v6, ok := r.(*dns.AAAA); ok {
					host := net.JoinHostPort(v6.AAAA.String(), "53")
					tmpservers.List = append(tmpservers.List, authcache.NewAuthServer(host, authcache.IPv6))
				}
			}
		}

		for _, r := range resp.Extra {
			if r.Header().Rrtype == dns.TypeA {
				if v4, ok := r.(*dns.A); ok {
					host := net.JoinHostPort(v4.A.String(), "53")
					tmpservers.List = append(tmpservers.List, authcache.NewAuthServer(host, authcache.IPv4))
				}
			}
		}

		if len(tmpservers.List) > 0 {
			r.rootservers.Lock()
			r.rootservers.List = tmpservers.List
			r.rootservers.Checked = true
			r.rootservers.Unlock()
		}

		if len(tmpservers.List) > 0 {
			log.Debug("Good! root servers update successful")

			return
		}
	}

	log.Error("root servers update failed", "error", "no records found")
}

func (r *Resolver) run() {
	for !middleware.Ready() {
		//wait middleware setup
		time.Sleep(50 * time.Millisecond)
	}

	r.checkPriming()

	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		r.checkPriming()
	}
}
