package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/lqueue"
)

// Resolver type
type Resolver struct {
	ncache *authcache.NSCache

	lqueue *lqueue.LQueue
	cfg    *config.Config

	rootservers     *authcache.AuthServers
	root6servers    *authcache.AuthServers
	fallbackservers *authcache.AuthServers

	// glue addrs cache
	ipv4cache *cache.Cache
	ipv6cache *cache.Cache

	rootkeys []dns.RR
}

var (
	errMaxDepth        = errors.New("maximum recursion depth for dns tree queried")
	errParentDetection = errors.New("parent servers detected")
	errDSRecords       = errors.New("DS records found on parent zone but no signatures")
)

const (
	rootzone = "."
)

// NewResolver return a resolver
func NewResolver(cfg *config.Config) *Resolver {
	r := &Resolver{
		cfg:    cfg,
		lqueue: lqueue.New(),

		ncache: authcache.NewNSCache(),

		rootservers:     new(authcache.AuthServers),
		root6servers:    new(authcache.AuthServers),
		fallbackservers: new(authcache.AuthServers),

		ipv4cache: cache.New(1024 * 128),
		ipv6cache: cache.New(1024 * 128),
	}

	if len(cfg.RootServers) > 0 {
		r.rootservers = &authcache.AuthServers{}
		for _, s := range cfg.RootServers {
			r.rootservers.List = append(r.rootservers.List, authcache.NewAuthServer(s))
		}
	}

	if len(cfg.Root6Servers) > 0 {
		r.root6servers = &authcache.AuthServers{}
		for _, s := range cfg.Root6Servers {
			r.root6servers.List = append(r.root6servers.List, authcache.NewAuthServer(s))
		}
	}

	if len(cfg.FallbackServers) > 0 {
		r.fallbackservers = &authcache.AuthServers{}
		for _, s := range cfg.FallbackServers {
			r.fallbackservers.List = append(r.fallbackservers.List, authcache.NewAuthServer(s))
		}
	}

	if len(cfg.RootKeys) > 0 {
		r.rootkeys = []dns.RR{}
		for _, k := range cfg.RootKeys {
			rr, err := dns.NewRR(k)
			if err != nil {
				log.Crit("Root keys invalid", "error", err.Error())
			}
			r.rootkeys = append(r.rootkeys, rr)
		}
	}

	go r.run()

	return r
}

// Resolve iterate recursively over the domains
func (r *Resolver) Resolve(ctx context.Context, proto string, req *dns.Msg, servers *authcache.AuthServers, root bool, depth int, level int, nsl bool, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	q := req.Question[0]

	if root {
		servers, parentdsrr, level = r.searchCache(q, req.CheckingDisabled, q.Name)
	}

	// RFC 7816 query minimization. There are some concerns in RFC.
	minReq, minimized := r.minimize(req, level)

	resp, err := r.lookup(ctx, proto, minReq, servers, level)
	if err != nil {
		return nil, err
	}

	resp = r.setTags(req, resp)

	if resp.Truncated {
		if minimized && proto == "udp" {
			return r.Resolve(ctx, "tcp", req, servers, false, depth, level, nsl, parentdsrr)
		}
		return resp, nil
	}

	if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) == 0 && len(resp.Ns) == 0 {
		if minimized {
			resp.Question = req.Question
		}
		return resp, nil
	}

	if !minimized && len(resp.Answer) > 0 {
		// this is like auth server external cname error but this can be recover.
		if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) > 0 {
			resp.Rcode = dns.RcodeSuccess
		}

		return r.answer(ctx, proto, req, resp, parentdsrr, extra...)
	}

	if minimized && len(resp.Answer) > 0 {
		for _, rr := range resp.Answer {
			resp.Ns = append(resp.Ns, rr)
		}
	}

	if len(resp.Ns) > 0 {
		if minimized {
			for _, rr := range resp.Ns {
				if _, ok := rr.(*dns.SOA); ok {
					level++
					return r.Resolve(ctx, proto, req, servers, false, depth, level, nsl, parentdsrr)
				}

				if _, ok := rr.(*dns.CNAME); ok {
					level++
					return r.Resolve(ctx, proto, req, servers, false, depth, level, nsl, parentdsrr)
				}
			}
		}

		var nsrr *dns.NS

		nss := make(map[string]struct{})
		for _, rr := range resp.Ns {
			if nsrec, ok := rr.(*dns.NS); ok {
				nsrr = nsrec
				nss[strings.ToLower(nsrec.Ns)] = struct{}{}
			}
		}

		if len(nss) == 0 {
			return r.authority(ctx, proto, minReq, resp, parentdsrr, q.Qtype)
		}

		q = dns.Question{Name: nsrr.Header().Name, Qtype: nsrr.Header().Rrtype, Qclass: nsrr.Header().Class}

		signer, signerFound := r.findRRSIG(resp, q.Name, false)
		parentdsrr, err = r.findDS(ctx, proto, signer, q.Name, resp, parentdsrr)
		if err != nil {
			return nil, err
		}

		if !signerFound && len(parentdsrr) > 0 {
			err = errDSRecords
			log.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())

			return nil, err
		} else if len(parentdsrr) > 0 {
			if !req.CheckingDisabled {
				_, err := r.verifyDNSSEC(ctx, proto, signer, nsrr.Header().Name, resp, parentdsrr)
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

		nlevel := len(dns.SplitDomainName(nsrr.Header().Name))
		if level > nlevel {
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

			return r.Resolve(ctx, proto, req, ncache.Servers, false, depth, nlevel, nsl, ncache.DSRR)
		}

		log.Debug("Nameserver cache not found", "key", key, "query", formatQuestion(q), "cd", cd)

		authservers := &authcache.AuthServers{}

		nsipv4 := make(map[string][]string)
		for _, a := range resp.Extra {
			if extra, ok := a.(*dns.A); ok {
				name := strings.ToLower(extra.Header().Name)

				if _, ok := nss[name]; ok {
					addr := extra.A.String()

					if isLocalIP(addr) {
						continue
					}

					if net.ParseIP(addr).IsLoopback() {
						continue
					}

					nsipv4[name] = append(nsipv4[name], addr)
					authservers.List = append(authservers.List, authcache.NewAuthServer(net.JoinHostPort(addr, "53")))
				}
			}
		}

		// add glue records to cache
		r.addIPv4Cache(nsipv4)

		if len(nss) > len(authservers.List) {
			if len(authservers.List) > 0 {
				// temprorary cache before lookup
				r.ncache.Set(key, parentdsrr, authservers)
			}

			// no extra rr for some nameservers, try lookup
			var wg sync.WaitGroup

			for name := range nss {
				wg.Add(1)
				go func(name string) {
					defer wg.Done()

					addrs, err := r.lookupNSAddrV4(ctx, proto, name, cd)
					if err != nil {
						log.Debug("Lookup NS ipv4 address failed", "query", formatQuestion(q), "ns", name, "error", err.Error())
						return
					}

					if len(addrs) == 0 {
						return
					}

					authservers.Lock()
					for _, addr := range addrs {
						authservers.List = append(authservers.List, authcache.NewAuthServer(net.JoinHostPort(addr, "53")))
					}
					authservers.Unlock()
				}(name)
			}

			wg.Wait()
		}

		if len(authservers.List) == 0 {
			if minimized && level < nlevel {
				level++
				return r.Resolve(ctx, proto, req, servers, false, depth, level, nsl, parentdsrr)
			}
			return nil, errors.New("nameservers are unreachable")
		}

		r.ncache.Set(key, parentdsrr, authservers)
		log.Debug("Nameserver cache insert", "key", key, "query", formatQuestion(q), "cd", cd)

		depth--

		if depth <= 0 {
			return nil, errMaxDepth
		}

		return r.Resolve(ctx, proto, req, authservers, false, depth, nlevel, nsl, parentdsrr)
	}

	// no answer, no authority. create new msg safer, sometimes received weird responses
	m := new(dns.Msg)

	m.Question = req.Question
	m.SetRcode(req, dns.RcodeSuccess)
	m.RecursionAvailable = true
	m.Extra = req.Extra

	return m, nil
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

func (r *Resolver) addIPv6Cache(nsipv6 map[string][]string) {
	for name, addrs := range nsipv6 {
		key := cache.Hash(dns.Question{Name: name, Qtype: dns.TypeAAAA})
		r.ipv4cache.Add(key, addrs)
	}
}

func (r *Resolver) getIPv6Cache(name string) ([]string, bool) {
	key := cache.Hash(dns.Question{Name: name, Qtype: dns.TypeAAAA})
	if v, ok := r.ipv6cache.Get(key); ok {
		return v.([]string), ok
	}

	return []string{}, false
}

func (r *Resolver) minimize(req *dns.Msg, level int) (*dns.Msg, bool) {
	q := req.Question[0]

	minReq := req.Copy()
	minimized := false

	if level < 3 && q.Name != rootzone {
		prev, end := dns.PrevLabel(q.Name, level+1)
		if !end {
			minimized = true
			minReq.Question[0].Name = q.Name[prev:]
			if minReq.Question[0].Name == q.Name {
				minimized = false
			} else {
				minReq.Question[0].Qtype = dns.TypeNS
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

func (r *Resolver) answer(ctx context.Context, proto string, req, resp *dns.Msg, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	if !req.CheckingDisabled {
		var err error
		q := req.Question[0]

		signer, signerFound := r.findRRSIG(resp, q.Name, true)
		parentdsrr, err = r.findDS(ctx, proto, signer, q.Name, resp, parentdsrr)
		if err != nil {
			return nil, err
		}

		if !signerFound && len(parentdsrr) > 0 {
			log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", errDSRecords.Error())
			return nil, errDSRecords
		} else if len(parentdsrr) > 0 {
			resp.AuthenticatedData, err = r.verifyDNSSEC(ctx, proto, signer, strings.ToLower(q.Name), resp, parentdsrr)
			if err != nil {
				log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", err.Error())
				return nil, err
			}
		}
	}

	resp = r.clearAdditional(req, resp, extra...)

	return resp, nil
}

func (r *Resolver) authority(ctx context.Context, proto string, req, resp *dns.Msg, parentdsrr []dns.RR, otype uint16) (*dns.Msg, error) {
	if !req.CheckingDisabled {
		var err error
		q := req.Question[0]

		signer, signerFound := r.findRRSIG(resp, q.Name, false)
		if !signerFound && len(parentdsrr) > 0 && otype == dns.TypeDS {
			err = errDSRecords
			log.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())

			return nil, err
		}

		parentdsrr, err = r.findDS(ctx, proto, signer, q.Name, resp, parentdsrr)
		if err != nil {
			return nil, err
		}

		if !signerFound && len(parentdsrr) > 0 {
			err = errDSRecords
			log.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())

			return nil, err
		} else if len(parentdsrr) > 0 {
			ok, err := r.verifyDNSSEC(ctx, proto, signer, q.Name, resp, parentdsrr)
			if err != nil {
				log.Warn("DNSSEC verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
				return nil, err
			}

			if ok && resp.Rcode == dns.RcodeNameError {
				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if len(nsec3Set) > 0 {
					err = verifyNameError(q, nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
						return nil, err
					}
				} else {
					nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC)
					if len(nsecSet) > 0 {
						//TODO: verify NSEC name error??
					}
				}
			}

			if ok && q.Qtype == dns.TypeDS {
				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if len(nsec3Set) > 0 {
					err = verifyNODATA(resp.Question[0], nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (NODATA)", "query", formatQuestion(q), "error", err.Error())
						return nil, err
					}
				} else {
					nsecSet := extractRRSet(resp.Ns, q.Name, dns.TypeNSEC)
					if len(nsecSet) > 0 {
						//TODO: verify NSEC nodata??
					}
				}
			}
		}
	}

	return resp, nil
}

func (r *Resolver) lookup(ctx context.Context, proto string, req *dns.Msg, servers *authcache.AuthServers, level int) (resp *dns.Msg, err error) {
	c := &dns.Client{
		Net: proto,
		Dialer: &net.Dialer{
			DualStack:     true,
			FallbackDelay: 100 * time.Millisecond,
			Timeout:       r.cfg.ConnectTimeout.Duration,
		},

		ReadTimeout:  r.cfg.Timeout.Duration,
		WriteTimeout: r.cfg.Timeout.Duration,
	}

	if len(r.cfg.OutboundIPs) > 0 {
		index := randInt(0, len(r.cfg.OutboundIPs))

		// port number will automatically chosen
		if proto == "tcp" {
			c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(r.cfg.OutboundIPs[index])}
		} else if proto == "udp" {
			c.Dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(r.cfg.OutboundIPs[index])}
		}
	}

	responseError := []int{}

	servers.TrySort()

	servers.RLock()
	defer servers.RUnlock()

tryagain:
	fatalServers := []int{}

mainloop:
	for index, server := range servers.List {
		resp, err = r.exchange(ctx, server, req, c)
		if err != nil {
			fatalServers = append(fatalServers, index)
			atomic.AddInt64(&server.Rtt, time.Second.Nanoseconds())

			continue
		}

		if resp.Rcode != dns.RcodeSuccess && len(servers.List)-1 > len(responseError) {
			responseError = append(responseError, index)
			err = nil

			continue
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Ns) > 0 && len(resp.Answer) == 0 {
			for _, rr := range resp.Ns {
				if nsrec, ok := rr.(*dns.NS); ok {
					check := false

					zLevel := dns.CountLabel(nsrec.Header().Name)
					if zLevel <= level {
						check = true
					}

					// looks invalid configuration, try another server
					if check {
						fatalServers = append(fatalServers, index)
						atomic.AddInt64(&server.Rtt, time.Second.Nanoseconds())

						continue mainloop
					}
				}
			}
		}

		return
	}

	if len(fatalServers) == len(servers.List) {
		return
	}

	if len(servers.List) > len(fatalServers) {
		goto tryagain
	}

	if len(servers.List) >= len(responseError) {
		return
	}

	panic("looks like no root servers, check your config")
}

func (r *Resolver) exchange(ctx context.Context, server *authcache.AuthServer, req *dns.Msg, c *dns.Client) (*dns.Msg, error) {
	q := req.Question[0]

	var resp *dns.Msg
	var err error

	rtt := r.cfg.Timeout.Duration
	defer func() {
		atomic.AddInt64(&server.Rtt, rtt.Nanoseconds())
		atomic.AddInt64(&server.Count, 1)
	}()

	resp, rtt, err = c.Exchange(req, server.Host)
	if err != nil {
		if c.Net == "udp" {
			c.Net = "tcp"
			if len(r.cfg.OutboundIPs) > 0 {
				index := randInt(0, len(r.cfg.OutboundIPs))
				c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(r.cfg.OutboundIPs[index])}
			}

			return r.exchange(ctx, server, req, c)
		}

		log.Debug("Socket error in server communication", "query", formatQuestion(q), "server", server, "net", c.Net, "error", err.Error())

		return nil, err
	}

	if resp != nil && resp.Rcode == dns.RcodeFormatError && req.IsEdns0() != nil {
		// try again without edns tags, some weird servers didn't implement that
		req = dnsutil.ClearOPT(req)
		return r.exchange(ctx, server, req, c)
	}

	return resp, nil
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
		log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q), "cd", cd)
		return ns.Servers, ns.DSRR, dns.CompareDomainName(origin, q.Name)
	}

	if !cd {
		key := cache.Hash(q, true)
		ns, err := r.ncache.Get(key)

		if err == nil && len(ns.DSRR) == 0 {
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

	for _, rr := range rrset {
		if inAnswer && !strings.EqualFold(rr.Header().Name, qname) {
			continue
		}
		if sigrec, ok := rr.(*dns.RRSIG); ok {
			signer = sigrec.SignerName
			signerFound = true
			break
		}
	}

	return
}

func (r *Resolver) findDS(ctx context.Context, proto, signer, qname string, resp *dns.Msg, parentdsrr []dns.RR) (dsset []dns.RR, err error) {
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

				dsResp, err := r.lookupDS(ctx, proto, candidate)
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
			dsResp, err := r.lookupDS(ctx, proto, signer)
			if err != nil {
				return nil, err
			}

			parentdsrr = extractRRSet(dsResp.Answer, signer, dns.TypeDS)
		}
	}

	dsset = parentdsrr

	return
}

func (r *Resolver) lookupDS(ctx context.Context, proto, qname string) (msg *dns.Msg, err error) {
	log.Debug("Lookup DS record", "qname", qname, "proto", proto)

	dsReq := new(dns.Msg)
	dsReq.SetQuestion(qname, dns.TypeDS)
	dsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	dsReq.RecursionDesired = true

	dsres, err := dnsutil.ExchangeInternal(ctx, proto, dsReq)
	if err != nil {
		return nil, err
	}

	if dsres.Truncated && proto == "udp" {
		// retrying in TCP mode
		return r.lookupDS(ctx, "tcp", qname)
	}

	if len(dsres.Answer) == 0 && len(dsres.Ns) == 0 {
		return nil, fmt.Errorf("DS or NSEC records not found")
	}

	return dsres, nil
}

func (r *Resolver) lookupNSAddrV4(ctx context.Context, proto string, qname string, cd bool) (addrs []string, err error) {
	log.Debug("Lookup NS ipv4 address", "qname", qname)

	// first look glue cache
	if addrs, ok := r.getIPv4Cache(qname); ok {
		return addrs, nil
	}

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeA)
	nsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	nsReq.RecursionDesired = true
	nsReq.CheckingDisabled = cd

	key := cache.Hash(nsReq.Question[0], cd)

	r.lqueue.Wait(key)

	if c := r.lqueue.Get(key); c != nil {
		// try look cache again
		if addrs, ok := r.getIPv4Cache(qname); ok {
			return addrs, nil
		}

		// loop here stop
		return addrs, nil
	}

	r.lqueue.Add(key)
	defer r.lqueue.Done(key)

	nsres, err := dnsutil.ExchangeInternal(ctx, proto, nsReq)
	if err != nil {
		// try fallback servers
		if len(r.fallbackservers.List) > 0 {
			nsres, err = r.lookup(ctx, proto, nsReq, r.fallbackservers, 0)
		}
	}

	if err != nil {
		return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s (%v)", qname, err)
	}

	if nsres.Truncated && proto == "udp" {
		// retrying in TCP mode
		r.lqueue.Done(key)
		return r.lookupNSAddrV4(ctx, "tcp", qname, cd)
	}

	if len(nsres.Answer) == 0 && len(nsres.Ns) == 0 {
		// try fallback servers
		if len(r.fallbackservers.List) > 0 {
			nsres, err = r.lookup(ctx, proto, nsReq, r.fallbackservers, 0)
			if err != nil {
				return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s (%v)", qname, err)
			}
		}
	}

	if addrs, ok := searchAddrs(nsres); ok {
		return addrs, nil
	}

	return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s", qname)
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

	if err := verifyDS(keys, dsset); err != nil {
		panic("root zone DS not verified")
	}

	if _, err := verifyRRSIG(keys, msg); err != nil {
		panic("root zone keys not verified")
	}

	return true
}

func (r *Resolver) verifyDNSSEC(ctx context.Context, proto string, signer, signed string, resp *dns.Msg, parentdsRR []dns.RR) (ok bool, err error) {
	keyReq := new(dns.Msg)
	keyReq.SetQuestion(signer, dns.TypeDNSKEY)
	keyReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	keyReq.RecursionDesired = true

	var msg *dns.Msg

	if resp.Question[0].Qtype != dns.TypeDNSKEY {
		msg, err = dnsutil.ExchangeInternal(ctx, proto, keyReq)
		if err != nil {
			return
		}

		if msg.Truncated && proto == "udp" {
			// retrying in TCP mode
			return r.verifyDNSSEC(ctx, "tcp", signer, signed, resp, parentdsRR)
		}
	} else if resp.Question[0].Qtype == dns.TypeDNSKEY {
		if resp.Question[0].Name == rootzone {
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

	err = verifyDS(keys, parentdsRR)
	if err != nil {
		log.Debug("DNSSEC DS verify failed", "signer", signer, "signed", signed, "error", err.Error())
		return
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

func (r *Resolver) equalServers(s1, s2 *authcache.AuthServers) bool {
	var list1, list2 []string

	s1.RLock()
	for _, s := range s1.List {
		list1 = append(list1, s.Host)
	}
	s1.RUnlock()

	s2.RLock()
	for _, s := range s2.List {
		list2 = append(list2, s.Host)
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

func (r *Resolver) checkPriming() error {
	req := new(dns.Msg)
	req.SetQuestion(rootzone, dns.TypeNS)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.RecursionDesired = true

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(r.cfg.Timeout.Duration))
	defer cancel()

	resp, err := r.Resolve(ctx, "udp", req, r.rootservers, true, 5, 0, false, nil, true)
	if err != nil {
		log.Error("root servers update failed", "error", err.Error())

		return err
	}

	if resp.Truncated {
		//retrying in TCP mode
		resp, err = r.Resolve(ctx, "tcp", req, r.rootservers, true, 5, 0, false, nil, true)
		if err != nil {
			return err
		}
	}

	if len(resp.Extra) > 0 {
		var tmpservers, tmp6servers authcache.AuthServers

		for _, r := range resp.Extra {
			if r.Header().Rrtype == dns.TypeA {
				if v4, ok := r.(*dns.A); ok {
					host := net.JoinHostPort(v4.A.String(), "53")
					tmpservers.List = append(tmpservers.List, authcache.NewAuthServer(host))
				}
			}

			if r.Header().Rrtype == dns.TypeAAAA {
				if v6, ok := r.(*dns.AAAA); ok {
					host := net.JoinHostPort(v6.AAAA.String(), "53")
					tmp6servers.List = append(tmp6servers.List, authcache.NewAuthServer(host))
				}
			}
		}

		if len(tmpservers.List) > 0 {
			r.rootservers.Lock()
			r.rootservers.List = tmpservers.List
			r.rootservers.Unlock()
		}

		if len(tmp6servers.List) > 0 {
			r.root6servers.Lock()
			r.root6servers.List = tmp6servers.List
			r.root6servers.Unlock()
		}

		if len(tmpservers.List) > 0 || len(tmp6servers.List) > 0 {
			log.Debug("Good! root servers update successful")

			return nil
		}
	}

	log.Error("root servers update failed", "error", "no records found")

	return errors.New("no records found")
}

func (r *Resolver) run() {
	r.checkPriming()

	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		r.checkPriming()
	}
}

func (r *Resolver) clearAdditional(req, resp *dns.Msg, extra ...bool) *dns.Msg {
	resp.Ns = []dns.RR{}

	noclear := len(extra) == 0
	if len(extra) > 0 && extra[0] == false {
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

// AuthCache returns nscache
func (r *Resolver) AuthCache() *authcache.NSCache {
	return r.ncache
}
