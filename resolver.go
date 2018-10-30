package main

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/semihalev/sdns/cache"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Resolver type
type Resolver struct {
	config *dns.ClientConfig

	Lqueue *cache.LQueue
	Qcache *cache.QueryCache
	Ncache *cache.NSCache
	Ecache *cache.ErrorCache
}

var (
	errMaxDepth             = errors.New("maximum recursion depth for DNS tree queried")
	errParentDetection      = errors.New("parent detection")
	errRootServersDetection = errors.New("root servers detection")
	errLoopDetection        = errors.New("loop detection")
	errTimeout              = errors.New("timedout")
	errResolver             = errors.New("resolv failed")
	errDSRecords            = errors.New("DS records found on parent zone but no signatures")

	rootzone        = "."
	rootservers     = &cache.AuthServers{}
	root6servers    = &cache.AuthServers{}
	fallbackservers = &cache.AuthServers{}
	rootkeys        = []dns.RR{}
)

// NewResolver return a resolver
func NewResolver() *Resolver {
	r := &Resolver{
		config: &dns.ClientConfig{},

		Ncache: cache.NewNSCache(),
		Qcache: cache.NewQueryCache(Config.CacheSize, Config.RateLimit),
		Ecache: cache.NewErrorCache(Config.CacheSize, Config.Expire),
		Lqueue: cache.NewLookupQueue(),
	}

	r.checkPriming()

	go r.run()

	return r
}

// Resolve will try find nameservers recursively
func (r *Resolver) Resolve(Net string, req *dns.Msg, servers *cache.AuthServers, root bool, depth int, level int, nsl bool, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	q := req.Question[0]

	if root && req.Question[0].Qtype != dns.TypeDS {
		servers, parentdsrr = r.searchCache(q, req.CheckingDisabled)
	}

	resp, err := r.lookup(Net, req, servers)
	if err != nil {
		return nil, err
	}

	resp.RecursionAvailable = true
	resp.Authoritative = false

	if resp.Truncated {
		return resp, nil
	}

	if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) == 0 {
		if resp.Rcode == dns.RcodeNameError {
			//TODO: should verify rrsig for nsecX records
			if upperName(q.Name) == "" {
				parentdsrr = r.dsRRFromRootKeys()
			}

			if len(parentdsrr) > 0 {
				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if len(nsec3Set) > 0 {
					err = verifyNameError(&q, nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (NXDOMAIN)", "query", formatQuestion(q), "error", err.Error())
						//TODO: after tests return error?
					}
				} else {
					nsecSet := extractRRSet(resp.Ns, q.Name, dns.TypeNSEC)
					if len(nsecSet) > 0 {
						//TODO: verify NSEC??
					}
				}
			}
		}

		return resp, nil
	}

	// This is like dns server config error but we can recover
	if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) > 0 {
		resp.Rcode = dns.RcodeSuccess
	}

	if len(resp.Answer) > 0 {
		if !req.CheckingDisabled {
			var signer string
			var signerFound bool

			for _, rr := range resp.Answer {
				if strings.ToLower(rr.Header().Name) != strings.ToLower(q.Name) {
					continue
				}
				if sigrec, ok := rr.(*dns.RRSIG); ok {
					signer = sigrec.SignerName
					signerFound = true
					break
				}
			}

			if signer == rootzone && len(parentdsrr) == 0 {
				parentdsrr = r.dsRRFromRootKeys()
			} else if len(parentdsrr) > 0 {
				dsrr := parentdsrr[0].(*dns.DS)
				dsname := strings.ToLower(dsrr.Header().Name)

				if signer == "" {
					//Generally auth server directly return answer without DS records
					n := dns.CompareDomainName(dsname, q.Name)
					nsplit := dns.SplitDomainName(q.Name)

					for len(nsplit)-n > 0 {
						candidate := dns.Fqdn(strings.Join(nsplit[len(nsplit)-n-1:], "."))

						dsDepth := Config.Maxdepth
						dsResp, err := r.lookupDS(Net, candidate, dsDepth)
						if err != nil {
							return nil, err
						}

						//verified nsec records with nodata function
						parentdsrr = extractRRSet(dsResp.Answer, candidate, dns.TypeDS)
						if len(parentdsrr) == 0 {
							break
						}

						n = dns.CompareDomainName(candidate, q.Name)
					}
				} else if dsname != signer {
					//try lookup DS records
					dsDepth := Config.Maxdepth
					dsResp, err := r.lookupDS(Net, signer, dsDepth)
					if err != nil {
						return nil, err
					}

					parentdsrr = extractRRSet(dsResp.Answer, signer, dns.TypeDS)
				}
			}

			if !signerFound && len(parentdsrr) > 0 {
				err = errDSRecords
				log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", err.Error())

				return nil, err
			} else if len(parentdsrr) > 0 {
				ok, err := r.verifyDNSSEC(Net, signer, strings.ToLower(q.Name), resp, parentdsrr)

				if err != nil {
					log.Warn("DNSSEC verify failed (answer)", "query", formatQuestion(q), "error", err.Error())

					return nil, err
				} else if !ok {
					log.Warn("DNSSEC cannot verify at the moment (answer)", "query", formatQuestion(q))
				}

				//set ad flag
				resp.AuthenticatedData = ok
			}
		}

		resp.Ns = []dns.RR{}

		if len(extra) == 0 {
			resp.Extra = []dns.RR{}

			opt := req.IsEdns0()
			if opt != nil {
				resp.Extra = append(resp.Extra, opt)
			}
		}

		return resp, nil
	}

	if len(resp.Ns) > 0 {
		var nsrr *dns.NS

		nsmap := make(map[string]string)
		for _, n := range resp.Ns {
			if nsrec, ok := n.(*dns.NS); ok {
				nsrr = nsrec
				nsmap[strings.ToLower(nsrec.Ns)] = ""
			}
		}

		if len(nsmap) == 0 {
			if q.Qtype == dns.TypeDS {
				//TODO: should verify nsec records
				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if len(nsec3Set) > 0 {
					err = verifyNODATA(&resp.Question[0], nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (NODATA)", "query", formatQuestion(q), "error", err.Error())
						return nil, err
					}
				} else {
					nsecSet := extractRRSet(resp.Ns, q.Name, dns.TypeNSEC)
					if len(nsecSet) > 0 {
						//verifiy NSEC?
					}
				}
			}

			return resp, nil
		}

		nlevel := len(dns.SplitDomainName(nsrr.Header().Name))
		if level > nlevel {
			return resp, errParentDetection
		}

		if nsrr.Header().Name == rootzone {
			return resp, errRootServersDetection
		}

		q := dns.Question{Name: nsrr.Header().Name, Qtype: nsrr.Header().Rrtype, Qclass: nsrr.Header().Class}

		key := cache.Hash(q, req.CheckingDisabled)

		nsCache, err := r.Ncache.Get(key)
		if err == nil {

			if r.equalServers(nsCache.Servers, servers) {
				return nil, errLoopDetection
			}

			log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q))

			if depth <= 0 {
				return nil, errMaxDepth
			}

			depth--
			return r.Resolve(Net, req, nsCache.Servers, false, depth, nlevel, nsl, nsCache.DSRR)
		}

		log.Debug("Nameserver cache not found", "key", key, "query", formatQuestion(q), "error", err.Error())

		for _, a := range resp.Extra {
			if extra, ok := a.(*dns.A); ok {
				name := strings.ToLower(extra.Header().Name)
				if nsl && name == strings.ToLower(req.Question[0].Name) && extra.A.String() != "" {
					resp.Answer = append(resp.Answer, extra)
					return resp, nil
				}

				if _, ok := nsmap[name]; ok {
					nsmap[name] = extra.A.String()
				}
			}
		}

		nservers := []string{}

		for _, addr := range nsmap {
			if addr != "" {
				if isLocalIP(addr) {
					continue
				}
				nservers = append(nservers, net.JoinHostPort(addr, "53"))
			}
		}

		if len(nsmap) > len(nservers) {
			if len(nservers) > 0 {
				// temprorary cache before lookup
				authservers := &cache.AuthServers{}
				for _, s := range nservers {
					authservers.List = append(authservers.List, cache.NewAuthServer(s))
				}

				r.Ncache.Set(key, nil, nsrr.Header().Ttl, authservers)
			}
			//non extra rr for some nameservers, try lookup
			for k, addr := range nsmap {
				if addr == "" {
					addr, err := r.lookupNSAddr(Net, k, q.Name, depth, req.CheckingDisabled)
					if err == nil {
						if isLocalIP(addr) {
							continue
						}
						nservers = append(nservers, net.JoinHostPort(addr, "53"))
					} else {
						log.Debug("Lookup NS addr failed", "query", formatQuestion(q), "ns", k, "error", err.Error())
					}
				}
			}
		}

		if len(nservers) == 0 {
			return nil, errors.New("nameservers are not reachable")
		}

		if !req.CheckingDisabled {
			var signer string
			var signerFound bool

			for _, rr := range resp.Ns {
				//no conditions because nsec3 records can be found different names
				if sigrec, ok := rr.(*dns.RRSIG); ok {
					signer = sigrec.SignerName
					signerFound = true
					break
				}
			}

			if signer == rootzone && len(parentdsrr) == 0 {
				parentdsrr = r.dsRRFromRootKeys()
			} else if len(parentdsrr) > 0 && req.Question[0].Qtype != dns.TypeDS {
				dsrr := parentdsrr[0].(*dns.DS)
				dsname := strings.ToLower(dsrr.Header().Name)

				if signer == "" {
					//Generally auth server directly return answer without DS records
					n := dns.CompareDomainName(dsname, q.Name)
					nsplit := dns.SplitDomainName(q.Name)

					for len(nsplit)-n > 0 {
						candidate := dns.Fqdn(strings.Join(nsplit[len(nsplit)-n-1:], "."))

						dsDepth := Config.Maxdepth
						dsResp, err := r.lookupDS(Net, candidate, dsDepth)
						if err != nil {
							return nil, err
						}

						//verified nsec records with nodata function
						parentdsrr = extractRRSet(dsResp.Answer, candidate, dns.TypeDS)
						if len(parentdsrr) == 0 {
							break
						}

						n = dns.CompareDomainName(candidate, q.Name)
					}
				} else if dsname != signer {
					//try lookup DS records
					dsDepth := Config.Maxdepth
					dsResp, err := r.lookupDS(Net, signer, dsDepth)
					if err != nil {
						return nil, err
					}

					parentdsrr = extractRRSet(dsResp.Answer, signer, dns.TypeDS)
				}
			}

			if !signerFound && len(parentdsrr) > 0 {
				err = errDSRecords
				log.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())

				return nil, err
			} else if len(parentdsrr) > 0 {
				ok, err := r.verifyDNSSEC(Net, signer, nsrr.Header().Name, resp, parentdsrr)
				if err != nil {
					log.Warn("DNSSEC verify failed (delegation)", "query", formatQuestion(q), "signer", signer, "signed", nsrr.Header().Name, "error", err.Error())
					return nil, err
				}

				if !ok {
					log.Warn("DNSSEC cannot verify at the moment (delegation)", "query", formatQuestion(q), "signer", signer, "signed", nsrr.Header().Name)
					ok = true
				}

				parentdsrr = extractRRSet(resp.Ns, nsrr.Header().Name, dns.TypeDS)

				nsec3Set := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
				if ok && len(nsec3Set) > 0 {
					err = verifyDelegation(nsrr.Header().Name, nsec3Set)
					if err != nil {
						log.Warn("NSEC3 verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())
						return nil, err
					}

					parentdsrr = []dns.RR{}
				} else {
					nsecSet := extractRRSet(resp.Ns, nsrr.Header().Name, dns.TypeNSEC)
					if ok && len(nsecSet) > 0 {
						if !verifyNSEC(&q, nsecSet) {
							log.Warn("NSEC verify failed (delegation)", "query", formatQuestion(q), "error", err.Error())
							return nil, fmt.Errorf("NSEC verify failed")
						}
						parentdsrr = []dns.RR{}
					}
				}
			}
		}

		authservers := &cache.AuthServers{}
		for _, s := range nservers {
			authservers.List = append(authservers.List, cache.NewAuthServer(s))
		}

		//final cache
		r.Ncache.Set(key, parentdsrr, nsrr.Header().Ttl, authservers)
		log.Debug("Nameserver cache insert", "key", key, "query", formatQuestion(q))

		if depth <= 0 {
			return nil, errMaxDepth
		}

		depth--
		return r.Resolve(Net, req, authservers, false, depth, nlevel, nsl, parentdsrr)
	}

	// no answer, no authority, create new msg safer, sometimes received broken response
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeSuccess)
	m.RecursionAvailable = true
	m.Extra = req.Extra

	return m, nil
}

func (r *Resolver) lookup(Net string, req *dns.Msg, servers *cache.AuthServers) (resp *dns.Msg, err error) {
	c := &dns.Client{
		Net: Net,
		Dialer: &net.Dialer{
			DualStack:     true,
			FallbackDelay: 100 * time.Millisecond,
			Timeout:       Config.ConnectTimeout.Duration,
		},
		ReadTimeout:  Config.Timeout.Duration,
		WriteTimeout: Config.Timeout.Duration,
	}

	if len(Config.OutboundIPs) > 0 {
		index := randInt(0, len(Config.OutboundIPs))

		if Net == "tcp" {
			c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(Config.OutboundIPs[index])}
		} else if Net == "udp" {
			c.Dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(Config.OutboundIPs[index])}
		}
	}

	servers.TrySort()

	servers.RLock()
	defer servers.RUnlock()

	for index, server := range servers.List {
		resp, err := r.exchange(server, req, c)
		if err != nil {
			if len(servers.List)-1 == index {
				return resp, err
			}

			continue
		}

		if resp.Rcode != dns.RcodeSuccess && len(servers.List)-1 != index {
			continue
		}

		return resp, err
	}

	panic("looks like no root servers, check your config")
}

func (r *Resolver) exchange(server *cache.AuthServer, req *dns.Msg, c *dns.Client) (*dns.Msg, error) {
	q := req.Question[0]

	var resp *dns.Msg
	var err error

	rtt := Config.Timeout.Duration
	defer func() {
		atomic.AddInt64(&server.Rtt, rtt.Nanoseconds())
		atomic.AddInt64(&server.Count, 1)
	}()

	resp, rtt, err = c.Exchange(req, server.Host)
	if err != nil && err != dns.ErrTruncated {
		if strings.Contains(err.Error(), "no route to host") && c.Net == "udp" {
			c.Net = "tcp"
			if len(Config.OutboundIPs) > 0 {
				c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(Config.OutboundIPs[0])}
			}

			return r.exchange(server, req, c)
		}

		log.Debug("Socket error in server communication", "query", formatQuestion(q), "server", server, "net", c.Net, "error", err.Error())

		return nil, err
	}

	if resp != nil && resp.Rcode == dns.RcodeFormatError && req.IsEdns0() != nil {
		// try again without edns tags
		req = clearOPT(req)
		return r.exchange(server, req, c)
	}

	return resp, nil
}

func (r *Resolver) searchCache(q dns.Question, cd bool) (servers *cache.AuthServers, parentdsrr []dns.RR) {
	key := cache.Hash(q, cd)

	ns, err := r.Ncache.Get(key)

	if err == nil {
		log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q))
		return ns.Servers, ns.DSRR
	}

	q.Name = upperName(q.Name)

	if q.Name == "" {
		return rootservers, nil
	}

	return r.searchCache(q, cd)
}

func (r *Resolver) lookupDS(Net, qname string, depth int) (msg *dns.Msg, err error) {
	log.Debug("Lookup DS record", "qname", qname)

	dsReq := new(dns.Msg)
	dsReq.SetQuestion(qname, dns.TypeDS)
	dsReq.SetEdns0(DefaultMsgSize, true)
	dsReq.RecursionDesired = true

	key := cache.Hash(dsReq.Question[0])

	dsres, _, err := r.Qcache.Get(key, dsReq)
	if err == nil {
		return dsres, nil
	}

	err = r.Ecache.Get(key)
	if err == nil {
		return nil, fmt.Errorf("ds records error occurred (cached)")
	}

	if depth <= 0 {
		return nil, fmt.Errorf("ds records max depth reach")
	}

	depth--
	dsres, err = r.Resolve(Net, dsReq, rootservers, true, depth, 0, true, nil)
	if err != nil {
		r.Ecache.Set(key)
		return nil, err
	}

	if dsres.Truncated && dsres.Rcode == dns.RcodeSuccess {
		//retrying in TCP mode
		return r.lookupDS("tcp", qname, depth+1)
	}

	if len(dsres.Answer) == 0 && len(dsres.Ns) == 0 {
		return nil, fmt.Errorf("no answer found")
	}

	r.Qcache.Set(key, dsres)

	return dsres, nil
}

func (r *Resolver) lookupNSAddr(Net string, ns, qname string, depth int, cd bool) (addr string, err error) {
	log.Debug("Lookup NS address", "qname", ns)

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(ns, dns.TypeA)
	nsReq.SetEdns0(DefaultMsgSize, true)
	nsReq.RecursionDesired = true
	nsReq.CheckingDisabled = cd

	q := nsReq.Question[0]

	key := cache.Hash(q, cd)

	if c := r.Lqueue.Get(key); c != nil {
		return "", fmt.Errorf("nameserver address lookup failed for %s (like loop?)", ns)
	}

	nsres, _, err := r.Qcache.Get(key, nsReq)
	if err == nil {
		if addr, ok := searchAddr(nsres); ok {
			return addr, nil
		}
	}

	err = r.Ecache.Get(key)
	if err == nil {
		return "", fmt.Errorf("nameserver address lookup failed for %s (cached)", ns)
	}

	r.Lqueue.Add(key)
	defer r.Lqueue.Done(key)

	if depth <= 0 {
		return "", fmt.Errorf("nameserver address lookup failed for %s (max depth)", ns)
	}

	depth--
	nsres, err = r.Resolve(Net, nsReq, rootservers, true, depth, 0, true, nil)
	if err != nil {
		//try fallback servers
		if len(fallbackservers.List) > 0 {
			nsres, err = r.lookup(Net, nsReq, fallbackservers)
		}
	}

	if err != nil {
		r.Ecache.Set(key)
		return addr, fmt.Errorf("nameserver address lookup failed for %s (%v)", ns, err)
	}

	if nsres.Truncated && nsres.Rcode == dns.RcodeSuccess {
		//retrying in TCP mode
		r.Lqueue.Done(key)
		return r.lookupNSAddr("tcp", ns, qname, depth+1, cd)
	}

	if len(nsres.Answer) == 0 && len(nsres.Ns) == 0 {
		//try fallback servers
		if len(fallbackservers.List) > 0 {
			nsres, err = r.lookup(Net, nsReq, fallbackservers)
			if err != nil {
				r.Ecache.Set(key)
				return addr, fmt.Errorf("nameserver address lookup failed for %s (%v)", ns, err)
			}
		}
	}

	if addr, ok := searchAddr(nsres); ok {
		r.Qcache.Set(key, nsres)
		return addr, nil
	}

	r.Ecache.Set(key)
	return addr, fmt.Errorf("nameserver address lookup failed for %s (no answer)", ns)
}

func (r *Resolver) dsRRFromRootKeys() (dsset []dns.RR) {
	for _, a := range rootkeys {
		if dnskey, ok := a.(*dns.DNSKEY); ok {
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
	for _, a := range rootkeys {
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

func (r *Resolver) verifyDNSSEC(Net string, signer, signed string, resp *dns.Msg, parentdsRR []dns.RR) (ok bool, err error) {
	keyReq := new(dns.Msg)
	keyReq.SetQuestion(signer, dns.TypeDNSKEY)
	keyReq.SetEdns0(DefaultMsgSize, true)
	keyReq.RecursionDesired = true

	q := keyReq.Question[0]

	cacheKey := cache.Hash(q)

	msg, _, err := r.Qcache.Get(cacheKey, keyReq)
	if resp.Question[0].Qtype != dns.TypeDNSKEY && msg == nil {
		depth := Config.Maxdepth
		msg, err = r.Resolve(Net, keyReq, rootservers, true, depth, 0, false, nil)
		if err != nil {
			return
		}

		if msg.Truncated {
			//retrying in TCP mode
			msg, err = r.Resolve("tcp", keyReq, rootservers, true, depth, 0, false, nil)
			if err != nil {
				return
			}
		}
	}

	if resp.Question[0].Qtype == dns.TypeDNSKEY {
		if resp.Question[0].Name == rootzone {
			if !r.verifyRootKeys(resp) {
				return false, fmt.Errorf("root zone keys not verified")
			}

			r.Qcache.Set(cacheKey, resp)
			log.Info("Good! root keys verified and set in cache")
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

	r.Qcache.Set(cacheKey, msg)

	if !ok {
		return false, nil
	}

	log.Debug("DNSSEC verified", "signer", signer, "signed", signed, "query", formatQuestion(resp.Question[0]))

	return true, nil
}

func (r *Resolver) equalServers(s1, s2 *cache.AuthServers) bool {
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
	req.SetEdns0(DefaultMsgSize, true)
	req.RecursionDesired = true

	resp, err := r.Resolve("udp", req, rootservers, true, 5, 0, false, nil, true)
	if err != nil {
		log.Error("root servers update failed", "error", err.Error())

		return err
	}

	if resp.Truncated {
		//retrying in TCP mode
		resp, err = r.Resolve("tcp", req, rootservers, true, 5, 0, false, nil, true)
		if err != nil {
			return err
		}
	}

	if len(resp.Extra) > 0 {
		var tmpservers, tmp6servers cache.AuthServers

		for _, r := range resp.Extra {
			if r.Header().Rrtype == dns.TypeA {
				if v4, ok := r.(*dns.A); ok {
					host := net.JoinHostPort(v4.A.String(), "53")
					tmpservers.List = append(tmpservers.List, cache.NewAuthServer(host))
				}
			}

			if r.Header().Rrtype == dns.TypeAAAA {
				if v6, ok := r.(*dns.AAAA); ok {
					host := net.JoinHostPort(v6.AAAA.String(), "53")
					tmp6servers.List = append(tmp6servers.List, cache.NewAuthServer(host))
				}
			}
		}

		if len(tmpservers.List) > 0 {
			rootservers.Lock()
			rootservers.List = tmpservers.List
			rootservers.Unlock()
		}

		if len(tmp6servers.List) > 0 {
			root6servers.Lock()
			root6servers.List = tmp6servers.List
			root6servers.Unlock()
		}

		if len(tmpservers.List) > 0 || len(tmp6servers.List) > 0 {
			log.Info("Good! root servers update successful")

			return nil
		}
	}

	log.Error("root servers update failed", "error", "no records found")

	return errors.New("no records found")
}

func (r *Resolver) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		r.checkPriming()
	}
}
