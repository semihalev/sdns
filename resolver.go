package main

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
)

// Resolver type
type Resolver struct {
	config   *dns.ClientConfig
	nsCache  *cache.NSCache
	rCache   *cache.QueryCache
	errCache *cache.ErrorCache
	lqueue   *cache.LQueue
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
	rootservers     = []*cache.AuthServer{}
	root6servers    = []*cache.AuthServer{}
	fallbackservers = []*cache.AuthServer{}
	rootkeys        = []dns.RR{}
)

// NewResolver return a resolver
func NewResolver() *Resolver {
	r := &Resolver{
		config:   &dns.ClientConfig{},
		nsCache:  cache.NewNSCache(),
		rCache:   cache.NewQueryCache(Config.Maxcount, Config.RateLimit),
		errCache: cache.NewErrorCache(Config.Maxcount, Config.Expire),
		lqueue:   cache.NewLookupQueue(),
	}

	r.checkPriming()

	go r.run()

	return r
}

// Resolve will try find nameservers recursively
func (r *Resolver) Resolve(Net string, req *dns.Msg, servers []*cache.AuthServer, root bool, depth int, level int, nsl bool, parentdsrr []dns.RR, extra ...bool) (*dns.Msg, error) {
	q := req.Question[0]

	if root && req.Question[0].Qtype != dns.TypeDS {
		servers, parentdsrr = r.searchCache(q)
	}

	resp, err := r.lookup(Net, req, servers)
	if err != nil {
		return nil, err
	}

	resp.RecursionAvailable = true
	resp.AuthenticatedData = true
	resp.Authoritative = false

	if resp.Truncated {
		return resp, nil
	}

	if resp.Rcode != dns.RcodeSuccess {
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

	if len(resp.Answer) > 0 {
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
				if !strings.Contains(err.Error(), errNoDNSKEY.Error()) { //some servers timedout for DNSKEY queries, ignoring
					return nil, err
				}
			} else if !ok {
				log.Warn("DNSSEC cannot verify at the moment (answer)", "query", formatQuestion(q))
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

		key := cache.Hash(q)

		nsCache, err := r.nsCache.Get(key)
		if err == nil {

			if equalSlice(nsCache.Servers, servers) {
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
					log.Debug("Glue NS addr in extra response", "qname", extra.Header().Name, "A", extra.A.String())
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
				authservers := []*cache.AuthServer{}
				for _, s := range nservers {
					authservers = append(authservers, cache.NewAuthServer(s))
				}

				r.nsCache.Set(key, nil, nsrr.Header().Ttl, authservers)
			}
			//non extra rr for some nameservers, try lookup
			for k, addr := range nsmap {
				if addr == "" {
					addr, err := r.lookupNSAddr(Net, k, q.Name, depth)
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

		authservers := []*cache.AuthServer{}
		for _, s := range nservers {
			authservers = append(authservers, cache.NewAuthServer(s))
		}

		//final cache
		err = r.nsCache.Set(key, parentdsrr, nsrr.Header().Ttl, authservers)
		if err != nil {
			log.Error("Set nameserver cache failed", "query", formatQuestion(q), "error", err.Error())
		} else {
			log.Debug("Nameserver cache insert", "key", key, "query", formatQuestion(q))
		}

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

func (r *Resolver) lookup(Net string, req *dns.Msg, servers []*cache.AuthServer) (resp *dns.Msg, err error) {
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
		Config.OutboundIPs = shuffleStr(Config.OutboundIPs)

		if Net == "tcp" {
			c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(Config.OutboundIPs[0])}
		} else if Net == "udp" {
			c.Dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(Config.OutboundIPs[0])}
		}
	}

	sort.Slice(servers, func(i, j int) bool { return servers[i].RTT < servers[j].RTT })

	for index, server := range servers {
		resp, err := r.exchange(server, req, c)
		if err != nil {
			if len(servers)-1 == index {
				return resp, err
			}

			continue
		}

		return resp, err
	}

	return nil, errors.New("unknown error")
}

func (r *Resolver) exchange(server *cache.AuthServer, req *dns.Msg, c *dns.Client) (*dns.Msg, error) {
	q := req.Question[0]

	var resp *dns.Msg
	var err error

	resp, server.RTT, err = c.Exchange(req, server.Host)
	if err != nil && err != dns.ErrTruncated {
		if strings.Contains(err.Error(), "no route to host") && c.Net == "udp" {
			c.Net = "tcp"
			if len(Config.OutboundIPs) > 0 {
				c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(Config.OutboundIPs[0])}
			}

			return r.exchange(server, req, c)
		}

		server.RTT = time.Hour
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

func (r *Resolver) searchCache(q dns.Question) (servers []*cache.AuthServer, parentdsrr []dns.RR) {
	key := cache.Hash(q)

	ns, err := r.nsCache.Get(key)

	if err == nil {
		log.Debug("Nameserver cache hit", "key", key, "query", formatQuestion(q))
		return ns.Servers, ns.DSRR
	}

	q.Name = upperName(q.Name)

	if q.Name == "" {
		return rootservers, nil
	}

	return r.searchCache(q)
}

func (r *Resolver) lookupDS(Net, qname string, depth int) (msg *dns.Msg, err error) {
	log.Debug("Lookup DS record", "qname", qname)

	dsReq := new(dns.Msg)
	dsReq.SetQuestion(qname, dns.TypeDS)
	dsReq.SetEdns0(DefaultMsgSize, true)
	dsReq.RecursionDesired = true

	key := cache.Hash(dsReq.Question[0])

	dsres, _, err := r.rCache.Get(key, dsReq)
	if err == nil {
		return dsres, nil
	}

	err = r.errCache.Get(key)
	if err == nil {
		return nil, fmt.Errorf("ds records error occurred (cached)")
	}

	if depth <= 0 {
		return nil, fmt.Errorf("ds records max depth reach")
	}

	depth--
	dsres, err = r.Resolve(Net, dsReq, rootservers, true, depth, 0, true, nil)
	if err != nil {
		r.errCache.Set(key)
		return nil, err
	}

	if dsres.Truncated && dsres.Rcode == dns.RcodeSuccess {
		//retrying in TCP mode
		return r.lookupDS("tcp", qname, depth+1)
	}

	if len(dsres.Answer) == 0 && len(dsres.Ns) == 0 {
		return nil, fmt.Errorf("no answer found")
	}

	r.rCache.Set(key, dsres)

	return dsres, nil
}

func (r *Resolver) lookupNSAddr(Net string, ns, qname string, depth int) (addr string, err error) {
	log.Debug("Lookup NS address", "qname", ns)

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(ns, dns.TypeA)
	nsReq.SetEdns0(DefaultMsgSize, true)
	nsReq.RecursionDesired = true

	q := nsReq.Question[0]

	key := cache.Hash(q)

	if c := r.lqueue.Get(key); c != nil {
		return "", fmt.Errorf("nameserver address lookup failed for %s (like loop?)", ns)
	}

	nsres, _, err := r.rCache.Get(key, nsReq)
	if err == nil {
		if addr, ok := searchAddr(nsres); ok {
			return addr, nil
		}
	}

	err = r.errCache.Get(key)
	if err == nil {
		return "", fmt.Errorf("nameserver address lookup failed for %s (cached)", ns)
	}

	r.lqueue.Add(key)
	defer r.lqueue.Done(key)

	if depth <= 0 {
		return "", fmt.Errorf("nameserver address lookup failed for %s (max depth)", ns)
	}

	depth--
	nsres, err = r.Resolve(Net, nsReq, rootservers, true, depth, 0, true, nil)
	if err != nil {
		//try fallback servers
		if len(fallbackservers) > 0 {
			nsres, err = r.lookup(Net, nsReq, fallbackservers)
		}
	}

	if err != nil {
		r.errCache.Set(key)
		return addr, fmt.Errorf("nameserver address lookup failed for %s (%v)", ns, err)
	}

	if nsres.Truncated && nsres.Rcode == dns.RcodeSuccess {
		//retrying in TCP mode
		r.lqueue.Done(key)
		return r.lookupNSAddr("tcp", ns, qname, depth+1)
	}

	if len(nsres.Answer) == 0 && len(nsres.Ns) == 0 {
		//try fallback servers
		if len(fallbackservers) > 0 {
			nsres, err = r.lookup(Net, nsReq, fallbackservers)
			if err != nil {
				r.errCache.Set(key)
				return addr, fmt.Errorf("nameserver address lookup failed for %s (%v)", ns, err)
			}
		}
	}

	if addr, ok := searchAddr(nsres); ok {
		r.rCache.Set(key, nsres)
		return addr, nil
	}

	r.errCache.Set(key)
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

	msg, _, err := r.rCache.Get(cacheKey, keyReq)
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

			r.rCache.Set(cacheKey, resp)
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

	r.rCache.Set(cacheKey, msg)

	if !ok {
		return false, nil
	}

	log.Debug("DNSSEC verified", "signer", signer, "signed", signed, "query", formatQuestion(resp.Question[0]))

	return true, nil
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

	if len(resp.Extra) > 0 {
		var tmpservers, tmp6servers []*cache.AuthServer

		for _, r := range resp.Extra {
			if r.Header().Rrtype == dns.TypeA {
				if v4, ok := r.(*dns.A); ok {
					host := net.JoinHostPort(v4.A.String(), "53")
					tmpservers = append(tmpservers, cache.NewAuthServer(host))
				}
			}

			if r.Header().Rrtype == dns.TypeAAAA {
				if v6, ok := r.(*dns.AAAA); ok {
					host := net.JoinHostPort(v6.AAAA.String(), "53")
					tmp6servers = append(tmp6servers, cache.NewAuthServer(host))
				}
			}
		}

		if len(tmpservers) > 0 {
			rootservers = tmpservers
		}

		if len(tmp6servers) > 0 {
			root6servers = tmp6servers
		}

		if len(tmpservers) > 0 || len(tmp6servers) > 0 {
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
