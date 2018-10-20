package main

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Resolver type
type Resolver struct {
	config   *dns.ClientConfig
	nsCache  *NameServerCache
	rCache   *QueryCache
	errCache *ErrorCache
	lqueue   *LQueue
}

var (
	errMaxDepth             = errors.New("maximum recursion depth for DNS tree queried")
	errParentDetection      = errors.New("parent detection")
	errRootServersDetection = errors.New("root servers detection")
	errLoopDetection        = errors.New("loop detection")
	errTimeout              = errors.New("timedout")
	errResolver             = errors.New("resolv failed")

	rootzone = "."

	rootservers = []*AuthServer{
		NewAuthServer("192.5.5.241:53"),
		NewAuthServer("198.41.0.4:53"),
		NewAuthServer("192.228.79.201:53"),
		NewAuthServer("192.33.4.12:53"),
		NewAuthServer("199.7.91.13:53"),
		NewAuthServer("192.203.230.10:53"),
		NewAuthServer("192.112.36.4:53"),
		NewAuthServer("128.63.2.53:53"),
		NewAuthServer("192.36.148.17:53"),
		NewAuthServer("192.58.128.30:53"),
		NewAuthServer("193.0.14.129:53"),
		NewAuthServer("199.7.83.42:53"),
		NewAuthServer("202.12.27.33:53"),
	}

	root6servers = []*AuthServer{
		NewAuthServer("[2001:500:2f::f]:53"),
		NewAuthServer("[2001:503:ba3e::2:30]:53"),
		NewAuthServer("[2001:500:200::b]:53"),
		NewAuthServer("[2001:500:2::c]:53"),
		NewAuthServer("[2001:500:2d::d]:53"),
		NewAuthServer("[2001:500:a8::e]:53"),
		NewAuthServer("[2001:500:12::d0d]:53"),
		NewAuthServer("[2001:500:1::53]:53"),
		NewAuthServer("[2001:7fe::53]:53"),
		NewAuthServer("[2001:503:c27::2:30]:53"),
		NewAuthServer("[2001:7fd::1]:53"),
		NewAuthServer("[2001:500:9f::42]:53"),
		NewAuthServer("[2001:dc3::35]:53"),
	}

	initialkeys = []string{
		".			172800	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=",
		".			172800	IN	DNSKEY	256 3 8 AwEAAdp440E6Mz7c+Vl4sPd0lTv2Qnc85dTW64j0RDD7sS/zwxWDJ3QRES2VKDO0OXLMqVJSs2YCCSDKuZXpDPuf++YfAu0j7lzYYdWTGwyNZhEaXtMQJIKYB96pW6cRkiG2Dn8S2vvo/PxW9PKQsyLbtd8PcwWglHgReBVp7kEv/Dd+3b3YMukt4jnWgDUddAySg558Zld+c9eGWkgWoOiuhg4rQRkFstMX1pRyOSHcZuH38o1WcsT4y3eT0U/SR6TOSLIB/8Ftirux/h297oS7tCcwSPt0wwry5OFNTlfMo8v7WGurogfk8hPipf7TTKHIi20LWen5RCsvYsQBkYGpF78=",
	}

	fallbackservers = []*AuthServer{
		NewAuthServer("8.8.8.8:53"),
		NewAuthServer("8.8.4.4:53"),
	}

	rootkeys = []dns.RR{}
)

// AuthServer type
type AuthServer struct {
	Host string
	RTT  time.Duration
}

// NewAuthServer return a server
func NewAuthServer(host string) *AuthServer {
	return &AuthServer{
		Host: host,
		RTT:  time.Hour, //default untrusted rtt
	}
}

func (a *AuthServer) String() string {
	return "host:" + a.Host + " " + "rtt:" + a.RTT.String()
}

func init() {
	for _, k := range initialkeys {
		rr, err := dns.NewRR(k)
		if err != nil {
			panic(err)
		}
		rootkeys = append(rootkeys, rr)
	}
}

// NewResolver return a resolver
func NewResolver() *Resolver {
	return &Resolver{
		&dns.ClientConfig{},
		NewNameServerCache(Config.Maxcount),
		NewQueryCache(Config.Maxcount),
		NewErrorCache(Config.Maxcount, Config.Expire),
		NewLookupQueue(),
	}
}

// Resolve will ask each nameserver in top-to-bottom fashion, starting a new request
// in every interval, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *Resolver) Resolve(Net string, req *dns.Msg, servers []*AuthServer, root bool, depth int, level int, nsl bool, parentdsrr []dns.RR) (*dns.Msg, error) {
	if root && req.Question[0].Qtype != dns.TypeDS {
		q := req.Question[0]
		servers, parentdsrr = r.searchCache(&q)
	}

	resp, err := r.lookup(Net, req, servers)
	if err != nil {
		return nil, err
	}

	resp.RecursionAvailable = true
	resp.AuthenticatedData = true
	resp.Authoritative = false

	if resp.Rcode != dns.RcodeSuccess {
		if resp.Rcode == dns.RcodeNameError {
			nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
			if len(nsecSet) > 0 {
				err = verifyNameError(&resp.Question[0], nsecSet)
				if err != nil {
					log.Info("NSEC3 verify failed (NXDOMAIN)", "qname", req.Question[0].Name, "qtype", dns.TypeToString[req.Question[0].Qtype], "error", err.Error())
				}
			}
		}

		return resp, nil
	}

	if len(resp.Answer) > 0 {
		var signer string
		var signerFound bool

		for _, rr := range resp.Answer {
			if strings.ToLower(rr.Header().Name) != strings.ToLower(req.Question[0].Name) {
				continue
			}
			if sigrec, ok := rr.(*dns.RRSIG); ok {
				signer = strings.ToLower(sigrec.SignerName)
				signerFound = true
				break
			}
		}

		if signerFound && len(parentdsrr) > 0 {
			if dsrr, ok := parentdsrr[0].(*dns.DS); ok {
				if req.Question[0].Qtype != dns.TypeDS && strings.ToLower(dsrr.Header().Name) != signer {
					//try lookup DS records
					dsReq := new(dns.Msg)
					dsReq.SetQuestion(signer, dns.TypeDS)
					dsReq.SetEdns0(DefaultMsgSize, true)

					dsDepth := Config.Maxdepth
					dsResp, err := r.Resolve(Net, dsReq, rootservers, true, dsDepth, 0, false, nil)
					if err == nil {
						parentdsrr = extractRRSet(dsResp.Answer, signer, dns.TypeDS)
					} else {
						signerFound = false
					}
				}
			}
		}

		if signerFound && (signer == rootzone || len(parentdsrr) > 0) {
			ok, err := r.verifyDNSSEC(Net, signer, strings.ToLower(req.Question[0].Name), resp, parentdsrr, servers)

			if err != nil {
				log.Warn("DNSSEC verify failed (answer)", "qname", req.Question[0].Name, "qtype", dns.TypeToString[req.Question[0].Qtype], "error", err.Error())
				if !strings.Contains(err.Error(), errNoDNSKEY.Error()) { //some servers timedout for DNSKEY queries, ignoring
					return nil, err
				}
			} else if !ok {
				log.Warn("DNSSEC cannot verify at the moment (answer)", "qname", req.Question[0].Name, "qtype", dns.TypeToString[req.Question[0].Qtype])
			}
		}

		resp.Ns = []dns.RR{}
		resp.Extra = []dns.RR{}

		opt := req.IsEdns0()
		if opt != nil {
			resp.Extra = append(resp.Extra, opt)
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
			nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC3)
			if len(nsecSet) > 0 && req.Question[0].Qtype == dns.TypeDS {
				err = verifyNODATA(&resp.Question[0], nsecSet)
				if err != nil {
					log.Info("NSEC3 verify failed (NODATA)", "qname", req.Question[0].Name, "qtype", dns.TypeToString[req.Question[0].Qtype], "error", err.Error())
					return resp, nil
				}
			}
			return resp, nil
		}

		nlevel := len(dns.SplitDomainName(nsrr.Header().Name))
		if level > nlevel {
			return resp, errParentDetection
		}

		Q := Question{unFqdn(nsrr.Header().Name), dns.TypeToString[nsrr.Header().Rrtype], dns.ClassToString[nsrr.Header().Class]}
		if Q.Qname == "" {
			return resp, errRootServersDetection
		}

		key := keyGen(Q)

		nsCache, err := r.nsCache.Get(key)
		if err == nil {
			if reflect.DeepEqual(nsCache.Servers, servers) {
				return nil, errLoopDetection
			}

			log.Debug("Nameserver cache hit", "key", key, "query", Q.String())

			if depth <= 0 {
				return nil, errMaxDepth
			}

			depth--
			return r.Resolve(Net, req, nsCache.Servers, false, depth, nlevel, nsl, nil)
		}

		log.Debug("Nameserver cache not found", "key", key, "query", Q.String(), "error", err.Error())

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
				nservers = append(nservers, addr+":53")
			}
		}

		if len(nsmap) > len(nservers) {
			if len(nservers) > 0 {
				// temprorary cache before lookup
				authservers := []*AuthServer{}
				for _, s := range nservers {
					authservers = append(authservers, NewAuthServer(s))
				}

				r.nsCache.Set(key, nil, nsrr.Header().Ttl, authservers)
			}
			//non extra rr for some nameservers, try lookup
			for k, addr := range nsmap {
				if addr == "" {
					addr, err := r.lookupNSAddr(Net, k, req.Question[0].Name, depth)
					if err == nil {
						if isLocalIP(addr) {
							continue
						}
						nservers = append(nservers, addr+":53")
					} else {
						log.Info("Lookup NS addr failed", "qname", req.Question[0].Name, "ns", k, "error", err.Error())
					}
				}
			}
		}

		if len(nservers) == 0 {
			return nil, errors.New("nameservers are not reachable")
		}

		nsecSet := extractRRSet(resp.Ns, "", dns.TypeNSEC3)

		if len(nsecSet) > 0 {
			err = verifyDelegation(resp.Question[0].Name, nsecSet)
			if err != nil {
				log.Warn("NSEC3 verify failed (delegation)", "qname", req.Question[0].Name, "qtype", dns.TypeToString[req.Question[0].Qtype], "error", err.Error())
			}
		} else {
			var signer string
			var signerFound bool

			for _, rr := range resp.Ns {
				if strings.ToLower(rr.Header().Name) != strings.ToLower(nsrr.Header().Name) {
					continue
				}
				if sigrec, ok := rr.(*dns.RRSIG); ok {
					signer = strings.ToLower(sigrec.SignerName)
					signerFound = true
					break
				}
			}

			if signerFound && len(parentdsrr) > 0 {
				if dsrr, ok := parentdsrr[0].(*dns.DS); ok {
					if req.Question[0].Qtype != dns.TypeDS && strings.ToLower(dsrr.Header().Name) != signer {
						//try lookup DS records
						dsReq := new(dns.Msg)
						dsReq.SetQuestion(signer, dns.TypeDS)
						dsReq.SetEdns0(DefaultMsgSize, true)

						dsDepth := Config.Maxdepth
						dsResp, err := r.Resolve(Net, dsReq, rootservers, true, dsDepth, 0, false, nil)
						if err == nil {
							parentdsrr = extractRRSet(dsResp.Answer, signer, dns.TypeDS)
						} else {
							signerFound = false
						}
					}
				}
			}

			if signerFound && (signer == rootzone || len(parentdsrr) > 0) {
				ok, err := r.verifyDNSSEC(Net, signer, nsrr.Header().Name, resp, parentdsrr, servers)
				if err != nil {
					log.Warn("DNSSEC verify failed (delegation)", "signer", signer, "signed", nsrr.Header().Name, "error", err.Error())
				} else if !ok {
					log.Warn("DNSSEC cannot verify at the moment (delegation)", "qname", req.Question[0].Name, "qtype", dns.TypeToString[req.Question[0].Qtype])
				}

				parentdsrr = extractRRSet(resp.Ns, strings.ToLower(nsrr.Header().Name), dns.TypeDS)
			}
		}

		authservers := []*AuthServer{}
		for _, s := range nservers {
			authservers = append(authservers, NewAuthServer(s))
		}

		//final cache
		err = r.nsCache.Set(key, parentdsrr, nsrr.Header().Ttl, authservers)
		if err != nil {
			log.Error("Set nameserver cache failed", "query", Q.String(), "error", err.Error())
		} else {
			log.Debug("Nameserver cache insert", "key", key, "query", Q.String())
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

func (r *Resolver) lookup(Net string, req *dns.Msg, servers []*AuthServer) (resp *dns.Msg, err error) {
	c := &dns.Client{
		Net:     Net,
		UDPSize: dns.DefaultMsgSize,
		Dialer: &net.Dialer{
			DualStack:     true,
			FallbackDelay: 100 * time.Millisecond,
			Timeout:       time.Duration(Config.ConnectTimeout) * time.Second,
		},
		ReadTimeout:  time.Duration(Config.Timeout) * time.Second,
		WriteTimeout: time.Duration(Config.Timeout) * time.Second,
	}

	if len(Config.OutboundIPs) > 0 {
		Config.OutboundIPs = shuffleStr(Config.OutboundIPs)

		if Net == "tcp" {
			c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(Config.OutboundIPs[0])}
		} else if Net == "udp" {
			c.Dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(Config.OutboundIPs[0])}
		}
	}

	qname := req.Question[0].Name
	qtype := dns.Type(req.Question[0].Qtype).String()

	resCh := make(chan *dns.Msg, len(servers))
	errCh := make(chan error, len(servers))

	L := func(server *AuthServer, last bool) {
	tryagain:
		var resp *dns.Msg
		var err error

		resp, server.RTT, err = c.Exchange(req, server.Host)
		if err != nil && err != dns.ErrTruncated {
			server.RTT = time.Hour
			log.Debug("Socket error in server communication", "qname", qname, "qtype", qtype, "server", server, "net", Net, "error", err.Error())

			if last {
				errCh <- err
			}
			return
		}

		if resp != nil && resp.Rcode == dns.RcodeFormatError {
			// try again without edns tags
			req = clearOPT(req)
			goto tryagain
		}

		if resp != nil && resp.Rcode != dns.RcodeSuccess && !last {
			log.Debug("Failed to get valid response", "qname", qname, "qtype", qtype, "server", server, "net", Net, "rcode", dns.RcodeToString[resp.Rcode])
			return
		}

		log.Debug("Query response", "qname", unFqdn(qname), "qtype", qtype, "server", server, "net", Net, "rcode", dns.RcodeToString[resp.Rcode])

		resCh <- resp
	}

	ticker := time.NewTicker(time.Duration(Config.Interval) * time.Millisecond)
	defer func() {
		ticker.Stop()
	}()

	sort.Slice(servers, func(i, j int) bool { return servers[i].RTT < servers[j].RTT })

	// Start lookup on each nameserver top-down, in interval
	for index, server := range servers {
		go L(server, len(servers)-1 == index)

		// but exit early, if we have an answer
		select {
		case resp = <-resCh:
			return resp, nil
		case err = <-errCh:
			return nil, err
		case <-ticker.C:
			continue
		}
	}

	select {
	case resp = <-resCh:
		return resp, nil
	case err = <-errCh:
		return nil, err
	}
}

func (r *Resolver) searchCache(q *dns.Question) (servers []*AuthServer, parentdsrr []dns.RR) {
	Q := Question{unFqdn(q.Name), dns.TypeToString[dns.TypeNS], dns.ClassToString[q.Qclass]}
	key := keyGen(Q)

	ns, err := r.nsCache.Get(key)

	if err == nil {
		log.Debug("Nameserver cache hit", "key", key, "query", Q.String())
		return ns.Servers, ns.DSRR
	}

	q.Name = upperName(q.Name)

	if q.Name == "" {
		return rootservers, nil
	}

	return r.searchCache(q)
}

func (r *Resolver) lookupNSAddr(Net string, ns, qname string, depth int) (addr string, err error) {
	log.Debug("Lookup NS address", "qname", ns)

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(ns, dns.TypeA)
	nsReq.SetEdns0(DefaultMsgSize, true)
	nsReq.RecursionDesired = true

	q := nsReq.Question[0]
	Q := Question{unFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}

	key := keyGen(Q)

	if c := r.lqueue.Get(key); c != nil {
		return "", fmt.Errorf("nameserver address lookup failed for %s (like loop?)", ns)
	}

	nsres, _, err := r.rCache.Get(key)
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
		nsres, err = r.lookup(Net, nsReq, fallbackservers)
	}

	if err != nil {
		r.errCache.Set(key)
		return addr, fmt.Errorf("nameserver address lookup failed for %s (%v)", ns, err)
	}

	if nsres.Truncated && nsres.Rcode == dns.RcodeSuccess {
		//retrying in TCP mode
		r.lqueue.Done(key)
		return r.lookupNSAddr("tcp", ns, qname, depth)
	}

	if len(nsres.Answer) == 0 && len(nsres.Ns) == 0 {
		//try fallback servers
		nsres, err = r.lookup(Net, nsReq, fallbackservers)
		if err != nil {
			r.errCache.Set(key)
			return addr, fmt.Errorf("nameserver address lookup failed for %s (%v)", ns, err)
		}
	}

	if addr, ok := searchAddr(nsres); ok {
		r.rCache.Set(key, nsres)
		return addr, nil
	}

	r.errCache.Set(key)
	return addr, fmt.Errorf("nameserver address lookup failed for %s (no answer)", ns)
}

func (r *Resolver) verifyDNSSEC(Net string, signer, signed string, resp *dns.Msg, parentdsRR []dns.RR, servers []*AuthServer) (ok bool, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%v for signer=%s signed=%s", err, signer, signed)
		}
	}()

	req := new(dns.Msg)
	req.SetQuestion(signer, dns.TypeDNSKEY)
	req.SetEdns0(DefaultMsgSize, true)

	q := req.Question[0]
	Q := Question{unFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}

	cacheKey := keyGen(Q)

	msg, _, err := r.rCache.Get(cacheKey)
	if msg == nil {
		if signer == rootzone {
			msg = new(dns.Msg)
			msg.SetQuestion(".", dns.TypeDNSKEY)

			msg.Answer = append(msg.Answer, rootkeys...)
		} else {
			msg, err = r.lookup(Net, req, servers)
			if err != nil {
				return
			}

			if msg.Truncated {
				//retrying in TCP mode
				msg, err = r.lookup("tcp", req, servers)
				if err != nil {
					return
				}
			}
		}

		r.rCache.Set(cacheKey, msg)
	}

	if resp.Question[0].Name == rootzone &&
		resp.Question[0].Qtype == dns.TypeDNSKEY {
		msg = resp
	}

	keys := make(map[uint16]*dns.DNSKEY)
	for _, a := range msg.Answer {
		if a.Header().Rrtype == dns.TypeDNSKEY {
			dnskey := a.(*dns.DNSKEY)
			switch dnskey.Algorithm {
			case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.RSAMD5:
				if !checkExponent(dnskey.PublicKey) {
					return false, nil
				}
			}
			tag := dnskey.KeyTag()
			if dnskey.Flags == 256 || dnskey.Flags == 257 {
				keys[tag] = dnskey
			}
		}
	}

	if len(keys) == 0 {
		return false, errNoDNSKEY
	}

	if len(parentdsRR) > 0 {
		err = verifyDS(keys, parentdsRR)
		if err != nil {
			log.Debug("DNSSEC DS verify failed", "signer", signer, "signed", signed, "error", err.Error())
			return
		}
	}

	if err = verifyRRSIG(keys, resp); err != nil {
		log.Debug("RRSIG not verified", "error", err.Error())
		return
	}

	log.Debug("DNSSEC verified", "signer", signer, "signed", signed)

	return true, nil
}
