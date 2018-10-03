package main

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Resolver type
type Resolver struct {
	config  *dns.ClientConfig
	nsCache *NameServerCache
}

var roothints = []string{
	"198.41.0.4:53",
	"192.228.79.201:53",
	"192.33.4.12:53",
	"199.7.91.13:53",
	"192.203.230.10:53",
	"192.5.5.241:53",
	"192.112.36.4:53",
	"128.63.2.53:53",
	"192.36.148.17:53",
	"192.58.128.30:53",
	"193.0.14.129:53",
	"199.7.83.42:53",
	"202.12.27.33:53",
}

// Lookup will ask each nameserver in top-to-bottom fashion, starting a new request
// in every second, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *Resolver) Lookup(Net string, req *dns.Msg) (message *dns.Msg, err error) {
	c := &dns.Client{
		Net:          Net,
		UDPSize:      dns.DefaultMsgSize,
		Dialer:       &net.Dialer{Timeout: time.Duration(Config.ConnectTimeout) * time.Second},
		ReadTimeout:  time.Duration(Config.Timeout) * time.Second,
		WriteTimeout: time.Duration(Config.Timeout) * time.Second,
	}

	qname := req.Question[0].Name
	qtype := dns.Type(req.Question[0].Qtype).String()

	res := make(chan *dns.Msg)

	var wg sync.WaitGroup

	L := func(nameserver string) {
		defer wg.Done()

		r, _, err := c.Exchange(req, nameserver)
		if err != nil && err != dns.ErrTruncated {
			log.Debug("Got an error from resolver", "qname", qname, "qtype", qtype, "resolver", nameserver, "net", Net, "error", err.Error())
			return
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			log.Debug("Failed to get a valid answer", "qname", qname, "qtype", qtype, "resolver", nameserver, "net", Net)
			if r.Rcode == dns.RcodeServerFailure && req.Question[0].Qtype != dns.TypePTR {
				return
			}
		} else {
			log.Debug("Resolve query", "qname", unFqdn(qname), "qtype", qtype, "resolver", nameserver, "net", Net)
		}

		select {
		case res <- r:
		default:
		}
	}

	ticker := time.NewTicker(time.Duration(Config.Interval) * time.Millisecond)
	defer ticker.Stop()

	// Start lookup on each nameserver top-down, in every second
	for _, nameserver := range Config.Nameservers {
		wg.Add(1)
		go L(nameserver)

		// but exit early, if we have an answer
		select {
		case r := <-res:
			return r, nil
		case <-ticker.C:
			continue
		}
	}

	// wait for all the namservers to finish
	wg.Wait()
	select {
	case r := <-res:
		return r, nil
	default:
		return nil, fmt.Errorf("resolv failed")
	}
}

// Resolve func
func (r *Resolver) Resolve(net string, req *dns.Msg, servers []string, root bool, depth int) (resp *dns.Msg, err error) {
	if depth == 0 {
		log.Error("Maximum recursion depth for DNS tree queried", "qname", req.Question[0].Name, "qtype", dns.Type(req.Question[0].Qtype).String())
		return resp, fmt.Errorf("maximum recursion depth for DNS tree queried")
	}

	if root {
		q := req.Question[0]
		servers = r.searchCache(&q)
	}

	resp, err = r.lookup(net, req, servers)
	if err != nil {
		return
	}

	if len(resp.Answer) > 0 {
		resp.Extra = []dns.RR{}
		resp.Ns = []dns.RR{}

		return
	}

	if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
		if nsrec, ok := resp.Ns[0].(*dns.NS); ok {
			Q := Question{unFqdn(nsrec.Header().Name), dns.TypeToString[nsrec.Header().Rrtype], dns.ClassToString[nsrec.Header().Class]}
			key := keyGen(Q)

			ns, err := r.nsCache.Get(key)
			if err == nil {
				if len(resp.Ns) != len(ns.Servers) {
					r.nsCache.Remove(key)
					goto tryservers
				}

				if reflect.DeepEqual(ns.Servers, servers) {
					return resp, fmt.Errorf("loop detection")
				}

				log.Debug("Nameserver cache hit", "key", key, "query", Q.String())

				depth--
				return r.Resolve(net, req, ns.Servers, false, depth)
			}
		}

	tryservers:
		ns := make(map[string]string)
		for _, n := range resp.Ns {
			nsrec, _ := n.(*dns.NS)
			if nsrec != nil {
				ns[nsrec.Ns] = ""
			}
		}

		for _, a := range resp.Extra {
			extra, ok := a.(*dns.A)
			if ok {
				_, ok := ns[extra.Header().Name]
				if ok {
					ns[extra.Header().Name] = fmt.Sprintf("%s:53", extra.A.String())
				}
			}
		}

		nservers := []string{}
		for k, addr := range ns {
			if addr == "" {
				nsReq := new(dns.Msg)
				nsReq.SetQuestion(k, dns.TypeA)
				nsReq.RecursionDesired = true

				nsres, err := r.lookup(net, nsReq, Config.Nameservers)
				if err == nil {
					for _, ans := range nsres.Answer {
						arec, ok := ans.(*dns.A)
						if ok {
							nservers = append(nservers, fmt.Sprintf("%s:53", arec.A.String()))
						}
					}
				}
			} else {
				nservers = append(nservers, addr)
			}
		}

		if len(nservers) == 0 {
			return
		}

		if nsrec, ok := resp.Ns[0].(*dns.NS); ok {
			Q := Question{unFqdn(nsrec.Header().Name), dns.TypeToString[nsrec.Header().Rrtype], dns.ClassToString[nsrec.Header().Class]}
			key := keyGen(Q)

			err := r.nsCache.Set(key, nsrec.Header().Ttl, nservers)
			if err != nil {
				log.Error("Set nameserver cache failed", "query", Q.String(), "error", err.Error())
			}
		}

		depth--
		return r.Resolve(net, req, nservers, false, depth)
	}

	return
}

func (r *Resolver) lookup(Net string, req *dns.Msg, servers []string) (resp *dns.Msg, err error) {
	c := &dns.Client{
		Net:          Net,
		UDPSize:      dns.DefaultMsgSize,
		Dialer:       &net.Dialer{Timeout: time.Duration(Config.ConnectTimeout) * time.Second},
		ReadTimeout:  time.Duration(Config.Timeout) * time.Second,
		WriteTimeout: time.Duration(Config.Timeout) * time.Second,
	}

	if Config.OutboundIP != "" {
		if Net == "tcp" {
			c.Dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(Config.OutboundIP)}
		} else if Net == "udp" {
			c.Dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(Config.OutboundIP)}
		}
	}

	qname := req.Question[0].Name
	qtype := dns.Type(req.Question[0].Qtype).String()

	res := make(chan *dns.Msg)

	var wg sync.WaitGroup

	L := func(server string) {
		defer wg.Done()

		r, _, err := c.Exchange(req, server)
		if err != nil && err != dns.ErrTruncated {
			log.Debug("Got an error from resolver", "qname", qname, "qtype", qtype, "server", server, "net", Net, "error", err.Error())
			return
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			log.Debug("Failed to get a valid answer", "qname", qname, "qtype", qtype, "server", server, "net", Net)
			if r.Rcode == dns.RcodeServerFailure {
				return
			}
		} else {
			log.Debug("Resolve query", "qname", unFqdn(qname), "qtype", qtype, "server", server, "net", Net)
		}

		select {
		case res <- r:
		default:
		}
	}

	ticker := time.NewTicker(time.Duration(Config.Interval) * time.Millisecond)
	defer ticker.Stop()

	// Start lookup on each nameserver top-down, in interval
	for _, server := range servers {
		wg.Add(1)
		go L(server)

		log.Debug("Try resursive from one of server", "server", server)

		// but exit early, if we have an answer
		select {
		case r := <-res:
			return r, nil
		case <-ticker.C:
			continue
		}
	}

	// wait for all the namservers to finish
	wg.Wait()
	select {
	case r := <-res:
		return r, nil
	default:
		return nil, fmt.Errorf("resolv failed")
	}
}

func (r *Resolver) searchCache(q *dns.Question) (servers []string) {
	Q := Question{unFqdn(q.Name), dns.TypeToString[dns.TypeNS], dns.ClassToString[q.Qclass]}
	key := keyGen(Q)

	ns, err := r.nsCache.Get(key)
	if err == nil {
		log.Debug("Nameserver cache hit", "key", key, "query", Q.String())
		return ns.Servers
	}

	q.Name = upperName(q.Name)
	if q.Name == "" {
		return roothints
	}

	return r.searchCache(q)
}
