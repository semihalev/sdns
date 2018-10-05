package main

import (
	"fmt"
	"net"
	"reflect"
	"strings"
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

// Resolve will ask each nameserver in top-to-bottom fashion, starting a new request
// in every interval, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *Resolver) Resolve(Net string, req *dns.Msg, servers []string, root bool, depth int, level int, nsl bool) (resp *dns.Msg, err error) {
	if depth == 0 {
		return resp, fmt.Errorf("maximum recursion depth for DNS tree queried")
	}

	if root {
		q := req.Question[0]
		servers = r.searchCache(&q)
	}

	resp, err = r.lookup(Net, req, servers)
	if err != nil {
		return
	}

	if len(resp.Answer) > 0 {
		resp.Ns = []dns.RR{}

		return
	}

	if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
		if nsrec, ok := resp.Ns[0].(*dns.NS); ok {
			nlevel := len(strings.Split(nsrec.Header().Name, "."))
			if level > nlevel {
				return resp, fmt.Errorf("parent detection")
			}

			Q := Question{unFqdn(nsrec.Header().Name), dns.TypeToString[nsrec.Header().Rrtype], dns.ClassToString[nsrec.Header().Class]}
			if Q.Qname == "" {
				return resp, fmt.Errorf("root servers detection")
			}

			key := keyGen(Q)

			ns, err := r.nsCache.Get(key)
			if err == nil {
				if reflect.DeepEqual(ns.Servers, servers) {
					return resp, fmt.Errorf("loop detection")
				}

				log.Debug("Nameserver cache hit", "key", key, "query", Q.String())

				depth--
				return r.Resolve(Net, req, ns.Servers, false, depth, nlevel, nsl)
			}

			log.Debug("Nameserver cache failed", "key", key, "query", Q.String(), "error", err.Error())
		}

		ns := make(map[string]string)
		for _, n := range shuffleRR(resp.Ns) {
			if nsrec, ok := n.(*dns.NS); ok {
				ns[nsrec.Ns] = ""
			}
		}

		if nsl && len(ns) == 0 {
			if _, ok := resp.Ns[0].(*dns.SOA); ok {
				return resp, fmt.Errorf("nameserver addr nxdomain")
			}
		}

		for _, a := range resp.Extra {
			if extra, ok := a.(*dns.A); ok {
				if nsl && extra.Header().Name == req.Question[0].Name && extra.A.String() != "" {
					resp.Answer = append(resp.Answer, extra)
					log.Debug("Glue NS addr", "qname", extra.Header().Name, "a", extra.A.String())
					return
				}

				if _, ok := ns[extra.Header().Name]; ok {
					ns[extra.Header().Name] = extra.A.String()
				}
			}
		}

		nservers := []string{}
		for k, addr := range ns {
			if addr == "" {
				if nsl && len(nservers) >= 1 {
					break
				}

				if k == req.Question[0].Name {
					continue
				}

				addr, err = r.lookupNSAddr(Net, k)
				if err == nil {
					nservers = append(nservers, fmt.Sprintf("%s:53", addr))
				}
			} else {
				nservers = append(nservers, fmt.Sprintf("%s:53", addr))
			}
		}

		if len(nservers) == 0 {
			return
		}

		if nsrec, ok := resp.Ns[0].(*dns.NS); ok {
			nlevel := len(strings.Split(nsrec.Header().Name, "."))
			if level > nlevel {
				return resp, fmt.Errorf("parent detection")
			}

			Q := Question{unFqdn(nsrec.Header().Name), dns.TypeToString[nsrec.Header().Rrtype], dns.ClassToString[nsrec.Header().Class]}
			if Q.Qname == "" {
				return resp, fmt.Errorf("root servers detection")
			}

			key := keyGen(Q)

			err := r.nsCache.Set(key, nsrec.Header().Ttl, nservers)
			if err != nil {
				log.Error("Set nameserver cache failed", "query", Q.String(), "error", err.Error())
			}

			depth--
			return r.Resolve(Net, req, nservers, false, depth, nlevel, nsl)
		}
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

	L := func(server string, last bool) {
		defer wg.Done()

		r, _, err := c.Exchange(req, server)
		if err != nil && err != dns.ErrTruncated {
			log.Info("Got an error from resolver", "qname", qname, "qtype", qtype, "server", server, "net", Net, "error", err.Error())
			return
		}

		if r != nil && r.Rcode != dns.RcodeSuccess && !last {
			log.Debug("Failed to get a valid answer", "qname", qname, "qtype", qtype, "server", server, "net", Net, "rcode", dns.RcodeToString[r.Rcode])
			return
		}

		log.Debug("Resolve query with rcode", "qname", unFqdn(qname), "qtype", qtype, "server", server, "net", Net, "rcode", dns.RcodeToString[r.Rcode])

		select {
		case res <- r:
		default:
		}
	}

	ticker := time.NewTicker(time.Duration(Config.Interval) * time.Millisecond)
	defer ticker.Stop()

	// Start lookup on each nameserver top-down, in interval
	for index, server := range servers {
		wg.Add(1)
		go L(server, len(servers)-1 == index)

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

func (r *Resolver) lookupNSAddr(Net string, ns string) (addr string, err error) {
	nsReq := new(dns.Msg)
	nsReq.SetQuestion(ns, dns.TypeA)
	nsReq.RecursionDesired = true

	q := nsReq.Question[0]
	Q := Question{unFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}

	depth := Config.Maxdepth

	nsres, err := r.Resolve(Net, nsReq, roothints, true, depth, 0, true)
	if err != nil {
		log.Debug("NS record failed", "qname", Q.Qname, "qtype", Q.Qtype, "error", err.Error())
		return
	}

	for _, ans := range nsres.Answer {
		if arec, ok := ans.(*dns.A); ok {
			addr = arec.A.String()
			return
		}
	}

	return addr, fmt.Errorf("ns addr failed")
}
