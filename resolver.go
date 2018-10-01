package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Resolver type
type Resolver struct {
	config *dns.ClientConfig
}

// Lookup will ask each nameserver in top-to-bottom fashion, starting a new request
// in every second, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *Resolver) Lookup(net string, req *dns.Msg) (message *dns.Msg, err error) {
	c := &dns.Client{
		Net:          net,
		UDPSize:      dns.DefaultMsgSize,
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
			log.Error("Got an error from resolver", "qname", qname, "qtype", qtype, "resolver", nameserver, "net", net, "error", err.Error())
			return
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			log.Debug("Failed to get a valid answer", "qname", qname, "qtype", qtype, "resolver", nameserver, "net", net)
			if r.Rcode == dns.RcodeServerFailure && req.Question[0].Qtype != dns.TypePTR {
				return
			}
		} else {
			log.Debug("Resolve query", "qname", unFqdn(qname), "qtype", qtype, "resolver", nameserver, "net", net)
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
