// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a modified version of net/hosts.go from the golang repo

package hostsfile

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

func parseLiteralIP(addr string) net.IP {
	if i := strings.Index(addr, "%"); i >= 0 {
		// discard ipv6 zone
		addr = addr[0:i]
	}

	return net.ParseIP(addr)
}

func absDomainName(b string) string {
	return strings.ToLower(dns.Fqdn(string(b)))
}

type hostsMap struct {
	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byNameV4 map[string][]net.IP
	byNameV6 map[string][]net.IP

	// Key for the list of host names must be a literal IP address
	// including IPv6 address with zone identifier.
	// We don't support old-classful IP address notation.
	byAddr map[string][]string
}

func newHostsMap() *hostsMap {
	return &hostsMap{
		byNameV4: make(map[string][]net.IP),
		byNameV6: make(map[string][]net.IP),
		byAddr:   make(map[string][]string),
	}
}

// Len returns the total number of addresses in the hostmap, this includes
// V4/V6 and any reverse addresses.
func (h *hostsMap) Len() int {
	l := 0
	for _, v4 := range h.byNameV4 {
		l += len(v4)
	}
	for _, v6 := range h.byNameV6 {
		l += len(v6)
	}
	for _, a := range h.byAddr {
		l += len(a)
	}
	return l
}

// Hostsfile contains known host entries.
type Hostsfile struct {
	sync.RWMutex

	// hosts maps for lookups
	hmap *hostsMap

	// inline saves the hosts file that is inlined in a Corefile.
	// We need a copy here as we want to use it to initialize the maps for parse.
	inline *hostsMap

	// path to the hosts file
	path string

	// mtime and size are only read and modified by a single goroutine
	mtime time.Time
	size  int64
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return new hostfile, it will be hosts file also
func New(cfg *config.Config) *Hostsfile {
	h := &Hostsfile{
		path: cfg.Hostsfile,
		hmap: newHostsMap(),
	}

	h.readHosts()

	go h.run()

	return h
}

// Name return middleware name
func (h *Hostsfile) Name() string { return name }

func (h *Hostsfile) run() {
	parseChan := make(chan bool)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-parseChan:
				return
			case <-ticker.C:
				h.readHosts()
			}
		}
	}()
}

// readHosts determines if the cached data needs to be updated based on the size and modification time of the hostsfile.
func (h *Hostsfile) readHosts() {
	file, err := os.Open(h.path)
	if err != nil {
		// We already log a warning if the file doesn't exist or can't be opened on setup. No need to return the error here.
		return
	}

	defer func() {
		err := file.Close()
		if err != nil {
			log.Warn("Hosts file close failed", "error", err.Error())
		}
	}()

	stat, err := file.Stat()
	if err == nil && h.mtime.Equal(stat.ModTime()) && h.size == stat.Size() {
		return
	}

	newMap := h.parse(file, h.inline)
	log.Debug("Parsed hosts file into", "entries", newMap.Len())

	h.Lock()

	h.hmap = newMap
	// Update the data cache.
	h.mtime = stat.ModTime()
	h.size = stat.Size()

	h.Unlock()
}

func (h *Hostsfile) initInline(inline []string) {
	if len(inline) == 0 {
		return
	}

	hmap := newHostsMap()
	h.inline = h.parse(strings.NewReader(strings.Join(inline, "\n")), hmap)
	*h.hmap = *h.inline
}

func (h *Hostsfile) parseReader(r io.Reader) { h.hmap = h.parse(r, h.inline) }

// Parse reads the hostsfile and populates the byName and byAddr maps.
func (h *Hostsfile) parse(r io.Reader, override *hostsMap) *hostsMap {
	hmap := newHostsMap()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if i := bytes.Index(line, []byte{'#'}); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := bytes.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr := parseLiteralIP(string(f[0]))
		if addr == nil {
			continue
		}
		ver := ipVersion(string(f[0]))
		for i := 1; i < len(f); i++ {
			name := absDomainName(string(f[i]))
			switch ver {
			case 4:
				hmap.byNameV4[name] = append(hmap.byNameV4[name], addr)
			case 6:
				hmap.byNameV6[name] = append(hmap.byNameV6[name], addr)
			default:
				continue
			}
			hmap.byAddr[addr.String()] = append(hmap.byAddr[addr.String()], name)
		}
	}

	if override == nil {
		return hmap
	}

	for name := range override.byNameV4 {
		hmap.byNameV4[name] = append(hmap.byNameV4[name], override.byNameV4[name]...)
	}
	for name := range override.byNameV4 {
		hmap.byNameV6[name] = append(hmap.byNameV6[name], override.byNameV6[name]...)
	}
	for addr := range override.byAddr {
		hmap.byAddr[addr] = append(hmap.byAddr[addr], override.byAddr[addr]...)
	}

	return hmap
}

// ipVersion returns what IP version was used textually
func ipVersion(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return 4
		case ':':
			return 6
		}
	}
	return 0
}

// LookupStaticHostV4 looks up the IPv4 addresses for the given host from the hosts file.
func (h *Hostsfile) LookupStaticHostV4(host string) []net.IP {
	h.RLock()
	defer h.RUnlock()
	if len(h.hmap.byNameV4) != 0 {
		if ips, ok := h.hmap.byNameV4[absDomainName(host)]; ok {
			ipsCp := make([]net.IP, len(ips))
			copy(ipsCp, ips)
			return ipsCp
		}
	}
	return nil
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the hosts file.
func (h *Hostsfile) LookupStaticHostV6(host string) []net.IP {
	h.RLock()
	defer h.RUnlock()
	if len(h.hmap.byNameV6) != 0 {
		if ips, ok := h.hmap.byNameV6[absDomainName(host)]; ok {
			ipsCp := make([]net.IP, len(ips))
			copy(ipsCp, ips)
			return ipsCp
		}
	}
	return nil
}

// LookupStaticAddr looks up the hosts for the given address from the hosts file.
func (h *Hostsfile) LookupStaticAddr(addr string) []string {
	h.RLock()
	defer h.RUnlock()
	addr = parseLiteralIP(addr).String()
	if addr == "" {
		return nil
	}
	if len(h.hmap.byAddr) != 0 {
		if hosts, ok := h.hmap.byAddr[addr]; ok {
			hostsCp := make([]string, len(hosts))
			copy(hostsCp, hosts)
			return hostsCp
		}
	}
	return nil
}

// ServeDNS implements the Handle interface.
func (h *Hostsfile) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	q := req.Question[0]

	answers := []dns.RR{}

	switch q.Qtype {
	case dns.TypePTR:
		names := h.LookupStaticAddr(dnsutil.ExtractAddressFromReverse(q.Name))
		if len(names) == 0 {
			ch.Next(ctx)
			return
		}
		answers = ptr(q.Name, names)
	case dns.TypeA:
		ips := h.LookupStaticHostV4(q.Name)
		answers = a(q.Name, ips)
	case dns.TypeAAAA:
		ips := h.LookupStaticHostV6(q.Name)
		answers = aaaa(q.Name, ips)
	}

	if len(answers) == 0 {
		if !h.otherRecordsExist(q.Qtype, q.Name) {
			ch.Next(ctx)
			return
		}
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative, m.RecursionAvailable = true, true
	m.Answer = answers

	_ = w.WriteMsg(m)

	ch.Cancel()
}

func (h *Hostsfile) otherRecordsExist(qtype uint16, qname string) bool {
	switch qtype {
	case dns.TypeA:
		if len(h.LookupStaticHostV6(qname)) > 0 {
			return true
		}
	case dns.TypeAAAA:
		if len(h.LookupStaticHostV4(qname)) > 0 {
			return true
		}
	default:
		if len(h.LookupStaticHostV4(qname)) > 0 {
			return true
		}
		if len(h.LookupStaticHostV6(qname)) > 0 {
			return true
		}
	}
	return false

}

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ips []net.IP) []dns.RR {
	answers := []dns.RR{}
	for _, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 3600}
		r.A = ip
		answers = append(answers, r)
	}
	return answers
}

// aaaa takes a slice of net.IPs and returns a slice of AAAA RRs.
func aaaa(zone string, ips []net.IP) []dns.RR {
	answers := []dns.RR{}
	for _, ip := range ips {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: 3600}
		r.AAAA = ip
		answers = append(answers, r)
	}
	return answers
}

// ptr takes a slice of host names and filters out the ones that aren't in Origins, if specified, and returns a slice of PTR RRs.
func ptr(zone string, names []string) []dns.RR {
	answers := []dns.RR{}
	for _, n := range names {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR,
			Class: dns.ClassINET, Ttl: 3600}
		r.Ptr = dns.Fqdn(n)
		answers = append(answers, r)
	}
	return answers
}

const name = "hostsfile"
