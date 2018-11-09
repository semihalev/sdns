package blocklist

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/doh"
)

// BlockList type
type BlockList struct {
	mu sync.RWMutex

	nullroute  net.IP
	null6route net.IP

	m map[string]bool
}

// New returns a new BlockList
func New(cfg *config.Config) *BlockList {
	return &BlockList{
		nullroute:  net.ParseIP(cfg.Nullroute),
		null6route: net.ParseIP(cfg.Nullroutev6),

		m: make(map[string]bool),
	}
}

// Name return middleware name
func (b *BlockList) Name() string {
	return "blocklist"
}

// ServeDNS implements the Handle interface.
func (b *BlockList) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	msg := b.handle("", req)
	if msg == nil {
		dc.NextDNS()
		return
	}

	w.WriteMsg(msg)

	dc.Abort()
}

func (b *BlockList) ServeHTTP(dc *ctx.Context) {
	w, r := dc.HTTPWriter, dc.HTTPRequest

	var f func(http.ResponseWriter, *http.Request) bool
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		f = doh.HandleJSON(b.handle)
	} else {
		f = doh.HandleWireFormat(b.handle)
	}

	next := f(w, r)
	if next {
		dc.NextHTTP()
		return
	}

	dc.Abort()
}

func (b *BlockList) handle(Net string, req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	if !b.Exists(strings.ToLower(q.Name)) {
		return nil
	}

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative, msg.RecursionAvailable = true, true

	switch q.Qtype {
	case dns.TypeA:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		a := &dns.A{Hdr: rrHeader, A: b.nullroute}
		msg.Answer = append(msg.Answer, a)
	case dns.TypeAAAA:
		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		a := &dns.AAAA{Hdr: rrHeader, AAAA: b.null6route}
		msg.Answer = append(msg.Answer, a)
	}

	return msg
}

// Get returns the entry for a key or an error
func (b *BlockList) Get(key string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	key = strings.ToLower(key)
	val, ok := b.m[key]

	if !ok {
		return false, errors.New("block not found")
	}

	return val, nil
}

// Remove removes an entry from the cache
func (b *BlockList) Remove(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key = strings.ToLower(key)
	delete(b.m, key)
}

// Set sets a value in the BlockList
func (b *BlockList) Set(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key = strings.ToLower(key)
	b.m[key] = true
}

// Exists returns whether or not a key exists in the cache
func (b *BlockList) Exists(key string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	key = strings.ToLower(key)
	_, ok := b.m[key]

	return ok
}

// Length returns the caches length
func (b *BlockList) Length() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.m)
}
