package blocklist

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// BlockList type
type BlockList struct {
	mu sync.RWMutex

	nullroute  net.IP
	null6route net.IP

	m map[string]bool

	cfg *config.Config
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New returns a new BlockList
func New(cfg *config.Config) *BlockList {
	b := &BlockList{
		nullroute:  net.ParseIP(cfg.Nullroute),
		null6route: net.ParseIP(cfg.Nullroutev6),

		m: make(map[string]bool),

		cfg: cfg,
	}

	go b.fetchBlocklists()

	return b
}

// Name return middleware name
func (b *BlockList) Name() string { return name }

// ServeDNS implements the Handle interface.
func (b *BlockList) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	q := req.Question[0]

	if !b.Exists(q.Name) {
		ch.Next(ctx)
		return
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

	_ = w.WriteMsg(msg)

	ch.Cancel()
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

const name = "blocklist"
