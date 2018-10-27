package cache

import (
	"sync"
	"time"

	rl "github.com/bsm/ratelimit"
	"github.com/miekg/dns"
)

type item struct {
	Rcode              int
	Authoritative      bool
	AuthenticatedData  bool
	RecursionAvailable bool
	Answer             []dns.RR
	Ns                 []dns.RR
	Extra              []dns.RR
}

// Query represents a cache entry
type Query struct {
	Item       *item
	RateLimit  *rl.RateLimiter
	UpdateTime time.Time

	mu sync.Mutex
}

// QueryCache type
type QueryCache struct {
	shards [shardSize]*shard
	rate   int
}

// NewQueryCache return new cache
func NewQueryCache(size int, ratelimit int) *QueryCache {
	ssize := size / shardSize
	if ssize < 4 {
		ssize = 4
	}

	c := &QueryCache{
		rate: ratelimit,
	}

	// Initialize all the shards
	for i := 0; i < shardSize; i++ {
		c.shards[i] = newShard(ssize)
	}

	return c
}

// Get returns the entry for a key or an error
func (c *QueryCache) Get(key uint64, req *dns.Msg) (*dns.Msg, *rl.RateLimiter, error) {
	shard := key & (shardSize - 1)
	el, ok := c.shards[shard].Get(key)

	if !ok {
		return nil, nil, ErrCacheNotFound
	}

	query, ok := el.(*Query)
	if !ok {
		return nil, nil, ErrCacheNotFound
	}

	query.mu.Lock()

	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(query.UpdateTime).Seconds())
	query.UpdateTime = now

	for _, answer := range query.Item.Answer {
		if elapsed > answer.Header().Ttl {
			query.mu.Unlock()
			c.Remove(key)
			return nil, nil, ErrCacheExpired
		}
		answer.Header().Ttl -= elapsed
	}

	for _, ns := range query.Item.Ns {
		if elapsed > ns.Header().Ttl {
			query.mu.Unlock()
			c.Remove(key)
			return nil, nil, ErrCacheExpired
		}
		ns.Header().Ttl -= elapsed
	}

	defer query.mu.Unlock()

	return query.Item.toMsg(req), query.RateLimit, nil
}

// Set sets a keys value to a Mesg
func (c *QueryCache) Set(key uint64, msg *dns.Msg) error {
	shard := key & (shardSize - 1)

	q := &Query{
		Item:       newItem(msg),
		RateLimit:  rl.New(c.rate, time.Second),
		UpdateTime: WallClock.Now().Truncate(time.Second),
	}

	c.shards[shard].Set(key, q)

	return nil
}

// Remove removes an entry from the cache
func (c *QueryCache) Remove(key uint64) {
	shard := key & (shardSize - 1)
	c.shards[shard].Remove(key)
}

// Len returns the caches length
func (c *QueryCache) Len() int {
	l := 0
	for _, s := range c.shards {
		l += s.Len()
	}
	return l
}

func newItem(m *dns.Msg) *item {
	i := new(item)
	i.Rcode = m.Rcode
	i.Authoritative = m.Authoritative
	i.AuthenticatedData = m.AuthenticatedData
	i.RecursionAvailable = m.RecursionAvailable

	i.Answer = make([]dns.RR, len(m.Answer))
	i.Ns = make([]dns.RR, len(m.Ns))
	i.Extra = make([]dns.RR, len(m.Extra))

	for j, r := range m.Answer {
		i.Answer[j] = dns.Copy(r)
	}
	for j, r := range m.Ns {
		i.Ns[j] = dns.Copy(r)
	}
	for j, r := range m.Extra {
		i.Extra[j] = dns.Copy(r)
	}
	return i
}

func (i *item) toMsg(m *dns.Msg) *dns.Msg {
	m1 := new(dns.Msg)
	m1.SetReply(m)

	m1.Authoritative = false
	m1.AuthenticatedData = i.AuthenticatedData
	m1.RecursionAvailable = i.RecursionAvailable
	m1.Rcode = i.Rcode

	m1.Answer = make([]dns.RR, len(i.Answer))
	m1.Ns = make([]dns.RR, len(i.Ns))
	m1.Extra = make([]dns.RR, len(i.Extra))

	for j, r := range i.Answer {
		m1.Answer[j] = dns.Copy(r)
	}
	for j, r := range i.Ns {
		m1.Ns[j] = dns.Copy(r)
	}
	for j, r := range i.Extra {
		m1.Extra[j] = dns.Copy(r)
	}
	return m1
}
