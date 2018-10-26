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
	mu sync.RWMutex

	m    map[uint64]*Query
	max  int
	rate int
}

// NewQueryCache return new cache
func NewQueryCache(maxcount int, ratelimit int) *QueryCache {
	c := &QueryCache{
		m:    make(map[uint64]*Query, maxcount),
		max:  maxcount,
		rate: ratelimit,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *QueryCache) Get(key uint64, req *dns.Msg) (*dns.Msg, *rl.RateLimiter, error) {
	c.mu.RLock()
	query, ok := c.m[key]
	c.mu.RUnlock()

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

	query.mu.Unlock()

	return query.Item.toMsg(req), query.RateLimit, nil
}

// Set sets a keys value to a Mesg
func (c *QueryCache) Set(key uint64, msg *dns.Msg) error {
	if c.Full() && !c.Exists(key) {
		return ErrCapacityFull
	}

	c.mu.Lock()
	c.m[key] = &Query{
		Item:       newItem(msg),
		RateLimit:  rl.New(c.rate, time.Second),
		UpdateTime: WallClock.Now().Truncate(time.Second),
	}
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *QueryCache) Remove(key uint64) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *QueryCache) Exists(key uint64) bool {
	c.mu.RLock()
	_, ok := c.m[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *QueryCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Full returns whether or not the cache is full
func (c *QueryCache) Full() bool {
	if c.max == 0 {
		return false
	}
	return c.Length() >= c.max
}

func (c *QueryCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, msg := range c.m {
		now := WallClock.Now().Truncate(time.Second)
		elapsed := uint32(now.Sub(msg.UpdateTime).Seconds())

		for _, answer := range msg.Item.Answer {
			if elapsed >= answer.Header().Ttl {
				delete(c.m, key)
				return
			}
		}
	}
}

func (c *QueryCache) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		c.clear()
	}
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
