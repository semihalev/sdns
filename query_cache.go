package main

import (
	"errors"
	"strings"
	"sync"
	"time"

	rl "github.com/bsm/ratelimit"
	"github.com/miekg/dns"
)

// Query represents a cache entry
type Query struct {
	Msg        *dns.Msg
	RateLimit  *rl.RateLimiter
	UpdateTime time.Time

	mu sync.Mutex
}

// QueryCache type
type QueryCache struct {
	mu sync.RWMutex

	m   map[string]*Query
	max int
}

var (
	// ErrCacheNotFound error
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error
	ErrCacheExpired = errors.New("cache expired")
	// ErrCapacityFull error
	ErrCapacityFull = errors.New("capacity full")
)

// NewQueryCache return new cache
func NewQueryCache(maxcount int) *QueryCache {
	c := &QueryCache{
		m:   make(map[string]*Query, maxcount),
		max: maxcount,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *QueryCache) Get(key string) (*dns.Msg, *rl.RateLimiter, error) {
	key = strings.ToLower(key)

	c.mu.RLock()
	query, ok := c.m[key]
	c.mu.RUnlock()

	if !ok {
		return nil, nil, ErrCacheNotFound
	}

	if query.Msg == nil {
		c.Remove(key)
		return nil, nil, ErrCacheNotFound
	}

	//Truncate time to the second, so that subsecond queries won't keep moving
	//forward the last update time without touching the TTL
	query.mu.Lock()

	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(query.UpdateTime).Seconds())
	query.UpdateTime = now

	for _, answer := range query.Msg.Answer {
		if elapsed > answer.Header().Ttl {
			query.mu.Unlock()
			c.Remove(key)
			return nil, nil, ErrCacheExpired
		}
		answer.Header().Ttl -= elapsed
	}

	for _, ns := range query.Msg.Ns {
		if elapsed > ns.Header().Ttl {
			query.mu.Unlock()
			c.Remove(key)
			return nil, nil, ErrCacheExpired
		}
		ns.Header().Ttl -= elapsed
	}

	query.mu.Unlock()

	return query.Msg, query.RateLimit, nil
}

// Set sets a keys value to a Mesg
func (c *QueryCache) Set(key string, msg *dns.Msg) error {
	key = strings.ToLower(key)

	if c.Full() && !c.Exists(key) {
		return ErrCapacityFull
	}

	c.mu.Lock()
	c.m[key] = &Query{
		Msg:        msg,
		RateLimit:  rl.New(Config.RateLimit, time.Second),
		UpdateTime: WallClock.Now().Truncate(time.Second),
	}
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *QueryCache) Remove(key string) {
	key = strings.ToLower(key)

	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *QueryCache) Exists(key string) bool {
	key = strings.ToLower(key)

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
		if msg.Msg == nil {
			delete(c.m, key)
		}

		now := WallClock.Now().Truncate(time.Second)
		elapsed := uint32(now.Sub(msg.UpdateTime).Seconds())

		for _, answer := range msg.Msg.Answer {
			if elapsed > answer.Header().Ttl {
				delete(c.m, key)
				break
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
