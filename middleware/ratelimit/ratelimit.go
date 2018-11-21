package ratelimit

import (
	"net"
	"sync"
	"time"

	"github.com/semihalev/sdns/middleware"

	rl "github.com/bsm/ratelimit"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
)

type limiter struct {
	rl *rl.RateLimiter
	ut time.Time
}

// RateLimit type
type RateLimit struct {
	mu sync.Mutex

	m    map[string]*limiter
	rate int
	now  func() time.Time
}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})
}

// New return accesslist
func New(cfg *config.Config) *RateLimit {
	r := &RateLimit{
		m:    make(map[string]*limiter),
		rate: cfg.ClientRateLimit,
		now:  time.Now,
	}

	go r.run()

	return r
}

// Name return middleware name
func (r *RateLimit) Name() string { return name }

// ServeDNS implements the Handle interface.
func (r *RateLimit) ServeDNS(dc *ctx.Context) {
	if r.rate == 0 {
		dc.NextDNS()
		return
	}

	client, _, _ := net.SplitHostPort(dc.DNSWriter.RemoteAddr().String())
	if ip := net.ParseIP(client); ip == nil {
		dc.NextDNS()
		return
	} else if ip.IsLoopback() {
		dc.NextDNS()
		return
	}

	rl := r.getLimiter(client)

	if rl.Limit() {
		//no reply to client
		dc.Abort()
		return
	}

	dc.NextDNS()
}

func (r *RateLimit) getLimiter(client string) *rl.RateLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	if limiter, ok := r.m[client]; ok {
		limiter.ut = r.now().UTC()
		return limiter.rl
	}

	rl := rl.New(r.rate, time.Minute)
	r.m[client] = &limiter{rl: rl, ut: r.now().UTC()}

	return rl
}

func (r *RateLimit) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now().UTC()
	for client, limiter := range r.m {
		if now.Sub(limiter.ut) > expireTime {
			delete(r.m, client)
		}
	}
}

func (r *RateLimit) run() {
	ticker := time.NewTicker(time.Minute)

	for range ticker.C {
		r.clear()
	}
}

const (
	name       = "ratelimit"
	expireTime = 5 * time.Minute
)
