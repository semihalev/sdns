package ratelimit

import (
	"hash/fnv"
	"net"
	"sync/atomic"
	"time"

	rl "github.com/bsm/ratelimit"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

type limiter struct {
	rl     *rl.RateLimiter
	cookie atomic.Value
}

// RateLimit type
type RateLimit struct {
	cookiesecret string

	cache *cache.Cache
	rate  int
}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})
}

// New return accesslist
func New(cfg *config.Config) *RateLimit {
	r := &RateLimit{
		cache:        cache.New(cacheSize),
		cookiesecret: cfg.CookieSecret,
		rate:         cfg.ClientRateLimit,
	}

	return r
}

// Name return middleware name
func (r *RateLimit) Name() string { return name }

// ServeDNS implements the Handle interface.
func (r *RateLimit) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	if r.rate == 0 {
		dc.NextDNS()
		return
	}

	if w.RemoteIP() == nil {
		dc.NextDNS()
		return
	} else if w.RemoteIP().IsLoopback() {
		dc.NextDNS()
		return
	}

	var cachedcookie, clientcookie, servercookie string

	l := r.getLimiter(w.RemoteIP())
	cachedcookie = l.cookie.Load().(string)

	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			switch option.Option() {
			case dns.EDNS0COOKIE:
				if len(option.String()) >= cookieSize {
					clientcookie = option.String()[:cookieSize]
					servercookie = dnsutil.GenerateServerCookie(r.cookiesecret, w.RemoteIP().String(), clientcookie)

					if cachedcookie == "" || cachedcookie == option.String() {
						dc.NextDNS()

						l.cookie.Store(servercookie)
						return
					}

					if w.Proto() == "udp" {
						if l.rl.Limit() {
							dc.Abort()
							return
						}

						l.cookie.Store(servercookie)
						option.(*dns.EDNS0_COOKIE).Cookie = servercookie

						w.WriteMsg(dnsutil.HandleFailed(req, dns.RcodeBadCookie, false))

						dc.Abort()
						return
					}
				}
			}
		}
	}

	if l.rl.Limit() {
		//no reply to client
		dc.Abort()
		return
	}

	dc.NextDNS()

	if servercookie != "" {
		l.cookie.Store(servercookie)
	}
}

func (r *RateLimit) getLimiter(remoteip net.IP) *limiter {
	fnv64 := fnv.New64()
	fnv64.Write(remoteip)
	key := fnv64.Sum64()

	if v, ok := r.cache.Get(key); ok {
		return v.(*limiter)
	}

	rl := rl.New(r.rate, time.Minute)

	l := &limiter{rl: rl}
	l.cookie.Store("")

	r.cache.Add(key, l)

	return l
}

const (
	cacheSize  = 256 * 100
	cookieSize = 16

	name = "ratelimit"
)
