package ratelimit

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/time/rate"
)

type limiter struct {
	rl     *rate.Limiter
	cookie atomic.Value
}

// RateLimit type
type RateLimit struct {
	cookiesecret string

	cache *cache.Cache
	rate  int
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
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
func (r *RateLimit) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if w.Internal() {
		ch.Next(ctx)
		return
	}

	if r.rate == 0 {
		ch.Next(ctx)
		return
	}

	if w.RemoteIP() == nil {
		ch.Next(ctx)
		return
	} else if w.RemoteIP().IsLoopback() {
		ch.Next(ctx)
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
						ch.Next(ctx)

						l.cookie.Store(servercookie)
						return
					}

					if w.Proto() == "udp" {
						if !l.rl.Allow() {
							ch.Cancel()
							return
						}

						l.cookie.Store(servercookie)
						option.(*dns.EDNS0_COOKIE).Cookie = servercookie

						ch.CancelWithRcode(dns.RcodeBadCookie, false)

						return
					}
				}
			}
		}
	}

	if !l.rl.Allow() {
		//no reply to client
		ch.Cancel()
		return
	}

	ch.Next(ctx)

	if servercookie != "" {
		l.cookie.Store(servercookie)
	}
}

func (r *RateLimit) getLimiter(remoteip net.IP) *limiter {
	xxhash := xxhash.New()
	_, _ = xxhash.Write(remoteip)
	key := xxhash.Sum64()

	if v, ok := r.cache.Get(key); ok {
		return v.(*limiter)
	}

	limit := rate.Limit(0)
	if r.rate > 0 {
		limit = rate.Every(time.Minute / time.Duration(r.rate))
	}

	rl := rate.NewLimiter(limit, r.rate)

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
