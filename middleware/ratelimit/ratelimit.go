package ratelimit

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"golang.org/x/time/rate"
)

type limiter struct {
	rl     *rate.Limiter
	cookie atomic.Value
}

// RateLimit type.
type RateLimit struct {
	cookiesecret string

	store *LimiterStore
	rate  int
}

// New return accesslist.
func New(cfg *config.Config) *RateLimit {
	r := &RateLimit{
		store:        NewLimiterStore(cacheSize, cfg.ClientRateLimit),
		cookiesecret: cfg.CookieSecret,
		rate:         cfg.ClientRateLimit,
	}

	// Periodic cleanup of old limiters (every 5 minutes)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			r.store.Cleanup(10 * time.Minute)
		}
	}()

	return r
}

// (*RateLimit).Name name return middleware name.
func (r *RateLimit) Name() string { return name }

// (*RateLimit).ServeDNS serveDNS implements the Handle interface.
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
			if option.Option() == dns.EDNS0COOKIE {
				if len(option.String()) >= cookieSize {
					clientcookie = option.String()[:cookieSize]
					servercookie = util.GenerateServerCookie(r.cookiesecret, w.RemoteIP().String(), clientcookie)

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
		// no reply to client
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

	return r.store.Get(key)
}

const (
	cacheSize  = 256 * 100
	cookieSize = 16

	name = "ratelimit"
)
