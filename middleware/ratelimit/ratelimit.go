package ratelimit

import (
	"context"
	"encoding/hex"
	"net"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/time/rate"
)

// rateLimitExceeded counts queries rejected by the per-client
// rate-limiter. Both the UDP-cookie-mismatch path and the plain-
// limiter-Allow path contribute. Operators alert on a sustained
// non-zero rate.
var rateLimitExceeded = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_ratelimit_exceeded_total",
	Help: "Total DNS queries rejected by the ratelimit middleware",
})

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

// (*RateLimit).ClientOnly marks the per-client limiter as
// client-traffic-only; middleware.Setup excludes it from internal
// sub-pipelines so an internal sub-query doesn't count against the
// limiter bucket attributed to its outer client.
func (r *RateLimit) ClientOnly() bool { return true }

// (*RateLimit).OncePerQuery: a token is consumed at entry, so the serve
// replay after an inline handoff must not run the limiter again.
func (r *RateLimit) OncePerQuery() bool { return true }

// (*RateLimit).ServeDNS serveDNS implements the Handle interface.
func (r *RateLimit) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer

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

	// A wire-born request carries its cookie as parsed offsets, so the
	// limiter runs without decoding; only the BADCOOKIE reply needs the
	// message. Everything else takes the decoded body below.
	if ch.Request.Undecoded() {
		r.serveWire(ctx, ch)
		return
	}

	// An active limit needs the request's cookie options.
	ctx, req := ch.Materialize(ctx)
	if req == nil {
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
					servercookie = dnsutil.GenerateServerCookie(r.cookiesecret, w.RemoteIP().String(), clientcookie)

					if cachedcookie == "" || cachedcookie == option.String() {
						ch.Next(ctx)

						l.cookie.Store(servercookie)
						return
					}

					if w.Proto() == "udp" {
						if !l.rl.Allow() {
							rateLimitExceeded.Inc()
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
		rateLimitExceeded.Inc()
		// no reply to client
		ch.Cancel()
		return
	}

	ch.Next(ctx)

	if servercookie != "" {
		l.cookie.Store(servercookie)
	}
}

// serveWire mirrors the decoded body over parsed wire facts. The cookie
// comparison works on the hex form option.String() produces, so a request
// whose cookie verifies — or that has no cookie and passes the limiter —
// continues down the chain undecoded. The one branch that must write a
// cookie back to the client, UDP BADCOOKIE, materializes; it is the
// stale-cookie retry path, not the steady state.
func (r *RateLimit) serveWire(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer

	l := r.getLimiter(w.RemoteIP())
	cachedcookie := l.cookie.Load().(string)

	if echo := ch.Request.CookieEcho(); echo != nil {
		fullcookie := hex.EncodeToString(echo)
		clientcookie := fullcookie[:cookieSize]
		servercookie := dnsutil.GenerateServerCookie(r.cookiesecret, w.RemoteIP().String(), clientcookie)

		if cachedcookie == "" || cachedcookie == fullcookie {
			ch.Next(ctx)

			l.cookie.Store(servercookie)
			return
		}

		if w.Proto() == "udp" {
			// Mirror the decoded body's ordering: the request and its
			// cookie option are in hand before any token is consumed or
			// state stored, so a refused decode mutates nothing.
			mctx, req := ch.Materialize(ctx)
			if req == nil {
				return
			}
			var cookieOpt *dns.EDNS0_COOKIE
			if opt := req.IsEdns0(); opt != nil {
				for _, option := range opt.Option {
					if option.Option() == dns.EDNS0COOKIE {
						cookieOpt = option.(*dns.EDNS0_COOKIE)
						break
					}
				}
			}
			if cookieOpt != nil {
				if !l.rl.Allow() {
					rateLimitExceeded.Inc()
					ch.Cancel()
					return
				}

				l.cookie.Store(servercookie)
				cookieOpt.Cookie = servercookie

				ch.CancelWithRcode(dns.RcodeBadCookie, false)
				return
			}

			// No cookie option in the decoded form — unreachable while
			// ratelimit precedes edns in the chain, but the decoded body
			// would take the plain limiter, so take it here too, on the
			// materialized context.
			if !l.rl.Allow() {
				rateLimitExceeded.Inc()
				ch.Cancel()
				return
			}

			ch.Next(mctx)

			l.cookie.Store(servercookie)
			return
		}

		// A mismatched cookie over a spoof-proof transport: like the
		// decoded body, fall through to the plain limiter.
		if !l.rl.Allow() {
			rateLimitExceeded.Inc()
			ch.Cancel()
			return
		}

		ch.Next(ctx)

		l.cookie.Store(servercookie)
		return
	}

	if !l.rl.Allow() {
		rateLimitExceeded.Inc()
		ch.Cancel()
		return
	}

	ch.Next(ctx)
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
