package ratelimit

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/cookie"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/time/rate"
)

// rateLimitExceeded counts queries rejected by the per-client
// rate-limiter, dropped or answered with a BADCOOKIE challenge. Operators
// alert on a sustained non-zero rate.
var rateLimitExceeded = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_ratelimit_exceeded_total",
	Help: "Total DNS queries rejected by the ratelimit middleware",
})

type limiter struct {
	rl *rate.Limiter
	// challenge bounds the BADCOOKIE replies a client over its quota
	// draws; nil for a source already proved.
	challenge *rate.Limiter
}

// RateLimit charges each client address a token per query. A query whose
// source is proved, by its transport's handshake or by a valid server
// cookie, draws from one bucket per address; any other from a second. The
// two are separate stores, so a flood from spoofed addresses can neither
// spend a proved client's quota nor evict its entry. Clients behind one
// address share its quota.
type RateLimit struct {
	secret cookie.Secret

	// limits is swapped whole by a reload of the rate.
	limits atomic.Pointer[limits]
}

// limits is one rate and the buckets charged at it: store holds the
// unproved buckets, verified the proved ones.
type limits struct {
	store    *LimiterStore
	verified *LimiterStore
	rate     int
}

func newLimits(rate int) *limits {
	l := &limits{
		store:    NewLimiterStore(cacheSize, rate),
		verified: NewLimiterStore(cacheSize, rate),
		rate:     rate,
	}
	l.store.challenges = true
	return l
}

// New return accesslist.
func New(cfg *config.Config) *RateLimit {
	r := &RateLimit{secret: cookie.NewSecret(cfg.CookieSecret)}
	r.limits.Store(newLimits(cfg.ClientRateLimit))

	// Periodic cleanup of old limiters (every 5 minutes)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			l := r.limits.Load()
			l.store.Cleanup(10 * time.Minute)
			l.verified.Cleanup(10 * time.Minute)
		}
	}()

	return r
}

// ReloadKeys implements middleware.Reloader.
func (r *RateLimit) ReloadKeys() []string { return []string{"clientratelimit"} }

// PrepareReload implements middleware.Reloader. A new rate gets new
// buckets, so every client starts the new rate with a full quota.
func (r *RateLimit) PrepareReload(cfg *config.Config) (func(), error) {
	l := newLimits(cfg.ClientRateLimit)
	return func() { r.limits.Store(l) }, nil
}

// (*RateLimit).Name name return middleware name.
func (r *RateLimit) Name() string { return name }

// (*RateLimit).ClientOnly marks the per-client limiter as
// client-traffic-only; middleware.Setup excludes it from internal
// sub-pipelines so an internal sub-query doesn't count against the
// limiter bucket attributed to its outer client.
func (r *RateLimit) ClientOnly() bool { return true }

// (*RateLimit).ServeDNS serveDNS implements the Handle interface. It reads
// the request's parsed facts only, so a wire-born request stays undecoded.
func (r *RateLimit) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	// The replay pass finishes a query the inline pass admitted: its
	// token was consumed and its cookie checked there, and a second
	// charge would bill one question twice. The limiter is pure entry
	// effect, nothing here observes the response, so the replay just
	// passes through.
	if ch.Replay() {
		ch.Next(ctx)
		return
	}

	w := ch.Writer

	if w.Internal() {
		ch.Next(ctx)
		return
	}

	lim := r.limits.Load()
	if lim.rate == 0 {
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

	st := ch.Cookie(r.secret)
	if ch.SourceVerified() || st.Verdict == cookie.Valid {
		if lim.verified.Get(ipKey(w.RemoteIP())).rl.Allow() {
			ch.Next(ctx)
			return
		}
		rateLimitExceeded.Inc()
		ch.Cancel()
		return
	}

	l := lim.store.Get(ipKey(w.RemoteIP()))
	if l.rl.Allow() {
		ch.Next(ctx)
		return
	}
	rateLimitExceeded.Inc()

	// Over its quota, a client that sent a cookie is told, within a
	// budget of its own, how to prove itself: BADCOOKIE with a server
	// cookie (RFC 7873 §5.2.3), which its retry carries into the proved
	// bucket. The edns layer writes the reply after its own checks. With
	// no cookie there is nothing to offer, and past the budget a reply
	// would only reflect traffic at a spoofed address.
	if (st.Verdict == cookie.ClientOnly || st.Verdict == cookie.Invalid) && l.challenge.Allow() {
		ch.ChallengeCookie()
		ch.Next(ctx)
		return
	}
	ch.Cancel()
}

// getLimiter returns the unproved bucket of remoteip.
func (r *RateLimit) getLimiter(remoteip net.IP) *limiter {
	return r.limits.Load().store.Get(ipKey(remoteip))
}

// ipKey hashes the address in one form: transports hand an IPv4 address
// over as 4 bytes or as 16, IPv4-mapped, and the two must be one client.
func ipKey(ip net.IP) uint64 {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return xxhash.Sum64(ip)
}

const (
	cacheSize = 256 * 100

	name = "ratelimit"
)
