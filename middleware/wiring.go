package middleware

import "github.com/miekg/dns"

// ClientOnly marks a Handler as serving real client traffic only.
// Middlewares that implement this method returning true are excluded
// from the internal sub-pipeline built in Setup — they exist to
// observe, rate-limit, or authorise external client queries, and
// either add noise (metrics, dnstap, accesslog) or actively hurt
// (ratelimit, accesslist, reflex) when an internal sub-query
// traverses them.
//
// The default for handlers that do NOT implement ClientOnly is
// "include in the internal sub-pipeline" — safe for anything
// participating in query resolution (hostsfile, blocklist, cache,
// failover, resolver, forwarder, etc).
type ClientOnly interface {
	ClientOnly() bool
}

// Store is the minimum cache facade a resolver sub-query needs.
// Satisfied by cache.Store; declared here so middleware.Setup can
// wire it from one handler into another without either importing
// the cache package.
type Store interface {
	Get(req *dns.Msg) (*dns.Msg, bool)
	SetFromResponse(resp *dns.Msg, keyCD bool)
}

// StoreProvider is implemented by handlers that own a Store which
// should be shared with other handlers (today: the cache
// middleware; consumed by the resolver handler).
type StoreProvider interface {
	Store() Store
}

// StoreSetter is implemented by handlers that consume a Store
// injected at Setup time (today: the resolver handler).
type StoreSetter interface {
	SetStore(s Store)
}

// QueryerSetter is implemented by handlers that consume the
// internal-sub-pipeline Queryer (today: cache middleware for CNAME
// chase, resolver for NS A/AAAA and DNAME target).
type QueryerSetter interface {
	SetQueryer(q Queryer)
}

// PrefetchQueryerSetter is implemented by handlers that consume
// the prefetch sub-pipeline Queryer (today: cache middleware's
// prefetch worker).
type PrefetchQueryerSetter interface {
	SetPrefetchQueryer(q Queryer)
}
