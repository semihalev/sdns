package middleware

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

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

// OncePerQuery marks a Handler whose ServeDNS entry has side effects that
// must happen exactly once per client query — a rate-limit token, a
// per-query score, an emitted tap frame. The server's inline fast path
// runs the full chain on the transport reader and replays the query on a
// worker when the cache cannot answer without blocking; handlers carrying
// this marker are excluded from the replay so their entry effect is not
// doubled. Handlers whose effects key off the response — metrics and
// accesslog gate on Written() — need no marker: the inline pass leaves a
// handed-off query unwritten, so they fire exactly once, on the replay.
type OncePerQuery interface {
	OncePerQuery() bool
}

// Store is the minimum cache facade a resolver sub-query needs.
// Satisfied by cache.Store; declared here so middleware.Setup can
// wire it from one handler into another without either importing
// the cache package.
type Store interface {
	Get(req *dns.Msg) (*dns.Msg, bool)
	// SetFromResponse stores resp keyed on (Question[0], keyCD).
	// cutUntil bounds the entry's effective lifetime to the
	// delegation cut that produced it (GHSA-mqfw-f48p-2vc8); zero
	// means unbounded.
	SetFromResponse(resp *dns.Msg, keyCD bool, cutUntil time.Time)
}

// ContextStore is the optional request-tree-aware cache contract. The built-in
// cache uses ctx to share bounded NSEC3 hash results with required DNSSEC
// validation and to retain client CD/ECS bypass policy across resolver-private
// DS and DNSKEY sub-queries. Third-party stores can keep implementing Store.
type ContextStore interface {
	Store
	GetWithContext(ctx context.Context, req *dns.Msg) (*dns.Msg, bool)
}

// CutStore is the extended production cache contract. Keeping Store's Phase
// 1b signature stable avoids forcing plugin/test stores to implement lineage
// identity before Phase 3 needs it; the built-in cache implements both.
type CutStore interface {
	Store
	SetFromResponseWithCut(resp *dns.Msg, keyCD bool, cutUntil time.Time, cutKey uint64)
}

// ResolutionFailureStore is the optional RFC 9520 extension implemented by
// the built-in cache. A resolver records a zone only after every usable
// authority endpoint for that delegation failed; the cache can then suppress
// random-QNAME retries below the same failed zone (and the resulting
// parent/ancestor traffic) until the bounded backoff expires.
//
// This stays separate from Store so plugins and test stores that only need
// ordinary answer caching do not have to implement failure-state policy.
type ResolutionFailureStore interface {
	Store
	RecordZoneFailure(q dns.Question, zone string)
	ClearZoneFailure(q dns.Question, zone string)
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

// DNSSECCryptoLimiter is the narrow shared concurrency seam required by
// optional cache-side DNSSEC work. TryAcquire is deliberately non-blocking:
// RFC 8198 synthesis is an optimization, so saturation must fall through to
// ordinary resolution instead of waiting ahead of required validation.
type DNSSECCryptoLimiter interface {
	TryAcquire() (release func(), ok bool)
}

// DNSSECCryptoLimiterProvider is implemented by the resolver that owns the
// process-wide DNSSEC concurrency gate.
type DNSSECCryptoLimiterProvider interface {
	DNSSECCryptoLimiter() DNSSECCryptoLimiter
}

// DNSSECCryptoLimiterSetter is implemented by optional DNSSEC work consumers
// such as the RFC 8198 proof cache. Setup wires the resolver-owned instance
// before publishing the pipeline.
type DNSSECCryptoLimiterSetter interface {
	SetDNSSECCryptoLimiter(DNSSECCryptoLimiter)
}
