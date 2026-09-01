---
layout: doc
title: Cache and TTLs
category: Configuration
order: 4
description: Cache size, prefetching, expired answers and what the TTL you receive actually means.
---

## Size and prefetch

```toml
cachesize = 256000
prefetch  = 10        # percent; 0 disables
```

`cachesize` is a record count, not a byte budget. The default holds a busy
resolver's working set comfortably; raising it costs memory roughly in
proportion.

`prefetch` refreshes an entry in the background when a query arrives and the
entry has less than that percentage of its original TTL left. It trades a small
amount of upstream traffic for hits that stay warm on popular names.

The value must be `0` — which turns prefetching off — or between 10 and 90.
Anything else is a configuration error rather than being clamped, so `sdns -t`
rejects it.

## Which TTL you receive

The TTL sdns serves is the answer's own remaining TTL, counted down from when
it was cached. It is not the smallest TTL of everything consulted on the way to
the answer — a short-lived delegation record on the path does not shorten the
answer.

There is one deliberate ceiling: a learned delegation lease. When the parent
granted a delegation for a bounded time, no answer under that delegation is
served past the point the parent's grant expires. That is why a long-TTL record
under a short-lived delegation can come back with less than you expected — the
cut, not the record, is the binding constraint.

## Serving expired answers

```toml
serve_stale         = false
serve_stale_max_ttl = "24h"
```

When resolution ends in SERVFAIL, sdns may answer from an expired positive entry
rather than failing (RFC 8767). Off by default.

`serve_stale_max_ttl` is measured from the moment the answer's TTL expired, and
defaults to 24 hours. An explicit `"0"` leaves the delegation lease as the only
upper bound; in whole-server forwarder mode, which learns no delegation cut,
`"0"` permits retention until the entry is evicted.

The delegation lease is a hard ceiling here too, so this cannot revive data past
a known parent-granted cut. It is failure-triggered and positive-only: a stale
NXDOMAIN is never served. The full design is on the
[Serve stale]({{ '/docs/features/serve-stale/' | relative_url }}) page.

## Negative caching

A name that does not exist is an answer worth keeping, and RFC 2308 says how
long for: the lifetime comes from the SOA in the denial, bounded by the smaller
of its TTL and its MINIMUM field.

That value is a ceiling, not a target. RFC 2308 says how long a resolver *may*
cache the denial, so sdns applies no minimum on top of it: a zone that
publishes a one-second negative TTL gets one second, and a denial carrying no
lifetime at all is not cached.

Ordinary answers do take a five-second floor. The difference is who is being
overruled. A negative TTL is the zone's own statement about how long its denial
holds, and raising it substitutes the resolver's judgement for the only party
entitled to make that call. The floor on a positive answer overrules nobody —
it is the resolver deciding how often to re-ask for a short-lived record, which
is its own business.

A denial arriving without an SOA is not cached either. There is nothing to
derive a lifetime from, and RFC 2308 is explicit that caching it anyway is what
lets two misconfigured servers pass the denial back and forth indefinitely.

The two mechanisms that *reuse* a denial for names it was never asked about are
bounded the same way, and were already. Both are on by default and both are
covered under
[Resolution and DNSSEC]({{ '/docs/configuration/resolution/' | relative_url }}):
RFC 8020 lets one NXDOMAIN answer every name beneath it, and RFC 8198 answers
later denials from a validated NSEC or NSEC3 record already held. For these,
sdns takes the smallest value across every component of the proof — the SOA,
the records in the authority section, the signatures over them, and the
delegation lease — and applies no floor on top, because a floor there would let
a cache setting extend an authenticated denial past the proof that authorised
it. Answering one name from another's denial is a claim about a whole subtree,
and it expires with the weakest thing supporting it. They are counted by
`nxdomain_cut_hits_total` and `aggressive_negative_hits_total`.

## Failure caching

```toml
expire = 600      # legacy; retained for compatibility
```

`expire` is a legacy error-cache ceiling kept so old configuration files still
load. Recursive resolution failures are governed by the RFC 9520 failure cache
in the `[recursion_firewall]` block instead — see the
[recursion firewall]({{ '/docs/features/recursion-firewall/' | relative_url }}).

## Purging

```bash
curl http://127.0.0.1:8080/api/v1/purge/example.com./A
```

Drops one name and type from the cache. There is no purge-everything endpoint;
restarting is the way to empty the cache entirely.

## Watching it

```
dns_cache_size              current entries
dns_cache_hits_total        hits
dns_cache_misses_total      misses
dns_cache_hit_rate          percentage, 0-100
dns_cache_evictions_total   entries dropped under pressure
dns_cache_prefetches_total  background refreshes
dns_cache_stale_answers_total  answers served past expiry
dns_cache_wire_fastpath_total  hits served straight from stored bytes
```

A rising `dns_cache_evictions_total` with a falling hit rate is the signal that
`cachesize` is too small for the working set.
