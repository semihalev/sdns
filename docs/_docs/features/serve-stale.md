---
layout: doc
title: Serve stale
category: Features
order: 3
description: Answering from an expired entry when resolution fails, or at once with a background refresh, and the bounds on when that is allowed.
---

```toml
serve_stale         = true
serve_stale_max_ttl = "24h"
```

When an authoritative server is unreachable, the correct DNS answer is SERVFAIL
and the practical result is a broken site. RFC 8767 permits a resolver to answer
from an expired cache entry instead. sdns implements it, off by default.

## Four bounds, all of which must hold

**It is failure-triggered, by default.** A stale answer is a last resort after
resolution has actually failed, not a latency optimisation. A query that can be
resolved is resolved. `serve_stale_mode = "immediate"`, below, is the one
opt-in exception, and the other three bounds hold in it unchanged.

**It is positive-only.** Expired positive answers may be served. An expired
NXDOMAIN or NODATA is not, a name that once did not exist is not evidence that
it still does not.

**The delegation lease is a hard ceiling.** If the parent granted the delegation
for a bounded time and that grant has expired, no answer under it is served,
however recently it was cached. A parent that has cut a zone loose has said
something about the zone, and stale-serving does not get to ignore it.

**`serve_stale_max_ttl` bounds the rest.** Measured from the moment the answer's
own TTL expired, defaulting to 24 hours. An explicit `"0"` removes this bound and
leaves the delegation lease as the only one.

## What a stale answer looks like

Every record in a stale answer carries a TTL of 30 seconds, or what is left of
the delegation lease if that is shorter. When less than one second of the
lease is left, the stale answer is declined, since a TTL of 0 is not allowed.
A client that sent EDNS gets EDE 3 (Stale Answer). The AD bit is cleared when
any signature in the answer has passed its expiration.

## Across restarts

With `cache_persist`, an entry whose TTL ran out while sdns was down is not
restored. Stale-eligible entries therefore do not survive a restart: after one,
only answers still inside their TTL can be served stale later.

## Immediate mode

```toml
serve_stale      = true
serve_stale_mode = "immediate"
```

Prefetch refreshes an entry only when a query arrives in the last part of its
TTL. A name asked for now and then misses that window, and the first query after
its TTL runs out waits for a full resolution. In immediate mode that query is
answered at once from the expired entry, and the entry is refreshed in the
background, so the next query gets the fresh answer from the cache.

This trades freshness for latency: a client can receive an answer past its TTL
even though a fresh one was reachable. RFC 8767 §7 advises against it for that
reason, which is why it is off unless chosen. The default, `"failure"`, is the
behaviour RFC 8767 describes.

What immediate mode serves, and when it declines and resolves instead:

- The same bounds as the failure path: positive answers only, the delegation
  lease, `serve_stale_max_ttl`, and a TTL of 30 seconds that never outlives the
  lease.
- Only with a refresh under way. If the refresh cannot be queued, the query is
  resolved rather than answered stale.
- Only for a client's own question with the RD bit set. A question that does not
  desire recursion, and a lookup the resolver makes for itself, never get one.
- Not for ECS-scoped entries, which have no background refresh.
- Not for an alias chain the entry cannot complete by itself, and not when a
  signature in the answer has lapsed.

A refresh that fails is recorded as a resolution failure (RFC 9520). Until that
failure expires, queries are answered stale through the failure path without
starting another refresh, so a failing authority is not retried on every query.

Do not use immediate mode on a resolver that validates domain control, such as
for certificate issuance: stale answers widen the window in which an address a
name no longer points to can still be returned (RFC 8767 §10).

## Forwarder mode

In whole-server forwarder mode there is no learned delegation cut, so that
ceiling does not exist. `serve_stale_max_ttl = "0"` there means retention until
the entry is evicted from the cache, which is a much weaker bound than it is in
recursive mode. Set a real duration if you forward.

## Watching it

```
dns_cache_stale_answers_total             answers served past expiry after a failure
dns_cache_stale_immediate_answers_total   answers served past expiry at once, in immediate mode
```

The first should be near zero in normal operation and spike during an outage.
The second tracks how often immediate mode spares a client a resolution. A
persistently nonzero rate means something you depend on is chronically failing
to resolve, and the stale answers are masking it.
