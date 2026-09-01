---
layout: doc
title: Serve stale
category: Features
order: 3
description: Answering from an expired entry when resolution fails, and the four bounds on when that is allowed.
---

```toml
serve_stale         = true
serve_stale_max_ttl = "24h"
```

When an authoritative server is unreachable, the correct DNS answer is SERVFAIL
and the practical result is a broken site. RFC 8767 permits a resolver to answer
from an expired cache entry instead. sdns implements it, off by default.

## Four bounds, all of which must hold

**It is failure-triggered.** A stale answer is a last resort after resolution has
actually failed, never a latency optimisation. A query that can be resolved is
resolved.

**It is positive-only.** Expired positive answers may be served. An expired
NXDOMAIN or NODATA is not — a name that once did not exist is not evidence that
it still does not.

**The delegation lease is a hard ceiling.** If the parent granted the delegation
for a bounded time and that grant has expired, no answer under it is served,
however recently it was cached. A parent that has cut a zone loose has said
something about the zone, and stale-serving does not get to ignore it.

**`serve_stale_max_ttl` bounds the rest.** Measured from the moment the answer's
own TTL expired, defaulting to 24 hours. An explicit `"0"` removes this bound and
leaves the delegation lease as the only one.

## Forwarder mode

In whole-server forwarder mode there is no learned delegation cut, so that
ceiling does not exist. `serve_stale_max_ttl = "0"` there means retention until
the entry is evicted from the cache, which is a much weaker bound than it is in
recursive mode. Set a real duration if you forward.

## Watching it

```
dns_cache_stale_answers_total   answers served past expiry
```

This should be near zero in normal operation and spike during an outage. A
persistently nonzero rate means something you depend on is chronically failing
to resolve, and the stale answers are masking it.
