---
layout: doc
title: Monitoring
category: Deployment
order: 3
description: The API, the metrics worth alerting on, and query logging.
---

## The API listener

```toml
api         = "127.0.0.1:8080"
bearertoken = "a-long-random-string"
```

`api = ""` disables it. When `bearertoken` is set every request must carry
`Authorization: Bearer <token>`.

| Endpoint | Method | Purpose |
|---|---|---|
| `/metrics` | GET | Prometheus exposition |
| `/api/v1/purge/:qname/:qtype` | GET | Drop one cache entry |
| `/api/v1/block/exists/:key` | GET | Is a name blocked |
| `/api/v1/block/get/:key` | GET | Read a blocklist entry |
| `/api/v1/block/set/:key` | GET | Add a name |
| `/api/v1/block/remove/:key` | GET | Remove a name |
| `/api/v1/block/set/batch` | POST | Add many |
| `/api/v1/block/remove/batch` | POST | Remove many |

The block endpoints are registered whether or not you configured a blocklist —
the default chain always builds the handler. Note that the
single-name mutations are GET requests, which means a browser or a link
preview can trigger them — another reason to keep this listener on loopback or
behind a token.

`/debug/pprof` is served only when `SDNS_PPROF=true` is in the environment — and
those routes are the one exception to the token, since pprof tooling sends no
`Authorization` header. With pprof on, a token is not sufficient protection for
this listener; keep it on loopback or behind an authenticating proxy. See
[diagnostics]({{ '/docs/deployment/diagnostics/' | relative_url }}).

## Metrics worth an alert

**Is it answering?**

```
dns_queries_total          total queries, by type and rcode
dns_resolver_failures_total
dns_resolver_dnssec_failures_total
```

A rise in `dns_resolver_dnssec_failures_total` is either an upstream zone that
broke its signing or something interfering with your traffic. It is worth
alerting on because it is invisible to clients — they just see SERVFAIL.

**Is the cache doing its job?**

```
dns_cache_hit_rate
dns_cache_evictions_total
dns_cache_size
```

Evictions climbing while the hit rate falls means `cachesize` is below the
working set.

**Is it being abused?**

```
dns_accesslist_denied_total
dns_ratelimit_exceeded_total
dns_recursion_fanout_ratio
dns_recursion_firewall_exhaustions_total
```

`dns_recursion_fanout_ratio` — outbound queries per client query — is the single
most useful number for spotting a query pattern designed to cost you work. It
sits low and flat in normal operation.

**Is anything being dropped at the door?**

```
dns_udp_ingress_drops_total
dns_udp_ingress_overflow_total
dns_tcp_ingress_drops_total
dns_listener_errors_total
```

Overflow means queries arrived faster than the workers accepted them. That is a
capacity signal, not a bug.

**Everything else.** All 64 metrics — with their types, labels, help strings,
ready-made PromQL and the alerts worth having — are in the
[metrics reference]({{ '/docs/reference/metrics/' | relative_url }}).

## Query logging

Two mechanisms, for two purposes.

```toml
accesslog = "/var/log/sdns/access.log"
```

Common Log Format, one line per query, human-readable. On a busy resolver this
is the largest thing the process writes; it is off by default for that reason.

```toml
dnstapsocket        = "/var/run/sdns/dnstap.sock"
dnstapidentity      = "sdns"
dnstaplogqueries    = true
dnstaplogresponses  = true
dnstapflushinterval = 5
```

dnstap is a binary protocol over a Unix socket, meant for a collector rather
than for reading. It is the right choice when you want to keep query data at
volume.

## Confirming which build is running

```bash
dig @resolver version.bind TXT CHAOS +short
```

Works while `chaos = true`. Useful across a fleet, where the answer to "did
that deploy land everywhere" is otherwise a guess.
