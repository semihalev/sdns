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

`api = ""` disables it. When `bearertoken` is set, the blocklist, purge and
metrics routes require `Authorization: Bearer <token>`, and anything else gets
`401 {"error":"unauthorized"}`. The `/debug/pprof` routes are the exception and
are covered below.

| Endpoint | Method | Purpose | Answer |
|---|---|---|---|
| `/metrics` | GET | Prometheus exposition | text |
| `/api/v1/purge/:qname/:qtype` | GET | Drop one question from every cache | `{"success":true}` |
| `/api/v1/block/exists/:key` | GET | Is a name blocked | `{"exists":true}` |
| `/api/v1/block/get/:key` | GET | Read a blocklist entry | `{"success":true}`, or 404 |
| `/api/v1/block/set/:key` | GET | Add a name | `{"success":true}` |
| `/api/v1/block/remove/:key` | GET | Remove a name | `{"success":false}` if absent |
| `/api/v1/block/set/batch` | POST | Add many | `{"requested":3,"added":3,"skipped":0}` |
| `/api/v1/block/remove/batch` | POST | Remove many | `{"requested":2,"removed":1,"missing":1}` |

A key is a name (`ads.example.com`) or a wildcard (`*.ads.example.com`). `set`
answers `success:false` for a name already there or one the whitelist covers,
and a batch counts those as `skipped`. The batch endpoints take
`{"keys":["a.example","*.b.example"]}`, at most 8 MiB, and refuse unknown
fields or an empty list with 400; each batch is one change and one write of the
blocklist file. Purge drops the question from the answer cache, both CD
partitions, and for `NS` from the delegation cache too; the root is
`/api/v1/purge/./NS`, and an unknown `qtype` is a 400. A path that exists under
another method answers 405, and so does `HEAD` on a route that changes state.

```bash
curl -X POST http://127.0.0.1:8080/api/v1/block/set/batch \
  -H 'Content-Type: application/json' \
  -d '{"keys":["ads.example.com","*.tracker.example"]}'
```

The block endpoints are registered whether or not you configured a blocklist,
the default chain always builds the handler.

The routes that change state, block `set` and `remove`, the batches and purge,
refuse a request a browser sends on behalf of another site with 403: a web page
cannot add to the blocklist or purge the cache through an image tag or a form,
token or not. Browsers say where a request comes from in `Sec-Fetch-Site` and
`Origin`; curl and scripts send neither and are not affected. No response
carries a CORS grant, so another site cannot read what this listener returns,
the metrics included.

Keep the listener on loopback all the same. It is plain HTTP: `bearertoken`
travels in the clear to a reachable address and can be replayed, so it is a
second layer rather than the protection. A reachable deployment needs a
TLS-terminating authenticating proxy, a VPN, or a firewall that restricts the
source.

`/debug/pprof` is served only when `SDNS_PPROF=true` is in the environment, and
those routes are the one exception to the token, since pprof tooling sends no
`Authorization` header. Every profile the runtime has is there, `goroutineleak`
included, alongside `profile`, `trace` and `symbol`. With pprof on, a token is
not sufficient protection for this listener; keep it on loopback or behind an
authenticating proxy. See
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
alerting on because it is invisible to clients, they just see SERVFAIL.

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

`dns_recursion_fanout_ratio`, outbound queries per client query, is the single
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

**Everything else.** All 68 metrics, with their types, labels, help strings,
ready-made PromQL and the alerts worth having, live in the
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
