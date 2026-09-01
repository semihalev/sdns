---
layout: doc
title: Access control and blocking
category: Configuration
order: 5
description: Who may query, how fast, and which names never resolve.
---

## Who may query

```toml
accesslist = ["127.0.0.1/32", "::1/128", "192.168.0.0/16"]
```

CIDR ranges allowed to query this resolver. Queries from anywhere else are
refused before any resolution work happens, the access list runs near the front
of the middleware chain, ahead of the cache and the resolver.

The shipped default is `["0.0.0.0/0", "::0/0"]`, which allows everyone. That is
right for a resolver on loopback and wrong for one on a public address. An open
recursive resolver on the internet will be found and used for reflection
attacks, so narrow this before you bind to a reachable address.

Watch `dns_accesslist_denied_total` to see whether anything is being refused.

## Rate limits

```toml
ratelimit       = 0     # queries per second, whole server; 0 disables
clientratelimit = 0     # queries per minute, per client IP; 0 disables
```

Both are off by default. `clientratelimit` is the more useful of the two on a
resolver serving known clients, it contains one misbehaving host without
capping the server. `ratelimit` is a blunt ceiling on everything.

Refusals increment `dns_ratelimit_exceeded_total`.

## Reflection and amplification defence

```toml
reflexenabled      = false
reflexblockmode    = true
reflexlearningmode = false
# reflexthreshold  = 0.7
```

Tracks per-IP behaviour to identify spoofed sources being used for reflection.
Off by default.

The two modes matter. With `reflexlearningmode = true` detections are logged and
nothing is blocked, which is how you calibrate the threshold against your own
traffic. `reflexblockmode = false` also only logs. Turn on blocking after you
have watched the detections for a while and are satisfied they are not your own
clients, the threshold is a score between 0 and 1, and lower is more aggressive.

## Blocking names

```toml
blocklists = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
blocklist  = ["ads.example.com"]
whitelist  = ["important.example.com"]
nullroute   = "0.0.0.0"
nullroutev6 = "::0"
```

`blocklists` are URLs downloaded and refreshed periodically; `blocklist` is a
manual list in the configuration file; `whitelist` bypasses all blocking and
wins over both. A blocked A query answers `nullroute` and a blocked AAAA answers
`nullroutev6`.

Entries can also be managed at runtime through the API without a restart:

```bash
curl http://127.0.0.1:8080/api/v1/block/set/ads.example.com
curl http://127.0.0.1:8080/api/v1/block/exists/ads.example.com
curl http://127.0.0.1:8080/api/v1/block/remove/ads.example.com
```

For policy that goes beyond a name list, rewriting to a CNAME, matching on the
client's address or on the address in the answer, vendor feeds over AXFR, or a
shadow mode that counts what enforcement *would* do, use
[Response Policy Zones]({{ '/docs/features/rpz/' | relative_url }}) instead.
RPZ runs after the blocklist in the chain and is the richer of the two.

`blocklistdir` is deprecated; the directory is created under `directory`
automatically.

## Local answers from a hosts file

```toml
hostsfile = "/etc/hosts"
```

Serves entries from a hosts file directly. Empty disables it. For answers scoped
to particular client networks rather than served to everyone, use
[views]({{ '/docs/features/views/' | relative_url }}).

## Per-domain metrics

```toml
domainmetrics      = false
domainmetricslimit = 1000
```

Tracks query counts per domain, exported as `dns_domain_queries_total`. Off by
default because the cardinality is unbounded on a public resolver, that is
what the limit is for. `0` means unlimited, which on a busy resolver will
consume memory until something gives.
