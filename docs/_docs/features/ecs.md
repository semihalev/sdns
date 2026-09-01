---
layout: doc
title: EDNS Client Subnet
category: Features
order: 7
description: Forwarding a slice of the client's address so geo-aware services can answer for the right location.
---

```toml
[ecs]
enabled    = true
forward_v4 = 24
forward_v6 = 56
```

ECS (RFC 7871) passes part of the client's IP address to the authoritative
server, so CDNs and geo-aware load balancers can return an answer appropriate to
where the client actually is.

sdns strips ECS by default, following the privacy guidance in RFC 7871 §11. This
section is strictly opt-in — every option below is ignored while `enabled` is
false, and client-supplied ECS is removed before forwarding.

## How much locality to disclose

```toml
forward_v4 = 24
forward_v6 = 56
```

The maximum source-prefix length sent upstream. A client that sends a narrower,
more specific prefix is clamped to this value, so the resolver never leaks more
locality than you intended — including when the client asked it to. `/24` and
`/56` match common practice.

## Who gets ECS

```toml
client_networks = ["10.0.0.0/8"]
```

CIDRs eligible for forwarding. Empty — the default — means every client that
reaches this resolver. Populating it is the useful configuration: forward ECS
for known internal sources such as load balancers, CDN edges and corporate
networks, and strip it for the open internet.

## The scope-keyed cache

```toml
cache_limit_ttl = "5m"
min_scope_v4    = 24
min_scope_v6    = 56
```

An answer the authority marks with a nonzero SCOPE is stored under a
scope-specific key and served only to clients inside that scope; SCOPE=0
answers share the ordinary global entry. A geo-tailored answer does not reach a
client it was not meant for.

`cache_limit_ttl` caps the TTL of any scoped entry — geo answers go stale
faster than a general TTL suggests, and a misconfigured upstream should not be
able to pin an audience-specific answer for hours.

`min_scope_v4` and `min_scope_v6` widen a narrower SCOPE before it becomes part
of the key. That is what bounds cardinality: without a floor, a resolver with
diverse clients would key entries per client. They default to the forwarding
ceilings, and `0` means "use that ceiling".

## Watching it

```
dns_cache_ecs_lookups_total   cache lookups carrying a client scope
```
