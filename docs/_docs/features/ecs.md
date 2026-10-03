---
layout: doc
title: EDNS Client Subnet
category: Features
order: 7
description: Forwarding, clamped, the client subnet a trusted sender supplies so geo-aware services can answer for the right location.
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

sdns never builds an ECS option from the address a query arrives from. It only
forwards ECS that the sender put in its own query, after clamping it. The
typical sender is a load balancer or a stub forwarder that sits in front of
sdns and knows the real client's address.

sdns strips ECS by default, following the privacy guidance in RFC 7871 §11. This
section is strictly opt-in, every option below is ignored while `enabled` is
false, and client-supplied ECS is removed before forwarding.

## How much locality to disclose

```toml
forward_v4 = 24
forward_v6 = 56
```

The maximum source-prefix length sent upstream. An ECS option with a longer,
more specific prefix is clamped to this value, and its address is truncated to
the clamped length, so the resolver never forwards more locality than you
intended. `/24` and `/56` match common practice.

## Who gets ECS

```toml
client_networks = ["10.0.0.0/8"]
```

The senders trusted to supply ECS. The list is matched against the address
the query arrives from (the transport peer), not against the subnet inside the
ECS option. Empty, the default, trusts every sender that reaches this resolver.
Populating it is the useful configuration: list the load balancers and stub
forwarders that set ECS on behalf of their clients, and ECS from anyone else is
stripped.

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

`cache_limit_ttl` caps the TTL of any scoped entry, geo answers go stale
faster than a general TTL suggests, and a misconfigured upstream should not be
able to pin an audience-specific answer for hours. Omitted, there is no cap;
the generated configuration file sets `5m`.

`min_scope_v4` and `min_scope_v6` widen a narrower SCOPE before it becomes part
of the key. That is what bounds cardinality: without a floor, a resolver with
diverse clients would key entries per client. They default to the forwarding
ceilings, and `0` means "use that ceiling".

## Watching it

```
dns_cache_ecs_lookups_total   cache lookups carrying a client scope
```
