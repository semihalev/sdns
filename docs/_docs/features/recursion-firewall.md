---
layout: doc
title: Recursion firewall
category: Features
order: 4
description: Bounding the total work one request may cause, and caching resolution failures per RFC 9520.
---

A single query can be made to cost a resolver a great deal: a delegation chain
that keeps referring, a zone whose nameservers all need resolving themselves, a
signature set crafted to be expensive to verify. Timeouts bound how *long* that
takes but not how much work it consumes.

The recursion firewall bounds the work itself, across the complete request tree,
retries and nested resolver-generated queries included.

```toml
[recursion_firewall]
mode = "shadow"
```

## Modes

`off` disables accounting. `shadow` records what would have been over budget and
changes no reply. `enforce` terminates over-budget recursion with SERVFAIL.

`shadow` is the shipped default, and it is a genuine default rather than a
placeholder: the right limits depend on your traffic, and the way to find them
is to run shadow and read the histograms before you enforce anything.

## The limits

```toml
max_outbound_queries = 128   # transport attempts in one request tree
max_internal_queries = 32    # resolver-generated child queries
```

An outbound attempt is one packet to one server; retries and UDP-to-TCP
fallbacks each consume another. An internal query is one the resolver generated
for itself: a cache-missed DS or DNSKEY, a nameserver address lookup, an alias
chase. `0` means "use the default" for both; to disable accounting use
`mode = "off"`.

```toml
max_dnskey_candidates      = 4    # same-tag keys tried per signature or DS
max_rrset_signature_checks = 8    # signatures tried per RRset
max_signature_checks       = 32   # signature verifications per request tree
max_ds_digests             = 32   # DS digest computations per request tree
max_nsec3_hashes           = 32   # NSEC3 hashes per request tree
max_concurrent_crypto      = 32   # crypto operations in flight, server-wide
```

The first two bound one verification; the next three bound the whole request
tree; the last bounds the server. Calibrate them from the
`dnssec_work_per_request` histogram, and pay particular attention to the NSEC3
p99, NSEC3 hashing is the operation an attacker can most cheaply make expensive.

## Failure caching (RFC 9520)

```toml
failure_cache_size    = 4096
failure_cache_min_ttl = "5s"
failure_cache_max_ttl = "5m"
```

This cache is active regardless of `mode`. `mode` governs work accounting;
caching failures and the per-server retry ceiling are protocol requirements, not
optional hardening.

The first failed resolution is held for 5 seconds. Repeated failures back off
exponentially to 5 minutes. RFC 9520 requires every active failure interval to
fall between 1 second and 5 minutes, which is what the two bounds enforce.

Without this, a name that cannot resolve becomes a retry loop that hits the
upstream once per client query.

## Watching it

```
dns_recursion_firewall_exhaustions_total  budget crossings, by limit
dns_recursion_fanout_ratio                outbound queries per client query
dns_resolution_shed_total                 resolutions abandoned
```

In shadow mode, `dns_recursion_firewall_exhaustions_total` is exactly the set of
requests `enforce` would have failed. If it is nonzero for ordinary traffic, the
limit is too low for your workload, raise it before enforcing, not after.
