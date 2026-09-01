---
layout: doc
title: Resolution and DNSSEC
category: Configuration
order: 3
description: Root servers, validation, QNAME minimisation, timeouts and work limits.
---

## Root servers

```toml
rootservers  = ["198.41.0.4:53", "170.247.170.2:53", ...]
root6servers = ["[2001:503:ba3e::2:30]:53", ...]
```

The generated file ships the full published list for both families. You would
only edit these to point at a private root, or to point at a private root
deployment.

You do not need to remove the IPv6 list on a host without IPv6 transit: sdns
probes for transit at startup and leaves the IPv6 roots out of the rotation when
the probe fails. `ipv6access = true` overrides the probe when it misjudges the
network.

If you want the root served locally instead of queried, see
[Local root zone]({{ '/docs/features/hyperlocal-root/' | relative_url }}).

## DNSSEC validation

```toml
dnssec   = "on"     # "on" or "off"
rootkeys = [ ... ]  # root trust anchors
rfc8198  = true
rfc9520  = true
```

`dnssec = "on"` validates every signed zone and refuses to serve data that fails
validation. `rootkeys` holds the root trust anchors in DNSKEY presentation
format; the generated file ships the published KSKs, and sdns tracks anchor
rollovers on its own (RFC 5011) once running.

`rfc8198` lets a validated NSEC/NSEC3 record answer later negative queries
without another authoritative lookup. `rfc9520` caches resolution failures and
failed-authority state. Both default to on and both are kill switches rather
than tuning knobs — turning either off costs upstream traffic and, in the case
of `rfc9520`, standards conformance. Exact negative caching and RFC 8020
NXDOMAIN subtree cuts stay active regardless.

If a trust anchor file is ever corrupted, the authoritative source for the root
KSKs is [data.iana.org/root-anchors](https://data.iana.org/root-anchors/).

## QNAME minimisation

```toml
qname_max_minimize_count = 10
qname_minimize_one_label = 4
```

sdns sends upstream servers only the labels the current delegation already
justifies, rather than the whole query name (RFC 9156). Past the budget the
full name goes out, so every delegation below that point sees all of it.

`qname_max_minimize_count` is how many minimised queries one lookup may spend;
`0` disables minimisation, and the RFC recommends 10. `qname_minimize_one_label`
is how many of those add a single label before the remaining labels are grouped
over the queries left; `0` selects the RFC's suggested 4. The shipped 10/4 is
the RFC's own recommendation.

The older `qname_min_level`, which counted delegation depth rather than queries,
is still read when `qname_max_minimize_count` is unset.

## Timeouts and depth

```toml
timeout      = "2s"      # per upstream query
querytimeout = "10s"     # for the whole client query
maxdepth     = 30        # recursion depth ceiling
```

`timeout` bounds one exchange with one upstream server. `querytimeout` bounds
everything sdns will do for a single client question, retries and nested
lookups included. `maxdepth` stops resolution loops.

For bounds on aggregate *work* rather than time — outbound attempts, internal
queries, DNSSEC operations — see the
[recursion firewall]({{ '/docs/features/recursion-firewall/' | relative_url }}),
which is the mechanism designed for that and which also owns the RFC 9520
failure cache.

## TCP connection pooling

```toml
tcpkeepalive      = false
roottcptimeout    = "5s"
tldtcptimeout     = "10s"
tcpmaxconnections = 100
```

Keeps TCP connections to root and TLD servers alive between queries. Off by
default. It helps when a large share of upstream traffic is truncated into TCP;
it costs sockets otherwise. `tcpmaxconnections = 0` uses the built-in 100.

## AS112 empty zones

```toml
emptyzones = []
```

Answers queries for the private-address reverse zones locally instead of
leaking them to the root (RFC 6303). An empty list uses the built-in set, which
is what you want; list zones explicitly only to narrow it.

RFC 6303 is the citation that applies to a resolver: it defines the zone list
and says the resolver should answer them itself. The often-quoted RFC 7534 is a
different document — it describes how to *run* an AS112 node, the sink that
catches these queries when a resolver does not answer them.
