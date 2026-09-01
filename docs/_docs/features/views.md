---
layout: doc
title: Views and forwarding
category: Features
order: 5
description: Answers scoped to client networks, per-zone upstreams, and whole-server forwarder mode.
---

## Views

A view serves particular answers to particular client networks. Everything a
view does not match falls through to normal resolution.

```toml
[[views]]
zone     = "lannet"
networks = ["192.168.1.0/24"]
answers  = [
    "*.example.lan. 60 IN A 192.168.1.3",
    "*.example.lan. 60 IN AAAA fd00::3",
]

[[views]]
zone     = "vpnnet"
networks = ["100.64.0.0/24"]
answers  = ["*.example.lan. 60 IN A 100.64.0.2"]
```

Answers are zone-file lines. Wildcards work, and an exact owner overrides a
covering wildcard. Views are evaluated in declaration order, and they run early
in the chain, ahead of the blocklist, RPZ and the cache, so a view answer is
not subject to policy or caching.

The example above is the common case: one internal name that must resolve to
different addresses depending on which network the client is on.

## Per-zone forwarding

Sends one zone's queries to its own upstreams while everything else still
resolves recursively.

```toml
[[forward_zone]]
name    = "corp.example."
servers = ["10.0.0.53:53", "tls://10.0.0.54:853"]
```

The most specific matching zone wins. A zone must name itself and at least one
server or startup fails, an omitted name would forward every query. A zone
whose upstreams all turn out unusable fails its own queries rather than falling
back to `forwarderservers`, because sending an internal zone's questions to a
public resolver is worse than failing them.

Servers take the same forms as `forwarderservers`, so DoT and DoH work per zone.

### This is forwarding, not delegation

The query goes out with RD=1 to a resolver that answers on your behalf, in the
RFC 8499 sense. The upstreams must be **recursive resolvers**, not the zone's
authoritative servers.

### A forwarded zone is not validated here

Answers carry whatever the upstream asserted, exactly as in whole-server
forwarder mode. Pointing a signed public zone at an upstream gives up local
DNSSEC validation for it. The intended use is the opposite case: an internal
zone the public namespace cannot resolve at all.

## Whole-server forwarder mode

```toml
forwarderservers = [
    "8.8.8.8:53",
    "tls://8.8.8.8:853",
    "https://cloudflare-dns.com/dns-query",
]
```

With this set, sdns stops resolving from the root and forwards everything.
Plain DNS, DoT (`tls://`) and DoH (`https://`, RFC 8484) are all accepted.

DoH URLs may use an IP literal or a hostname. A hostname is resolved once at
startup through the system resolver and the resulting addresses are pinned for
the life of the process, so there is no per-query DNS dependency and no
bootstrap loop.

Note what this costs: forwarding means trusting the upstream's answers rather
than validating them yourself, and it means no learned delegation cuts, which
in turn weakens the bound on
[serve-stale]({{ '/docs/features/serve-stale/' | relative_url }}).

## Fallback servers

```toml
fallbackservers = ["8.8.8.8:53"]
```

Used when normal resolution has returned SERVFAIL for any reason (a lame
delegation, an unreachable upstream, a network fault), not only when the root
is unreachable.
Unlike `forwarderservers` this does not change the normal mode of operation.

Three limits worth knowing. Fallback servers are queried over plain UDP with a
hard five-second ceiling per endpoint. Their answers are cached like any other.
And, the one that matters most, a fallback answer is **not** validated here:
it is written as the upstream asserted it, so configuring `fallbackservers`
means a resolution that failed locally can be answered by an upstream you are
trusting rather than checking. Note also that a per-zone forward that fails writes SERVFAIL, which is
itself a fallback trigger, so with `fallbackservers` set, an internal zone's
questions can reach them.
