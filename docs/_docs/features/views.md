---
layout: doc
title: Views and forwarding
category: Features
order: 5
description: Answers scoped to client networks, per-zone upstreams, and whole-server forwarder mode.
---

## Views

A view serves answers to particular client networks. Overlay mode selects a
matching name and type; authoritative-owner mode selects an exact IN owner
first, otherwise the closest matching wildcard owner, before checking type.
Missing types resolve normally in overlay mode and are answered locally at
selected owners in authoritative-owner mode. Unmatched names resolve normally.

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

Answers are zone-file lines. The first view, in declaration order, whose
networks contain the client is the only one consulted; later views are not
tried. `zone` is a label for logs, not a zone boundary.

`mode = "overlay"` is the default, including when `mode` is omitted or empty.
It matches the requested type first: an exact owner of that type overrides a
covering wildcard, and the longest matching wildcard suffix of that type wins.
If no record of the requested type matches, the query resolves normally. For
example, a view with only A records lets AAAA questions resolve publicly.

Set `mode = "authoritative-owner"` to keep questions for configured IN owners
local even when a type is absent:

```toml
[[views]]
zone     = "internal"
mode     = "authoritative-owner"
networks = ["192.168.1.0/24", "fd00::/8"]
answers  = ["*.example.lan. 60 IN A 192.168.1.3"]
```

This mode selects an exact IN owner first, otherwise the wildcard with the
longest matching suffix, before looking at the requested type. It returns
that owner's requested RRset, or its CNAME RRset if the requested type is
absent. If neither RRset exists, it returns NOERROR/NODATA with empty answer
and authority sections. There is no SOA and no advertised negative-cache TTL.
Unknown ordinary types follow the same
rule. Non-IN questions and meta-types declined by the resolver (ANY, AXFR,
IXFR and NXNAME) continue to downstream policy. Non-IN records do not establish
an owner in this mode.

CNAME targets are not chased, even when the target is configured in the same
view. Ordinary application resolvers may therefore fail when they look up an
address for that alias. A client that follows the CNAME target itself gets
normal Views processing for the target question.

An exact owner with no A record suppresses a covering wildcard's A records.
Likewise, a closer wildcard with no TXT record suppresses a broader wildcard's
TXT records. A wildcard containing only A records also answers TXT questions
such as `_acme-challenge.example.lan.` with NODATA, preventing public ACME TXT
lookup for matching clients. Use overlay mode if those types should resolve
normally. Names with no configured owner or matching wildcard still resolve
normally in either mode.

Wildcards match names strictly below their suffix, including nested names:
`*.example.lan.` matches `deep.host.example.lan.` but excludes `example.lan.`
itself. Matching ignores case. In authoritative-owner mode, exact owners and
wildcard suffixes are compared as decoded DNS names, so escaped and plain
spellings of the same label share ownership and RRsets. An
escaped dot stays within its label: `foo\.example.lan.` is outside
`*.example.lan.`. A first label that decodes to `*` is wildcard syntax, so
`\042.example.lan.` and `\*.example.lan.` have the same meaning as
`*.example.lan.`. Wildcard specificity follows suffix label count, not
presentation-string length. This is closest-suffix selection over configured
records, not a full authoritative zone implementation: it does not infer empty
non-terminals or zone-wide ownership from descendants.

Views run early in the chain, after the hosts file and ahead of the blocklist,
RPZ and the cache, so a view answer is not subject to policy or caching. A
name the hosts file answers never reaches the views.

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
RFC 9499 sense. The upstreams must be **recursive resolvers**, not the zone's
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
    "tls://9.9.9.9:853#dns.quad9.net",
    "https://cloudflare-dns.com/dns-query",
]
```

With this set, sdns stops resolving from the root and forwards everything.
Plain DNS, DoT (`tls://`) and DoH (`https://`, RFC 8484) are all accepted.

A DoT upstream is an IP address and port, and by default its certificate must
be valid for that address. Some providers' certificates carry only their
service name. For those, add the name after `#`:
`tls://9.9.9.9:853#dns.quad9.net` connects to 9.9.9.9, sends `dns.quad9.net`
as SNI, and accepts only a certificate valid for that name. The name is never
resolved: the address says where to connect, and the name what must answer
there. This is the IP address plus authentication domain name configuration
of RFC 8310, and it works in forward zones too. A certificate that does not
match fails that upstream, and the next configured one is tried as usual;
sdns never retries it without the name.

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

Used when normal resolution of a query with RD=1 has returned SERVFAIL because
it could not get an answer (a lame delegation, an unreachable upstream, a
network fault), not only when the root is unreachable. Unlike
`forwarderservers` this does not change the normal mode of operation.

Some SERVFAILs are passed to the client unchanged, without trying a fallback:

- a query with RD=0;
- a DNSSEC validation failure, so a bogus answer is never sent to a fallback
  server to be answered unvalidated;
- a request the recursion firewall stopped in `enforce` mode;
- a request whose own time has run out;
- a query shed while it waited on the retry of an expired cached resolution
  failure (RFC 9520), since a fallback query would bypass that bound;
- a SERVFAIL answered from the RFC 9520 failure cache: the cache sits ahead of
  the fallback in the chain, so while a failure is cached, its queries get it
  without a fallback attempt.

Three limits worth knowing. Fallback servers are queried over plain UDP, and
over TCP when a reply comes back truncated, with a hard five-second ceiling per
endpoint. Their answers are cached like any other. And, the one that matters
most, a fallback answer is **not** validated here: it is written as the
upstream asserted it, so configuring `fallbackservers` means a resolution that
failed locally can be answered by an upstream you are trusting rather than
checking. Note also that a per-zone forward that fails writes SERVFAIL, which
is itself a fallback trigger, so with `fallbackservers` set, an internal zone's
questions can reach them.
