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
dropped without a reply before any resolution work happens: the access list
runs near the front of the middleware chain, ahead of the cache and the
resolver.

The shipped default is `["0.0.0.0/0", "::0/0"]`, which allows everyone, and so
does an empty list or a file that leaves the key out. That is right for a
resolver on loopback and wrong for one on a public address. An open recursive
resolver on the internet will be found and used for reflection attacks, so
narrow this before you bind to a reachable address.

Watch `dns_accesslist_denied_total` to see whether anything is being dropped.

## Rate limits

```toml
ratelimit       = 0     # cache hits per second, per answer bucket; 0 disables
clientratelimit = 0     # queries per minute, per client IP; 0 disables
```

Both are off by default. `clientratelimit` is the more useful of the two on a
resolver serving known clients: it contains one misbehaving host without
capping the server.

`ratelimit` is not a server-wide ceiling. It limits how often cached answers
are served. Each cached answer is mapped, by a hash of its cache key, to one of
997 shared token buckets, each refilling at `ratelimit` tokens a second with a
burst of the same size; answers that hash to the same bucket share it. Answers
cached under an ECS scope are the exception: they all share a single bucket,
so with `[ecs]` on, every scoped hit draws from the same `ratelimit` budget. A
cache hit over its bucket's rate is dropped without a reply. Cache misses, and
everything answered before the cache, are not limited by it, and these drops
are not counted in `dns_ratelimit_exceeded_total`.

`clientratelimit` keeps two buckets per client address. Queries whose source is
proved, by a TCP or QUIC handshake or by a valid DNS server cookie (RFC 7873),
draw from one; plain UDP queries without a valid cookie draw from the other. A
flood sent in a client's name from spoofed addresses therefore cannot spend
the quota of that client's real traffic. Clients behind one NAT address share
its quota. A UDP client over its quota that sent a cookie gets a BADCOOKIE
reply carrying a server cookie, at most one a second; its retry with that
cookie is served from the proved bucket. Anything else over the quota is
dropped. Loopback clients are exempt.

Each query over a client's quota, dropped or answered with a BADCOOKIE
challenge, increments `dns_ratelimit_exceeded_total`.

### Cookie secret

```toml
cookiesecret = ""
```

The server cookies above are RFC 9018 cookies, a SipHash over the client
cookie, a timestamp and the client's address, keyed by `cookiesecret`. The key
is not in the generated file. Exactly 32 hex digits are used as the key itself.
Any other text is hashed into a key, the same text always to the same key.
Left empty, sdns generates 16 random bytes at startup, so the cookies it hands
out change on every restart and clients relearn them.

Members of an anycast set must share one fixed value, so a cookie one member
issued is valid at the others. Between sdns servers any identical string will
do. When other DNS software takes part in the set, use 32 hex digits, since
that is the key form RFC 9018 servers have in common.

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
traffic. `reflexblockmode = false` also only logs, but at debug level, so at
`loglevel = "info"` its detections do not appear in the log. Turn on blocking
after you have watched the detections for a while and are satisfied they are
not your own clients. The threshold is a score between 0 and 1, and lower is
more aggressive.

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

`blocklists` are URLs downloaded once at startup, into the `blacklists`
directory under `directory`; there is no periodic refresh, so restart sdns to
fetch newer copies. `blocklist` is a manual list in the configuration file;
`whitelist` wins over both. It exempts names from this blocklist only: RPZ
policy still applies to a whitelisted name. A blocked A query answers
`nullroute` and a blocked AAAA answers `nullroutev6`.

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
hostsfilechecknames = true
hostsfilezones = ["home.arpa."]
```

Serves entries from a hosts file directly. Empty `hostsfile` disables it.
`hostsfilechecknames` and `hostsfilezones` are independent filters: the
first checks each name; the second limits names to configured DNS zones.
Setting `hostsfilechecknames = true` alone checks names without limiting their
zones. An empty zone list disables zone filtering. With both options omitted
or at their defaults, hosts-file importing keeps its existing behavior.

When name checking is enabled, SDNS accepts ASCII RFC 952/1123-style
hostname labels containing letters, digits, and hyphens. Each label must begin
and end with a letter or digit, and may contain hyphens between them. Labels
are limited to 63 octets and names to 255 octets on the DNS wire. A trailing
dot is optional. A leading `*.` is allowed for a wildcard entry. An invalid
name is skipped with a warning that identifies its file and line; it contributes no
forward answer or PTR record. For a line with aliases, each name is considered
individually. The first accepted normal name is promoted to the row's primary
name for CNAME and PTR processing. Equivalent names in one row are imported once
when either filter is enabled; addresses from separate rows still aggregate.
A surviving wildcard keeps the existing wildcard-row precedence and does not
create a PTR record.

`hostsfilezones` entries are DNS zones. Matching is label-aware and
case-insensitive: a zone matches its apex and subdomains, so `corp.example`
matches `printer.corp.example` but not `notcorp.example`. Root `.` and
names with or without a trailing dot are accepted. A name outside every
configured zone continues through normal resolution.

A name the file lists with addresses of one family only gets NODATA for the
other family; the query is not sent upstream. For answers scoped to particular
client networks rather than served to everyone, use
[views]({{ '/docs/features/views/' | relative_url }}).

## Per-domain metrics

```toml
domainmetrics      = false
domainmetricslimit = 1000
```

Tracks query counts per domain, exported as `dns_domain_queries_total`. Off by
default because the cardinality is unbounded on a public resolver; that is
what the limit is for. `0`, or leaving the key out, means unlimited, which on a
busy resolver will consume memory until something gives.

## Suppress AAAA answers

```toml
block_aaaa = false
```

Off by default, including when omitted. Set it to `true` to answer normal
single-question IN/AAAA client queries with NOERROR and empty Answer and
Authority sections (NODATA). It applies to IPv4 and IPv6 clients on every DNS
transport, including queries with RD=0 or CD=1. Other types and classes keep
their usual behavior.

Use this setting for intentionally IPv4-only downstream networks. Suppressing
AAAA makes IPv6-only destinations unreachable to those clients. IPv6 listeners,
outbound IPv6 connectivity and internal lookups of nameserver and resolver
addresses are unaffected. The setting
does not remove IPv6 addresses in other record types, including HTTPS/SVCB
address hints, or prevent a client from using an IPv6 address it already knows.

Suppression runs after access controls, EDNS and DDR, ahead of hosts files,
views, blocklists, RPZ, cache and DNS64. Their AAAA answers and synthesis are
therefore bypassed even when cached. The `resolver.arpa` zone remains under
DDR control. Enabling DNS64 alongside `block_aaaa` is accepted; suppression
wins for client AAAA queries.

These replies describe local policy, not authenticated denial from the
authoritative zone: AA and AD are clear, RA is set, and the client's RD and CD
are preserved. No SOA or DNSSEC denial proof is supplied, so there is no
SOA-based negative-cache lifetime; validating clients may reject the
unsigned answer. EDNS clients receive EDE 0 (Other), with text
“AAAA response suppressed by policy”; clients without EDNS receive no OPT.
The `dns_aaaa_blocked_total` counter counts successfully written policy replies.
