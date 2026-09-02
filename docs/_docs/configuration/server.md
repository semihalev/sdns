---
layout: doc
title: Server and listeners
category: Configuration
order: 2
description: Bind addresses, encrypted transports, outbound source IPs, the API and logging.
---

## Listeners

```toml
bind    = ":53"       # UDP and TCP
bindtls = ":853"      # DNS over TLS
binddoh = ":443"      # DNS over HTTPS
binddoq = ":853"      # DNS over QUIC
```

`bind` opens both UDP and TCP. A bare `":53"` means every address on both
families; give an address to narrow it (`"192.0.2.10:53"`, `"[2001:db8::1]:53"`).
Leaving a key unset means that listener is not started, the encrypted
transports are all unset by default.

`bindtls` and `binddoq` can share port 853 because one is TCP and the other UDP.

### TLS material

```toml
tlscertificate = "/etc/sdns/server.crt"
tlsprivatekey  = "/etc/sdns/server.key"
```

Both are PEM files, and both are required before DoT, DoH or DoQ will start.
`sdns -t` opens them, so a path typo or a key the process cannot read is caught
before a restart rather than after it.

## Outbound source addresses

```toml
outboundips  = ["192.0.2.10", "192.0.2.11"]
outboundip6s = ["2001:db8::10"]
```

Addresses sdns sends its own queries from. With more than one, a source is
picked per request, which spreads queries across them. Leave both empty to let
the operating system choose.

These must be addresses the host actually holds. A source address that is not
local fails at bind time when the query goes out, not at startup.

## HTTP API

```toml
api         = "127.0.0.1:8080"
bearertoken = ""
```

Serves `/metrics` in Prometheus format plus the blocklist and cache-purge
endpoints. Set `api = ""` to disable it entirely.

`bearertoken`, when set, requires `Authorization: Bearer <token>` on the
blocklist, purge and metrics routes.

It is not sufficient protection on its own. This listener is plain HTTP with no
TLS, so a token sent to a reachable address crosses the network in the clear.
And with `SDNS_PPROF=true` the `/debug/pprof` routes skip the token check
entirely, because pprof tooling sends no `Authorization` header.

Keep it on loopback. If it must be reachable, put it behind a TLS-terminating
authenticating proxy, a VPN, or a source-restricted firewall, and treat the
token as a second layer rather than the first. See
[Monitoring]({{ '/docs/deployment/monitoring/' | relative_url }}) for what the
endpoints do.

## Logging

```toml
loglevel  = "info"     # error, warn, info, debug
accesslog = ""         # path; empty disables
```

`accesslog` writes one line per query in Common Log Format. It is off by
default because on a busy resolver it is the largest thing the process writes.

For structured, machine-readable query logging, use dnstap instead:

```toml
dnstapsocket        = "/var/run/sdns/dnstap.sock"
dnstapidentity      = "sdns"
dnstapversion       = "1.0"
dnstaplogqueries    = true
dnstaplogresponses  = true
dnstapflushinterval = 5
```

## Identification

```toml
nsid  = ""      # RFC 5001; empty disables
chaos = true
```

`nsid` returns a server identifier in an EDNS option, which is how you tell
which member of an anycast set answered you.

`chaos` answers `version.bind`, `version.server`, `hostname.bind` and
`id.server` in the CHAOS class. It is on by default and is the usual way to
confirm which build a node is running:

```bash
dig @resolver version.bind TXT CHAOS +short
```

Turn it off if you would rather not publish the version.

## Server resources

The worker pool, the in-flight query cap and the TCP/DoT connection cap are
derived at startup from the machine's memory, CPU count and file-descriptor
limit, and each is logged as its listener starts. The overrides exist, but
leave them unset unless a measurement on your own hardware says otherwise:

```toml
# ingressworkers  = 256    # handler workers per listener
# ingressqueue    = 64     # ready-queue depth before a query gets its own goroutine
# ingresstcpconns = 1024   # concurrent inbound TCP/DoT connections
# memorytrim      = true   # return burst memory to the OS after a long idle
```

`memorytrim` runs one synchronous garbage collection over the whole process
after several quiet minutes. It is meant for memory-constrained devices,
containers on routers, small VPSes, where returning a traffic burst's memory
matters more than the pause. On a busy server it is the wrong trade.
