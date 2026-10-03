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
`bind` is always opened: left unset or empty, it listens on `":53"`. Leaving
`bindtls`, `binddoh` or `binddoq` unset means that listener is not started, and
the encrypted transports are all unset by default.

Every key also takes a list, to listen on some addresses but not all of them:

```toml
bind    = ["192.0.2.10:53", "[2001:db8::1]:53", "127.0.0.1:53"]
bindtls = ["192.0.2.10:853", "[2001:db8::1]:853"]
```

A listener on several addresses is still one listener: its workers, connection
limits and memory budget are shared across the addresses, not multiplied by
them. It opens every address it names or none, so an address that cannot be
opened stops startup with that address in the error, as a single address
always has. `sdns -t` refuses an address listed twice, however it is spelled,
and a wildcard (`":53"`, `"0.0.0.0:53"`, `"[::]:53"`) listed with specific
addresses, since the wildcard already covers them. A wildcard on two ports
(`[":53", ":5353"]`) is fine.

`bindtls` and `binddoq` can share port 853 because one is TCP and the other UDP.
`binddoh` is different: besides its TCP listener it opens UDP on the same
address for DNS over HTTP/3, so `binddoh` and `binddoq` cannot share a port.

### TLS material

```toml
tlscertificate = "/etc/sdns/server.crt"
tlsprivatekey  = "/etc/sdns/server.key"
```

Both are PEM files, and both are required before DoT, DoH or DoQ will start.
`sdns -t` opens them, so a path typo or a key the process cannot read is caught
before a restart rather than after it.

The certificate is reloaded without a restart: on `SIGHUP`, when either file
changes on disk, and on a recheck every five minutes in case a change was
missed. A load that fails (a broken file, or an expired certificate) is logged,
and the certificate already in use stays in service.

## Outbound source addresses

```toml
outboundips  = ["192.0.2.10", "192.0.2.11"]
outboundip6s = ["2001:db8::10"]
```

Addresses sdns sends its own queries from. With more than one, a source is
picked per request, which spreads queries across them. Leave both empty to let
the operating system choose.

These must be addresses the host actually holds. `sdns -t` refuses one that is
not an address of this machine, and sdns stops at startup if it is given one.
`outboundip6s` is used only while IPv6 access is on (`ipv6access`, or a
successful IPv6 probe at startup).

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

`chaos` answers TXT queries in the CHAOS class for these names, each in a
`.bind` and a `.server` form: `version`, `hostname.bind` and `id.server`,
`uptime`, `platform`, `fingerprint` and `stats`. The generated file sets it to
`true`; a file that leaves the key out gets `false`. It is the usual way to
confirm which build a node is running:

```bash
dig @resolver version.bind TXT CHAOS +short
```

Turn it off if you would rather not publish the version.

When sdns resolves recursively, it resolves only class IN. A CHAOS question
not answered here, any of these with `chaos` off included, gets REFUSED, and a
question in any other class gets NOTIMP with Extended DNS Error 21 (Not
Supported). In forwarder mode, and for a forwarded zone, such a question goes
to the upstream instead.

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
