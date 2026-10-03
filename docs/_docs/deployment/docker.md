---
layout: doc
title: Containers
category: Deployment
order: 2
description: Running sdns in Docker, and the two things a container gets wrong by default.
---

The image is built `FROM scratch` and contains the static binary and a CA
bundle. There is no shell in it.

```bash
docker run -d --name sdns \
  -p 127.0.0.1:53:53 -p 127.0.0.1:53:53/udp \
  -v sdns-data:/var/lib/sdns \
  -v /etc/sdns.conf:/etc/sdns.conf:ro \
  --stop-timeout 20 \
  ghcr.io/semihalev/sdns:{{ site.sdns_version | remove_first: 'v' }} -c /etc/sdns.conf
```

Pin a release tag: the full version for an exact release, or the minor series
(such as `1.9`) for the newest patch of that line. `latest` is rebuilt from
every push to the `main` branch, so it tracks development, not releases.

`--stop-timeout 20` gives a stop room to finish. sdns waits up to
`querytimeout` (10 seconds by default) for in-flight queries to drain, and
with `cache_persist` on, saving the snapshot can add up to 5 more. Docker's
default of 10 seconds would kill it mid-save. If you raise `querytimeout`,
raise the stop timeout to at least `querytimeout` plus 5 seconds, with some
margin; the same goes for `stop_grace_period` below.

## Persist the state directory

`directory` in the configuration must point at the volume:

```toml
directory = "/var/lib/sdns"
```

It holds the RFC 5011 trust anchor database (`trust-anchor.db` and
`trust-anchor-tombstones.db`), downloaded blocklists (`blacklists/`), the
local root copy (`root.zone`, with `hyperlocal_root`) and the cache snapshot
(`cache.snapshot`, with `cache_persist`). Without a volume, every restart
re-fetches all of it and, more importantly, throws away the trust anchor state
that tracks root KSK rollovers.

This is the mistake worth avoiding: a container that resolves fine will keep
resolving fine for a long time without a volume, and the problem only surfaces
at a rollover.

## Publish both protocols

DNS needs UDP and TCP on the same port. `-p 53:53` alone publishes TCP only, and
the result is a resolver that answers the occasional truncated retry and nothing
else. Both `-p 53:53` and `-p 53:53/udp` are required.

## Compose

```yaml
services:
  sdns:
    image: ghcr.io/semihalev/sdns:{{ site.sdns_version | remove_first: 'v' }}
    container_name: sdns
    restart: unless-stopped
    stop_grace_period: 20s
    command: ["-c", "/etc/sdns.conf"]
    ports:
      - "127.0.0.1:53:53"
      - "127.0.0.1:53:53/udp"
    volumes:
      - sdns-data:/var/lib/sdns
      - ./sdns.conf:/etc/sdns.conf:ro

volumes:
  sdns-data:
```

Binding to `127.0.0.1` keeps the resolver off the host's public addresses. If
you publish it more widely, set `accesslist` first, see
[Access control]({{ '/docs/configuration/access-control/' | relative_url }}).

## Ports the image declares

```
53/tcp  53/udp   plain DNS
853/tcp          DoT
8053/tcp         DoH
8080/tcp         HTTP API and metrics
```

`EXPOSE` in the image declares TCP unless a port says otherwise, so **DoQ and
HTTP/3 have no declaration**. They are UDP. `docker run -P` will not publish
them; name them explicitly (`-p 853:853/udp`, `-p 8053:8053/udp`) if you serve
either.

The generated configuration sets `api = "127.0.0.1:8080"`. Inside a container
that is the container's own loopback, so publishing 8080 reaches nothing. To
use the API from outside, the configuration must set `api = ":8080"`, and then
it needs the protection below.

Publish only what you actually serve. The API listener in particular is plain
HTTP with no TLS, so a bearer token sent to it crosses the network in the clear
and can be replayed. Keep it unpublished, or publish it to loopback only; if it
has to be reachable, the protection is a TLS-terminating authenticating proxy,
a VPN or a source-restricted firewall, with the token as a second layer.

## Validating the config

The image has no shell, but it does have the binary:

```bash
docker run --rm -v ./sdns.conf:/etc/sdns.conf:ro \
  -v sdns-data:/var/lib/sdns \
  ghcr.io/semihalev/sdns:{{ site.sdns_version | remove_first: 'v' }} -t -c /etc/sdns.conf
```

Exit code 0 means the file is good. Mount the state volume here too: the test
checks that `directory` exists or can be created, and the image has no
`/var/lib`, so without the volume `directory = "/var/lib/sdns"` fails the
check.

## Memory-constrained hosts

On a router or a small VPS, consider:

```toml
memorytrim = true
```

It returns a traffic burst's memory to the operating system after several idle
minutes, at the cost of one synchronous garbage collection over the whole
process. That is the right trade on a 256 MB device and the wrong one on a busy
server.
