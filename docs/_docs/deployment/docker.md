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
  ghcr.io/semihalev/sdns:latest -c /etc/sdns.conf
```

## Persist the state directory

`directory` in the configuration must point at a volume. It holds the RFC 5011
trust anchor database, cached blocklists and the local root copy. Without a
volume, every restart re-fetches all of it and — more importantly — throws away
the trust anchor state that tracks root KSK rollovers.

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
    image: ghcr.io/semihalev/sdns:latest
    container_name: sdns
    restart: unless-stopped
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
you publish it more widely, set `accesslist` first — see
[Access control]({{ '/docs/configuration/access-control/' | relative_url }}).

## Ports the image declares

```
53/tcp  53/udp   plain DNS
853              DoT and DoQ
8053             DoH
8080             HTTP API and metrics
```

Publish only what you actually serve. In particular, the API listener should
stay on loopback or behind a token.

## Validating the config

The image has no shell, but it does have the binary:

```bash
docker run --rm -v ./sdns.conf:/etc/sdns.conf:ro \
  ghcr.io/semihalev/sdns:latest -t -c /etc/sdns.conf
```

Exit code 0 means the file is good.

## Memory-constrained hosts

On a router or a small VPS, consider:

```toml
memorytrim = true
```

It returns a traffic burst's memory to the operating system after several idle
minutes, at the cost of one synchronous garbage collection over the whole
process. That is the right trade on a 256 MB device and the wrong one on a busy
server.
