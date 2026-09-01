---
layout: doc
title: Installation
category: Getting Started
order: 1
description: Packages, containers and building from source.
---

## Pre-built binaries

Every release publishes archives for Linux, macOS, FreeBSD and Windows on
amd64, arm64 and armv5/6/7, plus `.deb` and `.rpm` packages.

Asset names carry the version, so there is no version-less `latest/download/`
URL to fetch. Resolve the tag first:

```bash
TAG=$(curl -fsSL https://api.github.com/repos/semihalev/sdns/releases/latest \
        | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
curl -fsSL -o sdns.tar.gz \
  "https://github.com/semihalev/sdns/releases/download/${TAG}/sdns-${TAG#v}_linux_amd64.tar.gz"
tar xzf sdns.tar.gz
./sdns-${TAG#v}_linux_amd64/sdns version
```

Replace `linux_amd64` with the platform you want — the
[releases](https://github.com/semihalev/sdns/releases/latest) page lists every
asset, and pinning a specific tag rather than resolving `latest` is the right
call in a deployment script.

## Docker

```bash
# sdns.conf must set directory = "/var/lib/sdns" and narrow accesslist —
# see below for why each half of this command matters.
docker run -d --name sdns \
  -p 127.0.0.1:53:53 -p 127.0.0.1:53:53/udp \
  -v sdns-data:/var/lib/sdns \
  -v "$PWD/sdns.conf:/etc/sdns.conf:ro" \
  ghcr.io/semihalev/sdns:1.8.2 -c /etc/sdns.conf
```

Three parts of that are not decoration.

**`127.0.0.1:` on both publishes.** A bare `-p 53:53` binds every interface on
the host. The shipped `accesslist` allows every client, so on a machine with a
public address that is an open recursive resolver, and open resolvers are found
and used for reflection attacks within hours. Publish to loopback until
`accesslist` says who may query.

**A configuration file, mounted, and named with `-c`.** Without one the
container writes a default config and uses it.

**`directory = "/var/lib/sdns"` inside that file.** The image is built
`FROM scratch` with no `WORKDIR`, so the process runs in `/` and the default
relative `directory = "db"` resolves to `/db` — not the volume. The trust
anchor state then lives in the container's writable layer and is lost on the
next `docker rm`, which is exactly the failure the volume was meant to prevent
and which only surfaces at a root KSK rollover.

The volume is not optional: it holds the RFC 5011 trust-anchor state, and a
container without it only reveals the problem at a root KSK rollover. A compose
file and the rest of the container story are on the
[Containers]({{ '/docs/deployment/docker/' | relative_url }}) page.

## Package managers

```bash
brew install semihalev/tap/sdns   # macOS, tracks releases
snap install sdns                 # Linux
yay -S sdns-git                   # Arch (AUR)
```

## From source

Go 1.26 or newer is required; the toolchain pinned in `go.mod` is 1.27.

```bash
git clone https://github.com/semihalev/sdns
cd sdns
make all        # generate, tidy, test, build
./sdns version
```

`make all` runs the test suite before it builds; use `go build` directly if you
only want the binary.

## Verifying the install

Port 53 needs privilege, and the shipped access list allows every client — so
verify on a loopback high port instead of running this as root:

```bash
printf 'bind = "127.0.0.1:5353"\napi = ""\naccesslist = ["127.0.0.1/32"]\n' > check.conf
./sdns -c check.conf &
dig @127.0.0.1 -p 5353 example.com A +dnssec
```

The keys not named there are filled in from the defaults, so this is a real
resolver — just one only you can reach.

An answer with the `ad` flag means the response was validated. If the first
query is slow, that is the resolver priming the root and fetching the trust
anchor — subsequent queries are served from cache.
