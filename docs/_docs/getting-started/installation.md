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
docker run -d --name sdns \
  -p 53:53 -p 53:53/udp \
  -v sdns-data:/var/lib/sdns \
  ghcr.io/semihalev/sdns:1.8.2
```

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

Start it with the generated configuration and ask it something:

```bash
./sdns -c sdns.conf &
dig @127.0.0.1 example.com A +dnssec
```

An answer with the `ad` flag means the response was validated. If the first
query is slow, that is the resolver priming the root and fetching the trust
anchor — subsequent queries are served from cache.
