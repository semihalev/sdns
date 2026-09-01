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

```bash
curl -fsSL -o sdns.tar.gz \
  https://github.com/semihalev/sdns/releases/latest/download/sdns-linux_amd64.tar.gz
tar xzf sdns.tar.gz
./sdns version
```

## Docker

```bash
docker run -d --name sdns \
  -p 53:53 -p 53:53/udp \
  ghcr.io/semihalev/sdns:latest
```

A compose file, and the volume layout for keeping the trust anchor and cache
state across restarts, are covered in
[Running as a service]({{ '/docs/deployment/service/' | relative_url }}).

## Package managers

```bash
brew install sdns                 # macOS
snap install sdns                 # Linux
yay -S sdns                       # Arch (AUR)
```

## From source

Go 1.24 or newer is required.

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
