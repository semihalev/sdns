---
layout: doc
title: Installation
category: Getting Started
order: 1
description: Packages, containers and building from source.
---

## Pre-built binaries

Every release publishes archives, plus `.deb` and `.rpm` packages for Linux
amd64 (x86_64) only. The archive architectures differ by platform:

| Platform | Architectures |
|---|---|
| Linux | amd64, arm64, armv5/6/7, mips, mipsle, mips64, mips64le (softfloat) |
| macOS | amd64, arm64 |
| Windows | amd64 |
| FreeBSD, OpenBSD, NetBSD | amd64 |

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

Replace `linux_amd64` with the platform you want; the
[releases](https://github.com/semihalev/sdns/releases/latest) page lists every
asset. In a deployment script, pin a specific tag rather than resolving
`latest`.

## Docker

```bash
# sdns.conf must set directory = "/var/lib/sdns" and narrow accesslist,
# see below for why each half of this command matters.
docker run -d --name sdns \
  -p 127.0.0.1:53:53 -p 127.0.0.1:53:53/udp \
  -v sdns-data:/var/lib/sdns \
  -v "$PWD/sdns.conf:/etc/sdns.conf:ro" \
  --stop-timeout 20 \
  ghcr.io/semihalev/sdns:{{ site.sdns_version | remove_first: 'v' }} -c /etc/sdns.conf
```

Each release publishes its full version and its minor series
(`{{ site.sdns_version | remove_first: 'v' | split: '.' | slice: 0, 2 | join: '.' }}`)
as image tags. `latest` is built from every push to the main branch, not from
a release, so pin a release tag.

Four parts of that are not decoration.

**`127.0.0.1:` on both publishes.** A bare `-p 53:53` binds every interface on
the host. The shipped `accesslist` allows every client, so on a machine with a
public address that is an open recursive resolver, and open resolvers are found
and used for reflection attacks within hours. Publish to loopback until
`accesslist` says who may query.

**A configuration file, mounted, and named with `-c`.** Without one the
container writes a default config and uses it.

**`directory = "/var/lib/sdns"` inside that file.** The image is built
`FROM scratch` with no `WORKDIR`, so the process runs in `/` and the default
relative `directory = "db"` resolves to `/db`, not the volume. The RFC 5011
trust anchor state then lives in the container's writable layer and is lost on
the next `docker rm`, which is exactly the failure the volume is there to
prevent, and which only surfaces at a root KSK rollover.

**`--stop-timeout 20`.** A stop waits at most 10 seconds for in-flight queries
to drain, whatever `querytimeout` is, and with `cache_persist` on, saving the
snapshot can take up to 5 seconds more. Docker's default of 10 seconds would
kill it mid-save.

A compose file and the rest of the container story are on the
[Containers]({{ '/docs/deployment/docker/' | relative_url }}) page.

## Package managers

```bash
brew install sdns         # macOS, or Linux with Homebrew
sudo snap install sdns    # Linux
yay -S sdns-git           # Arch (AUR), built from the latest commit
```

The Homebrew formula is in homebrew-core and follows each release.
`sudo brew services start sdns` runs it as root with
`$(brew --prefix)/etc/sdns.conf`, generated on the first start. The service
runs from the installed version's own directory, so the generated relative
`directory = "db"` would put the trust anchor state inside it, where the next
upgrade discards it. Set `directory` to an absolute path outside it, such as
`/opt/homebrew/var/sdns` (`/usr/local/var/sdns` on Intel Macs), and restart.
The log is `$(brew --prefix)/var/log/sdns.log`.

The snap's stable channel is published with every release. The snap runs
sdns as a service with `/var/snap/sdns/current/sdns.conf`, the standard
generated file with `directory` set to `/var/snap/sdns/common/db`, which every
snap revision shares, so a refresh keeps the state. Edit the file, check it
with `sudo sdns.sdns-cli -t`, and apply it with `sudo snap restart sdns`. A
configuration written by an older snap, in the legacy `[server]` layout, is
moved aside to `sdns.conf.legacy` and a fresh one is generated; carry your
settings across by hand.

## From source

Go 1.27 or newer is required.

```bash
git clone https://github.com/semihalev/sdns
cd sdns
make all        # generate, tidy, test, build
./sdns version
```

`make all` runs the test suite before it builds; use `go build` directly if you
only want the binary.

## Verifying the install

Port 53 needs privilege and the shipped access list allows every client, so
verify on a loopback high port rather than as root.

A partial file will not do: many settings you leave out are **not** filled in
from the defaults, and a file without `directory`, `rootservers` and
`rootkeys` is rejected. Generate a complete one first. Pointing `-t` at a path
that does not exist writes the full documented file and validates it:

```bash
./sdns -t -c check.conf
```

Then change three keys in `check.conf`:

```toml
bind       = "127.0.0.1:5354"     # 5353 is mDNS; pick something else
api        = ""
accesslist = ["127.0.0.1/32"]
```

Check it again, start it, and ask it what it is:

```bash
./sdns -t -c check.conf
./sdns -c check.conf &
dig @127.0.0.1 -p 5354 version.bind TXT CHAOS +short
```

`"SDNS {{ site.sdns_version }}"` means it is up. A real query works too:

```bash
dig @127.0.0.1 -p 5354 example.com A +dnssec
```

An answer with the `ad` flag means the response was validated. The first query
is slow while the resolver primes the root and fetches the trust anchor;
subsequent queries are served from cache.
