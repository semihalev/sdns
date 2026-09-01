<p align="center">
  <img src="https://github.com/semihalev/sdns/blob/main/logo.png?raw=true" width="200">
</p>

<h1 align="center">SDNS</h1>

<p align="center">
  A recursive DNS resolver with DNSSEC validation, written in Go.
</p>

<p align="center">
  <a href="https://github.com/semihalev/sdns/actions"><img src="https://img.shields.io/github/actions/workflow/status/semihalev/sdns/ci.yml?style=flat-square"></a>
  <a href="https://goreportcard.com/report/github.com/semihalev/sdns"><img src="https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square"></a>
  <a href="http://godoc.org/github.com/semihalev/sdns"><img src="https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square"></a>
  <a href="https://codecov.io/gh/semihalev/sdns"><img src="https://img.shields.io/codecov/c/github/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/releases"><img src="https://img.shields.io/github/v/release/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/blob/main/LICENSE"><img src="https://img.shields.io/github/license/semihalev/sdns?style=flat-square"></a>
</p>

<p align="center">
  <b><a href="https://sdns.dev/docs/">Documentation</a></b> ·
  <a href="https://sdns.dev/docs/getting-started/installation/">Install</a> ·
  <a href="https://sdns.dev/docs/configuration/overview/">Configuration</a> ·
  <a href="BENCHMARKS.md">Benchmarks</a>
</p>

***

SDNS resolves from the root, validates answers against the DNSSEC trust
anchors, and caches them. It serves DNS over TLS, HTTPS and QUIC alongside
plain UDP and TCP, and answers warm cache hits from the bytes it already holds.

Full documentation lives at **[sdns.dev](https://sdns.dev/docs/)** — this file
covers installing it and getting a first answer out of it.

## Install

```shell
go install github.com/semihalev/sdns@latest
```

Pre-built binaries for Linux, macOS, FreeBSD and Windows on amd64, arm64 and
armv5/6/7 — plus `.deb` and `.rpm` packages — are on the
[releases](https://github.com/semihalev/sdns/releases/latest) page.

```shell
# Docker — publish both protocols, and persist the state directory
docker run -d --name sdns \
  -p 53:53 -p 53:53/udp -v sdns-data:/var/lib/sdns \
  ghcr.io/semihalev/sdns:latest

# macOS
brew install semihalev/tap/sdns && brew services start sdns

# Linux
snap install sdns

# Arch
yay -S sdns-git
```

Images are published to
[ghcr.io/semihalev/sdns](https://github.com/semihalev/sdns/pkgs/container/sdns)
and [c1982/sdns](https://hub.docker.com/r/c1982/sdns) on every tagged release.
Pin a version in production.

## Quick start

```shell
# Starting without a config writes one, documented in place, and uses it.
sdns

# Check a config the way the server will read it, before restarting.
sdns -t -c /etc/sdns.conf

# Ask it something.
dig @127.0.0.1 example.com A +dnssec
```

An answer with the `ad` flag was validated. The first query is slow while the
resolver primes the root and fetches the trust anchor; after that it is served
from cache.

See [Your first configuration](https://sdns.dev/docs/getting-started/first-config/)
for the handful of settings worth changing straight away — in particular
`accesslist`, which allows everyone by default.

## What it does

**Resolution.** Recursive from the root with DNSSEC validation, QNAME
minimisation (RFC 9156), aggressive NSEC use (RFC 8198), NXDOMAIN subtree cuts
(RFC 8020), failure caching (RFC 9520), and Extended DNS Errors (RFC 8914).
Optionally the root zone served from a ZONEMD-verified local copy (RFC 8806),
or expired answers as a last resort when resolution fails (RFC 8767).

**Transports.** UDP, TCP, DoT (RFC 7858), DoH with HTTP/3 (RFC 8484), DoQ
(RFC 9250). Warm wire-eligible cache hits are served allocation-free, with
batched `recvmmsg`/`sendmmsg` on Linux.

**Policy.** Response Policy Zones with name, client-address and answer-address
triggers, file and TSIG-signed AXFR feeds, and a shadow mode whose counters
predict what enforcement would do. Blocklists, per-client views, access lists,
rate limits, and reflection-attack detection.

**Other namespaces.** Per-zone conditional forwarding, whole-server forwarder
mode, Kubernetes cluster DNS, DNS64 synthesis (RFC 6147), EDNS Client Subnet
(RFC 7871), AS112 empty zones (RFC 7534).

**Operations.** Prometheus metrics, an HTTP API, dnstap, a recursion firewall
that bounds the work one request may cause, serving bounds derived from the
machine at startup, and a validation gate that reports every configuration
problem at once.

The [documentation](https://sdns.dev/docs/) covers each of these, including
what they cost and what they deliberately do not do.

## Performance

Throughput measurements, the methodology, resolver comparisons and their
caveats are in [BENCHMARKS.md](BENCHMARKS.md).

## Development

```shell
make all     # generate, tidy, test, build
make test    # tests only
go build     # binary only
```

Conventions a patch is expected to follow — plain `testing` idioms with no
assertion library, no live-network tests, `gofmt` and `golangci-lint` clean —
are on the [building and testing](https://sdns.dev/docs/development/building/)
page. The middleware interface and the plugin contract are documented
[there too](https://sdns.dev/docs/development/middleware/).

## Contributing

Pull requests are welcome. For significant changes, please open an issue first
so the approach can be discussed.

Please review [CONTRIBUTING.md](https://github.com/semihalev/sdns/blob/main/CONTRIBUTING.md)
before submitting patches.

## Made with

*   [miekg/dns](https://github.com/miekg/dns)

## Inspired by

*   [looterz/grimd](https://github.com/looterz/grimd)

## License

[MIT](https://github.com/semihalev/sdns/blob/main/LICENSE)
