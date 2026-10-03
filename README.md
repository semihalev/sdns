<p align="center">
  <img src="logo.svg" alt="sdns" width="120">
</p>

<h1 align="center">SDNS</h1>

<p align="center">
  A recursive DNS resolver with DNSSEC validation, written in Go.
</p>

<p align="center">
  <a href="https://github.com/semihalev/sdns/actions"><img src="https://img.shields.io/github/actions/workflow/status/semihalev/sdns/ci.yml?style=flat-square"></a>
  <a href="https://pkg.go.dev/github.com/semihalev/sdns"><img src="https://img.shields.io/badge/pkg.go.dev-reference-blue.svg?style=flat-square"></a>
  <a href="https://codecov.io/gh/semihalev/sdns"><img src="https://img.shields.io/codecov/c/github/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/releases"><img src="https://img.shields.io/github/v/release/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/blob/main/LICENSE"><img src="https://img.shields.io/github/license/semihalev/sdns?style=flat-square"></a>
</p>

<p align="center">
  <b><a href="https://sdns.dev/docs/">Documentation</a></b> ·
  <a href="https://sdns.dev/docs/getting-started/installation/">Install</a> ·
  <a href="https://sdns.dev/docs/configuration/overview/">Configuration</a> ·
  <a href="https://sdns.dev/docs/reference/benchmarks/">Benchmarks</a>
</p>

***

SDNS resolves from the root, validates answers against the DNSSEC trust
anchors, and caches them. It serves DNS over TLS, HTTPS and QUIC alongside
plain UDP and TCP, and answers warm cache hits from the bytes it already holds.

Full documentation lives at **[sdns.dev](https://sdns.dev/docs/)**. This file
covers installing it and getting a first answer out of it.

## Install

```shell
go install github.com/semihalev/sdns@latest   # needs Go 1.27 or newer
```

Pre-built binaries for Linux, macOS, Windows and the BSDs, plus `.deb` and
`.rpm` packages for Linux amd64 (x86_64), are on the
[releases](https://github.com/semihalev/sdns/releases/latest) page. The full
architecture matrix is in the
[installation guide](https://sdns.dev/docs/getting-started/installation/).

```shell
# Docker. Loopback because the default access list allows every client; -c and
# directory = "/var/lib/sdns" in the file because the image has no WORKDIR, so
# a relative state directory resolves to /db and misses the volume entirely.
# --stop-timeout covers the shutdown drain plus the cache snapshot save.
docker run -d --name sdns \
  -p 127.0.0.1:53:53 -p 127.0.0.1:53:53/udp \
  -v sdns-data:/var/lib/sdns -v "$PWD/sdns.conf:/etc/sdns.conf:ro" \
  --stop-timeout 20 \
  ghcr.io/semihalev/sdns:1.9 -c /etc/sdns.conf

# macOS, or Linux with Homebrew
brew install sdns && sudo brew services start sdns

# Linux
sudo snap install sdns

# Arch, built from the latest commit rather than a release
yay -S sdns-git
```

Images are published to
[ghcr.io/semihalev/sdns](https://github.com/semihalev/sdns/pkgs/container/sdns)
and [c1982/sdns](https://hub.docker.com/r/c1982/sdns). Every tagged release
publishes its full version (such as `1.9.0`) and its minor series (such as
`1.9`). `latest` is built from every push to the main branch, not from a
release, so pin a release tag in production. The
[installation page](https://sdns.dev/docs/getting-started/installation/) names
the current one.

## Quick start

The generated configuration listens on port 53 on every interface and lets
every client query, so try it on a loopback high port first.

```shell
# A path that does not exist yet gets the full documented file, then -t
# checks it the way the server will read it.
sdns -t -c sdns.conf

# Edit sdns.conf: bind = "127.0.0.1:5354", accesslist = ["127.0.0.1/32"].
sdns -t -c sdns.conf
sdns -c sdns.conf &

# Ask it something.
dig @127.0.0.1 -p 5354 example.com A +dnssec
```

An answer with the `ad` flag was validated. The first query is slow while the
resolver primes the root and fetches the trust anchor; after that it is served
from cache.

See [Your first configuration](https://sdns.dev/docs/getting-started/first-config/)
for the handful of settings worth changing before it serves a network, in
particular `accesslist`.

## What it does

**Resolution.** Recursive from the root with DNSSEC validation, QNAME
minimisation (RFC 9156), aggressive NSEC use (RFC 8198), NXDOMAIN subtree cuts
(RFC 8020), failure caching (RFC 9520), and Extended DNS Errors (RFC 8914).
Delegations and nameserver addresses still in use are renewed in the last
tenth of their lease, so the cache does not fall off a cliff when a busy
zone's delegation expires. Optionally the root zone served from a
ZONEMD-verified local copy (RFC 8806), or expired answers (RFC 8767), either
when resolution fails or, with `serve_stale_mode = "immediate"`, at once while
a background refresh runs.

**Post-quantum.** DNSSEC validation of ML-DSA-44 signatures (algorithm 18).
Every TLS transport, served and upstream, offers the X25519MLKEM768 hybrid key
exchange that Go's TLS stack enables by default; sdns does not restrict the
curve list.

**Transports.** UDP, TCP, DoT (RFC 7858), DoH with HTTP/3 (RFC 8484), DoQ
(RFC 9250). Each listener takes one address or a list. Discovery of Designated
Resolvers (RFC 9462) under `[ddr]` lets plain DNS clients find the encrypted
listeners. DoT upstreams can be authenticated by name, `tls://ip:port#name`
(RFC 8310). DNS cookies (RFC 7873, RFC 9018), with a `cookiesecret` that can be
shared across an anycast set. A padded query over an encrypted transport gets a
padded reply (RFC 8467). Warm wire-eligible cache hits are served
allocation-free, with batched `recvmmsg`/`sendmmsg` on Linux.

**Policy.** Response Policy Zones with name, client-address and answer-address
triggers, file and TSIG-signed AXFR feeds, and a shadow mode whose counters
predict what enforcement would do. Blocklists, per-client views, access lists,
rate limits, and reflection-attack detection.

**Other namespaces.** Per-zone conditional forwarding, whole-server forwarder
mode, Kubernetes cluster DNS, DNS64 synthesis (RFC 6147), EDNS Client Subnet
(RFC 7871), locally served zones (RFC 6303).

**Operations.** Prometheus metrics, an HTTP API, dnstap, a recursion firewall
that bounds the work one request may cause, serving bounds derived from the
machine at startup, and a validation gate that reports every configuration
problem at once. Warm restart: `cache_persist` saves the answer cache at a
clean shutdown and loads it at the next start, and the local root copy is kept
in `root.zone`.

The [documentation](https://sdns.dev/docs/) covers each of these, including
what they cost and what they deliberately do not do.

## Performance

Throughput measurements, the methodology, resolver comparisons and their
caveats are in the
[benchmarks](https://sdns.dev/docs/reference/benchmarks/) document.

## Development

```shell
make all     # generate, tidy, test, build
make test    # tests only
go build     # binary only
```

Conventions a patch is expected to follow (plain `testing` idioms with no
assertion library, no live-network tests, `gofmt` and `golangci-lint` clean)
are on the [building and testing](https://sdns.dev/docs/development/building/)
page. The middleware interface is documented on the
[middleware](https://sdns.dev/docs/development/middleware/) page, and the
plugin contract on the [plugins](https://sdns.dev/docs/development/plugins/)
page.

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
