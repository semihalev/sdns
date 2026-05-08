<p align="center">
  <img src="https://github.com/semihalev/sdns/blob/main/logo.png?raw=true" width="200">
</p>

<h1 align="center">SDNS :rocket:</h1>

<p align="center">
  A high-performance, recursive DNS resolver server with DNSSEC support, focused on preserving privacy.
</p>

<p align="center">
  <a href="https://github.com/semihalev/sdns/actions"><img src="https://img.shields.io/github/actions/workflow/status/semihalev/sdns/ci.yml?style=flat-square"></a>
  <a href="https://goreportcard.com/report/github.com/semihalev/sdns"><img src="https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square"></a>
  <a href="http://godoc.org/github.com/semihalev/sdns"><img src="https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square"></a>
  <a href="https://codecov.io/gh/semihalev/sdns"><img src="https://img.shields.io/codecov/c/github/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/releases"><img src="https://img.shields.io/github/v/release/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/blob/main/LICENSE"><img src="https://img.shields.io/github/license/semihalev/sdns?style=flat-square"></a>
</p>

***

## Installation

Install SDNS using the `go install` command:

```shell
go install github.com/semihalev/sdns@latest
```

#### Pre-built Binaries

Download the latest release from the [GitHub Releases](https://github.com/semihalev/sdns/releases/latest) page.

#### Docker

Multi-arch images (linux/amd64, linux/arm64) are published on every tagged release to both registries:

*   [GitHub Container Registry](https://github.com/semihalev/sdns/pkgs/container/sdns): `ghcr.io/semihalev/sdns`
*   [Docker Hub](https://hub.docker.com/r/c1982/sdns): `c1982/sdns`

```shell
$ docker run -d --name sdns -p 53:53 -p 53:53/udp ghcr.io/semihalev/sdns:latest
```

Pin to a specific version (recommended for production):

```shell
$ docker run -d --name sdns -p 53:53 -p 53:53/udp ghcr.io/semihalev/sdns:1.6.6
```

#### Docker Compose

Install `docker-compose` and run from the root directory:

```shell
$ sudo apt install docker-compose
$ docker-compose up -d
```

#### Homebrew for macOS

Install and run as a service:

```shell
$ brew install sdns
$ brew install semihalev/tap/sdns (updated every release)
$ brew services start sdns
```

#### Snapcraft

```shell
$ snap install sdns
```

#### AUR for ArchLinux

```shell
$ yay -S sdns-git
```

> **Note:** Pre-built binaries, Docker packages, brew taps, and snaps are automatically created by GitHub [workflows](https://github.com/semihalev/sdns/actions).

## Building from Source

```shell
$ go build
```

## Testing

```shell
$ make test
```

## Flags

| Flag              | Description                                                                    |
| ----------------- | ------------------------------------------------------------------------------ |
| -c, --config PATH | Location of the config file. If it doesn't exist, a new one will be generated. Default: /sdns.conf  |
| -t, --test        | Test configuration file and exit. Returns exit code 0 if valid, 1 if invalid  |
| -v, --version     | Show the SDNS version                                                          |
| -h, --help        | Show help information and exit                                                 |

## Debugging Environment

To debug your environment, execute the following command:

```shell
$ export SDNS_DEBUGNS=true && export SDNS_PPROF=true && ./sdns
```

The `SDNS_DEBUGNS` environment variable is beneficial for verifying the RTT (Round Trip Time) of authoritative servers. To use it, send an HINFO query for zones with chaos class.

Here's an example of the output you might receive:

```shell
$ dig chaos hinfo example.com

; <<>> DiG 9.17.1 <<>> chaos hinfo example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29636
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: f27dbb995df5ac79e4fa37c07d131b5bd03aa1c5f802047a7c02fb228a886cb281ecc319323dea81 (good)
;; QUESTION SECTION:
;example.com.			CH	HINFO

;; AUTHORITY SECTION:
example.com.		0	CH	HINFO	"Host" "IPv4:199.43.135.53:53 rtt:142ms health:[GOOD]"
example.com.		0	CH	HINFO	"Host" "IPv4:199.43.133.53:53 rtt:145ms health:[GOOD]"
example.com.		0	CH	HINFO	"Host" "IPv6:[2001:500:8f::53]:53 rtt:147ms health:[GOOD]"
example.com.		0	CH	HINFO	"Host" "IPv6:[2001:500:8d::53]:53 rtt:148ms health:[GOOD]"
```

## Configuration (v1.6.6)

| Key                  | Description                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **version**          | Configuration file version                                                                                          |
| **directory**        | Working directory for SDNS data storage. Must be writable by the SDNS process. Default: "/db"                        |
| **bind**             | DNS server binding address and port. Default: ":53" (0.0.0.0:53 and [::]:53)                                                                 |
| **bindtls**          | DNS-over-TLS (DoT) server binding address. Default: ":853"                                                          |
| **binddoh**          | DNS-over-HTTPS (DoH) server binding address. Default: ":8053"                                                       |
| **binddoq**          | DNS-over-QUIC (DoQ) server binding address. Default: ":853"                                                         |
| **tlscertificate**   | Path to the TLS certificate file for DoT/DoH/DoQ. Automatically reloaded on changes                                 |
| **tlsprivatekey**    | Path to the TLS private key file for DoT/DoH/DoQ. Automatically reloaded on changes                                 |
| **outboundips**      | Outbound IPv4 addresses for DNS queries. Multiple addresses enable random source IP selection per request            |
| **outboundip6s**     | Outbound IPv6 addresses for DNS queries. Multiple addresses enable random source IP selection per request            |
| **rootservers**      | Root DNS servers (IPv4). These are the authoritative name servers for the DNS root zone                             |
| **root6servers**     | Root DNS servers (IPv6). These are the authoritative name servers for the DNS root zone                             |
| **dnssec**           | Enable DNSSEC validation for secure DNS responses. Options: "on" or "off". Default: "on"                            |
| **rootkeys**         | DNSSEC root zone trust anchors in DNSKEY format                                                                     |
| **fallbackservers**  | Upstream DNS servers used when all others fail. Format: "IP:port" (e.g., "8.8.8.8:53")                             |
| **forwarderservers** | Forward all queries to these DNS servers. Format: "IP:port" (e.g., "8.8.8.8:53")                                   |
| **api**              | HTTP API server binding address for statistics and control. Leave empty to disable                                  |
| **bearertoken**      | API bearer token for authorization. If set, Authorization header must be included in API requests                   |
| **blocklists**       | URLs of remote blocklists to download and use for filtering                                                         |
| **blocklistdir**     | \[DEPRECATED] Blocklist directory. Now automatically created in the working directory                               |
| **loglevel**         | Logging verbosity level. Options: crit, error, warn, info, debug. Default: "info"                                  |
| **accesslog**        | Path to the access log file in Common Log Format. Leave empty to disable                                            |
| **nullroute**        | IPv4 address returned for blocked A queries. Default: "0.0.0.0"                                                     |
| **nullroutev6**      | IPv6 address returned for blocked AAAA queries. Default: "::0"                                                      |
| **accesslist**       | IP addresses/subnets allowed to make queries. Default allows all: ["0.0.0.0/0", "::0/0"]                           |
| **querytimeout**     | Maximum time to wait for any DNS query to complete. Default: "10s"                                                  |
| **timeout**          | Network timeout for upstream DNS queries. Default: "2s"                                                             |
| **hostsfile**        | Path to hosts file (RFC 952/1123 format) for local resolution. Auto reloads with fs watch. (The directory of the file is being watched, not the file. Best practice is to deploy the file in an individual directory.) Leave empty to disable |
| **expire**           | Cache TTL for error responses in seconds. Default: 600                                                              |
| **cachesize**        | Maximum number of cached DNS records. Default: 256000                                                               |
| **prefetch**         | Prefetch threshold percentage (10-90). Refreshes popular cache entries before expiration. 0 disables               |
| **maxdepth**         | Maximum recursion depth for queries. Prevents infinite loops. Default: 30                                           |
| **ratelimit**        | Global query rate limit per second. 0 disables. Default: 0                                                          |
| **clientratelimit**  | Per-client rate limit per minute. 0 disables. Default: 0                                                            |
| **domainmetrics**    | Enable per-domain query metrics collection. Default: false                                                          |
| **domainmetricslimit** | Maximum number of domains to track in metrics. 0 = unlimited (use with caution). Default: 10000                  |
| **blocklist**        | Manual domain blocklist. Domains listed here will be blocked                                                        |
| **whitelist**        | Manual domain whitelist. Overrides blocklist matches                                                                |
| **cookiesecret**     | DNS cookie secret (RFC 7873) for client verification. Auto-generated if not set                                     |
| **nsid**             | DNS server identifier (RFC 5001) for identifying this instance. Leave empty to disable                              |
| **chaos**            | Enable responses to version.bind and hostname.bind chaos queries. Default: true                                     |
| **qname_min_level**  | QNAME minimization level (RFC 7816). 0 disables. Higher values increase privacy but may impact performance         |
| **emptyzones**       | Enable local authoritative responses for RFC 1918 zones. See http://as112.net/ for details                         |
| **tcpkeepalive**     | Enable TCP connection pooling for root and TLD servers. Improves performance by reusing connections. Default: false |
| **roottcptimeout**   | TCP idle timeout for root server connections. Default: "5s"                                                          |
| **tldtcptimeout**    | TCP idle timeout for TLD server connections (com, net, org, etc.). Default: "10s"                                   |
| **tcpmaxconnections**| Maximum number of pooled TCP connections. 0 uses default. Default: 100                                               |
| **maxconcurrentqueries** | Maximum number of concurrent DNS queries allowed. Limits resource usage under heavy load. Default: 10000         |
| **reflexenabled**    | Enable DNS amplification/reflection attack detection. Default: false                                                |
| **reflexblockmode**  | Block detected attacks (if false, only logs). Default: true                                                         |
| **reflexlearningmode** | Log detections without blocking for threshold tuning. Default: false                                              |
| **reflexthreshold**  | Suspicion score threshold (0.0-1.0). Lower = more aggressive. Default: 0.7                                          |
| **dnstapsocket**     | Unix domain socket path for dnstap binary DNS logging. Leave empty to disable                                       |
| **dnstapidentity**   | Server identity string for dnstap messages. Defaults to hostname                                                    |
| **dnstapversion**    | Server version string for dnstap messages. Default: "sdns"                                                          |
| **dnstaplogqueries** | Log DNS queries via dnstap. Default: true                                                                           |
| **dnstaplogresponses** | Log DNS responses via dnstap. Default: true                                                                        |
| **dnstapflushinterval** | Dnstap message flush interval in seconds. Default: 5                                                             |
| **views**            | Per-client static-answer rules. Each entry has `zone` (label), `networks` (CIDRs), and `answers` (zone-file RRs). See the Views middleware section below for shape and examples |

## Middleware Configuration

SDNS supports a flexible middleware architecture that allows extending its functionality through built-in middlewares and external plugins.

### Built-in Middlewares

#### Kubernetes DNS Middleware

The Kubernetes middleware provides full DNS integration for Kubernetes clusters, supporting all standard Kubernetes DNS patterns.

**Features:**
- Service DNS resolution (A, AAAA, CNAME, SRV)
- Pod DNS resolution (by IP and hostname)
- Headless services and StatefulSets
- ExternalName services
- Full IPv6 and dual-stack support
- Real-time Kubernetes API synchronization
- 256-way sharded registry for concurrent informer writes and lock-free reads
- Reverse-IP and pod-by-name indexes for O(1) PTR / StatefulSet lookups

**Configuration:**
```toml
[kubernetes]
enabled = true
cluster_domain = "cluster.local"  # Default: cluster.local
# kubeconfig = "/path/to/kubeconfig"  # Optional, uses in-cluster config by default
```

> The legacy `killer_mode` flag is accepted for backward compatibility
> but has no effect — the middleware always uses the sharded registry.

For detailed information, see the [Kubernetes middleware documentation](middleware/kubernetes/README.md).

#### Reflex: DNS Amplification Attack Detection

The Reflex middleware detects and blocks DNS amplification/reflection attacks by analyzing IP behavior patterns.

**How It Works:**
- Tracks query patterns per source IP (rate, types, amplification ratio)
- Identifies spoofed IPs used in reflection attacks
- TCP connections prove real IP ownership (clears suspicion)
- Bounded memory usage with automatic cleanup

**Detection Factors:**
- High query rate from single IP
- High-amplification query types only (DNSKEY, TXT, etc.)
- Lack of normal queries (A, AAAA)
- Actual response/request amplification ratio
- Low query type diversity

**Configuration:**
```toml
reflexenabled = false       # Enable detection
reflexblockmode = true      # Block attacks (false = log only)
reflexlearningmode = false  # Log without blocking for tuning
# reflexthreshold = 0.7     # Score threshold (0.0-1.0)
```

**Prometheus Metrics:**
- `reflex_detections_total` - Suspected attacks by query type
- `reflex_blocked_total` - Blocked queries
- `reflex_tracked_ips` - Currently tracked IPs

#### Views: Per-Client Static Answers

The Views middleware serves different DNS answers based on the client's source IP — a split-horizon resolver where a name like `*.example.lan.` can resolve to one address for LAN clients and a different address for VPN clients, all without disturbing recursion for everyone else.

**How It Works:**
- Each view declares a list of CIDR `networks` and a list of zone-file `answers`.
- A query whose source IP falls in one of a view's networks is matched against that view's answers (by name and qtype, with `*.zone.` wildcard support per RFC 4592).
- A matching answer is synthesised with the query name as owner and short-circuits the chain.
- A query that matches the view's networks but has no matching answer (or comes from a client outside every view's networks) falls through to the rest of the chain — blocklist, cache, resolver, etc.
- Internal sub-queries skip the views middleware entirely (no real client IP).

**Configuration:**
```toml
[[views]]
zone = "lannet"
networks = ["192.168.1.0/24"]
answers = [
    "*.example.lan. 60 IN A 192.168.1.3",
    "*.example.lan. 60 IN AAAA fd00::3",
]

[[views]]
zone = "vpnnet"
networks = ["100.64.0.0/24"]
answers = [
    "*.example.lan. 60 IN A 100.64.0.2",
]
```

Views are evaluated in declaration order; the first whose `networks` contains the client IP wins. `zone` is a free-form label used in error logs — it doesn't have to be a DNS zone name.

#### DNS64 (RFC 6147)

The DNS64 middleware lets IPv6-only clients reach IPv4-only services. When a client AAAA query has no usable answer, the middleware issues a secondary A-record lookup and synthesises AAAA records by embedding each IPv4 address into a configured Pref64::/n IPv6 prefix (RFC 6052). The client receives addresses in a NAT64-routable subnet and can connect to the IPv4-only target through a paired NAT64 gateway.

**How It Works:**

- The middleware sits between the `kubernetes` and `cache` middlewares. The cache stores the original AAAA response — synthesis runs per client query against that cached response. The secondary A lookup itself is cached, so repeat synthesis is bounded to a memcpy plus a cache hit. This preserves per-client correctness when `client_networks` restricts who gets synthesis.
- **RCODE handling** follows RFC 6147 §5.1.2 / §5.1.3 / §5.5:
  - `NOERROR` with at least one usable AAAA → pass through (after AAAA exclusion filtering, see below).
  - `NXDOMAIN` → pass through unchanged. The name doesn't exist, so it has no A either.
  - `SERVFAIL` carrying a DNSSEC-failure Extended DNS Error (codes 1/2/5–12/27 — Unsupported DNSKEY Algorithm, Unsupported DS Digest Type, DNSSEC Indeterminate, DNSSEC Bogus, Signature Expired/Not Yet Valid, DNSKEY/RRSIGs/NSEC Missing, No Zone Key Bit Set, Unsupported NSEC3 Iterations Value) → pass through unchanged. Synthesising over a validation failure would let an attacker bypass DNSSEC.
  - `NOERROR` with no usable AAAA, or any other nonzero RCODE (`SERVFAIL` without a DNSSEC EDE, `REFUSED`, etc.) → treated as "no answer" and the secondary A lookup is attempted. When the A query yields empty/error too, that response (rcode + Authority + any CNAME/DNAME chain) becomes the basis for the client reply per §5.1.6.
- **Recursion bit:** `RD=0` queries skip DNS64 entirely. Synthesis requires a recursive secondary lookup, so honouring the client's non-recursive intent means stepping aside.
- **AAAA exclusion (RFC 6147 §5.1.4):** AAAA records returned by the upstream are filtered against `exclude_aaaa_networks` (default `::ffff:0:0/96` IPv4-mapped) before deciding pass-through vs synthesis. If every AAAA is excluded, the response is treated as if no AAAA were returned and synthesis proceeds. Excluded AAAAs are stripped from the Answer section even on the pass-through path so they never reach the client.
- **A side filtering (RFC 6147 §5.1.4):** when the active prefix is the IANA Well-Known `64:ff9b::/96`, IPv4 addresses inside `exclude_a_networks` are dropped from synthesis. Operator-chosen prefixes ignore that list — you picked the prefix knowing the network's reachability.
- **CNAME / DNAME chains (RFC 6147 §5.1.5)** are carried through into the synthesised answer. Synthesised AAAAs adopt the A record's owner — the terminal name after the chain has resolved.
- **TTL (RFC 6147 §5.1.7):** the synthesised AAAA TTL is `min(A record TTL, AAAA negative-cache TTL)`. When the original AAAA carried no SOA, the synth TTL caps at 600 s. No artificial floor.
- **Multi-prefix synthesis (RFC 6147 §5.2):** every configured prefix produces its own synthesised AAAA per A record, so a client receives every reachable Pref64 path in a single response. Per-prefix RFC 6147 §5.1.4 filtering still applies — a private IPv4 may be excluded under `64:ff9b::/96` but synthesised under an operator prefix listed alongside it.
- **PTR translation (RFC 6147 §5.3.1):** `ip6.arpa` PTR queries whose embedded IPv4 falls under any configured Pref64 are answered with a CNAME pointing at the corresponding `in-addr.arpa` name; if the chase succeeds, the resolved PTR records are appended. Names that decode to addresses outside every Pref64 (or whose IPv4 hits the §5.1.4 exclusion under the well-known prefix) flow through normal recursion so real reverse zones still answer.
- **DNSSEC (RFC 6147 §5.5):** when the original NODATA was `AD=1`, the synthesised reply clears AD and attaches Extended DNS Error 4 ("Forged Answer"). Clients that set `CD=1` are validating themselves and bypass synthesis (both AAAA and PTR paths).
- **Internal sub-queries** (resolver NS chase, cache CNAME chase) skip DNS64 entirely — synthesis is a client-facing concern, not part of resolution semantics.

**Configuration:**
```toml
[dns64]
enabled = true
prefixes = ["64:ff9b::/96"]         # IANA Well-Known Prefix; or your own /32, /40, /48, /56, /64, /96. List multiple to synthesise one AAAA per prefix per A.
client_networks = []                # Empty = all clients eligible; restrict to your IPv6-only subnets to scope synthesis
exclude_zones = []                  # FQDNs (suffix match) whose AAAA must never be synthesised
exclude_aaaa_networks = ["::ffff:0:0/96"]  # IPv6 prefixes whose AAAA records are filtered out of upstream replies (RFC 6147 §5.1.4)
exclude_a_networks = [              # IPv4 ranges skipped under the well-known prefix only (RFC 6147 §5.1.4)
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    # …plus the rest of the IANA Special-Purpose Address Registry; defaults documented in sdns.conf
]
```

`exclude_aaaa_networks` defaults to `["::ffff:0:0/96"]` when the field is unset. Pass `[]` (declared empty) to opt out of AAAA filtering entirely. `exclude_a_networks` is consulted only when `64:ff9b::/96` is among the active prefixes.

**Prometheus Metrics:**
- `dns64_synthesised_total` — AAAA queries answered with synthesised records
- `dns64_ptr_translated_total` — `ip6.arpa` PTR queries redirected to `in-addr.arpa`
- `dns64_passthrough_total{reason}` — AAAA queries left untouched, labelled by reason: `aaaa_present`, `nxdomain`, `dnssec_fail`, `no_rd`, `client_excluded`, `zone_excluded`, `cd_bit`, `internal`, `a_excluded`
- `dns64_a_lookup_failures_total{reason}` — failures of the secondary A lookup, labelled by reason

#### Cache Metrics

SDNS exports comprehensive cache metrics via the Prometheus `/metrics` endpoint for monitoring cache performance.

**Prometheus Metrics:**
- `dns_cache_hits_total` - Total number of cache hits
- `dns_cache_misses_total` - Total number of cache misses
- `dns_cache_evictions_total` - Total number of cache evictions
- `dns_cache_prefetches_total` - Total number of prefetch operations
- `dns_cache_size{type="positive|negative"}` - Current number of entries in the cache
- `dns_cache_hit_rate` - Cache hit rate percentage

**Example Prometheus Queries:**
```promql
# Cache hit rate
dns_cache_hit_rate

# Cache hit ratio (alternative calculation)
rate(dns_cache_hits_total[5m]) / (rate(dns_cache_hits_total[5m]) + rate(dns_cache_misses_total[5m]))

# Total cache size
sum(dns_cache_size)

# Cache operations per second
rate(dns_cache_hits_total[1m]) + rate(dns_cache_misses_total[1m])
```

### External Plugins

SDNS supports custom plugins to extend its functionality. The execution order of plugins and middlewares affects their behavior. Configuration keys must be strings, while values can be any type. Plugins are loaded before the cache middleware in the order specified.

For implementation details, see the [example plugin](https://github.com/semihalev/sdnsexampleplugin).

**Example Configuration:**
```toml
[plugins]
     [plugins.example]
     path = "/path/to/exampleplugin.so"
     config = {key_1 = "value_1", intkey = 2, boolkey = true, keyN = "nnn"}
     [plugins.another]
     path = "/path/to/anotherplugin.so"
```

## TLS Certificate Management

SDNS automatically monitors and reloads TLS certificates when they change on disk, making it compatible with automatic certificate renewal systems like Let's Encrypt.

### Automatic Certificate Reloading

*   Certificate files are monitored for changes using filesystem notifications
*   When a certificate is updated, SDNS automatically reloads it without dropping connections
*   Works seamlessly with Let's Encrypt and other ACME clients
*   Certificate changes are detected within seconds

### Manual Certificate Reload

You can also trigger a certificate reload manually by sending a SIGHUP signal:

```shell
$ kill -HUP $(pidof sdns)
```

This is useful when:
*   Filesystem notifications are not reliable on your system
*   You want to reload certificates on demand
*   You're using a certificate deployment system that doesn't modify files in-place

### Certificate Requirements

*   Certificate and key files must be readable by the SDNS process
*   Supports standard PEM-encoded X.509 certificates
*   Works with wildcard certificates
*   Compatible with both RSA and ECDSA certificates

## Server Configuration Checklist

*   Increase the file descriptor limit on your server

## Features

*   Linux/BSD/Darwin/Windows support
*   Full DNS RFC compatibility
*   DNS queries using both IPv4 and IPv6 authoritative servers
*   High-performance DNS caching with prefetch support
*   Full DNSSEC validation support with RFC 8914 Extended DNS Errors (EDE)
*   DNS over TLS (DoT) support
*   DNS over HTTPS (DoH) support with HTTP/3
*   DNS over QUIC (DoQ) support
*   Multiple outbound IP selection for queries
*   Extensible middleware architecture
*   RTT-based server prioritization with adaptive timeouts
*   Parallel DNS lookups for improved performance
*   Failover to backup servers on failure
*   DNS forwarding support
*   EDNS Cookie support (RFC 7873)
*   EDNS NSID support (RFC 5001)
*   Extended DNS Errors (EDE) support (RFC 8914)
*   Full IPv6 support (both client and server communication)
*   Query-based rate limiting
*   Client IP-based rate limiting
*   IP-based access control lists
*   Comprehensive access logging
*   Prometheus metrics with optional per-domain tracking
*   DNS sinkholing for malicious domains
*   HTTP API for management and statistics
*   Cache purge via API and DNS queries
*   Chaos TXT query support for version.bind and hostname.bind
*   Empty zones support (RFC 1918)
*   External plugin support
*   Binary DNS logging via dnstap protocol (RFC 6742)
*   QNAME minimization for privacy (RFC 7816)
*   Automatic DNSSEC trust anchor updates (RFC 5011)
*   Zero-allocation cache operations for improved performance
*   TCP connection pooling for persistent connections
*   **Kubernetes DNS integration with a 256-way sharded registry and zero-allocation lookups**
*   **Automatic TLS certificate reloading without downtime**
*   **DNS amplification/reflection attack detection (Reflex)**
*   **DNS64 synthesis for IPv6-only clients (RFC 6147)**

## TODO

*   \[x] More tests
*   \[x] Try lookup NS address better way
*   \[x] DNS over TLS support
*   \[x] DNS over HTTPS support
*   \[x] Full DNSSEC support
*   \[x] RTT optimization
*   \[x] Access list
*   \[x] Periodic priming queries described at RFC 8109
*   \[x] Full IPv6 support (server<->server communication)
*   \[x] Query name minimization to improve privacy described at RFC 7816
*   \[x] DNAME Redirection in the DNS described at RFC 6672
*   \[x] Automated Updates DNSSEC Trust Anchors described at RFC 5011
*   \[x] DNS64 DNS Extensions for NAT from IPv6 Clients to IPv4 Servers described at RFC 6147
*   \[x] DNS over QUIC support described at RFC 9250
*   \[x] Kubernetes DNS integration

## Performance

### Benchmark Environment

*   **Server Specifications:**
    *   Processor: Apple M1 Pro
    *   Memory: 16GB

### Benchmarking Tool

*   **Tool:** [DNS-OARC dnsperf](https://www.dns-oarc.net/tools/dnsperf)
*   **Configuration:**
    *   Query volume: 50,000 sample queries
    *   Test date: June 2025

### Benchmark Comparisons

Tests were performed on the following DNS resolvers: SDNS 1.6.5, PowerDNS Recursor 5.4.1, BIND 9.19.12, and Unbound 1.17.1.

### Benchmark Results

| Resolver | Version | QPS    | Avg Latency | Lost Queries | Runtime  | Response Codes                                      |
| -------- | ------- | ------ | ----------- | ------------ | -------- | --------------------------------------------------- |
| SDNS     | 1.6.5   | 708/s  | 134ms       | 1 (0.00%)    | 70.5s    | NOERROR: 66.87%, SERVFAIL: 1.71%, NXDOMAIN: 31.43% |
| PowerDNS | 5.4.1   | 617/s  | 147ms       | 17 (0.03%)   | 80.9s    | NOERROR: 66.87%, SERVFAIL: 1.69%, NXDOMAIN: 31.44% |
| BIND     | 9.19.12 | 405/s  | 200ms       | 156 (0.31%)  | 123.0s   | NOERROR: 67.84%, SERVFAIL: 1.62%, NXDOMAIN: 30.54% |
| Unbound  | 1.17.1  | 338/s  | 237ms       | 263 (0.53%)  | 147.0s   | NOERROR: 68.20%, SERVFAIL: 1.20%, NXDOMAIN: 30.60% |

### Performance Summary

SDNS demonstrates superior performance across all key metrics:
- **Highest throughput**: 708 queries per second (15% faster than PowerDNS, 75% faster than BIND, 109% faster than Unbound)
- **Lowest latency**: 134ms average (9-43% lower than competitors)
- **Best reliability**: Only 1 lost query out of 50,000 (99.998% success rate)
- **Fastest completion**: 70.5 seconds total runtime

For Kubernetes DNS, the registry is the hot path:

- `BenchmarkRegistryResolveQuery` reports **0 B/op, 0 allocs/op** at
  ~95 ns/op on Apple M5 — every query is a single sharded map lookup
  followed by a slice-header copy.
- Each mutation (`AddService`/`AddPod`/`SetEndpoints`) pre-builds the
  `dns.RR` slices the affected names will return, including SRV
  per named port and PTR for ClusterIPs / pod IPs.
- The full `ServeDNS` path adds the unavoidable `dns.Msg` setup and
  wire-pack overhead from miekg/dns; that's the only remaining
  per-query allocation cost.

> The legacy `killer_mode` flag is still parsed for backward
> compatibility but is now a no-op — the registry above is always
> active. The previous "killer mode" components (per-package cache,
> SmartPredictor, PrefetchStrategy) were removed.

## Contributing

We welcome pull requests. If you're considering significant changes, please start a discussion by opening an issue first.

Before submitting patches, please review our [CONTRIBUTING](https://github.com/semihalev/sdns/blob/main/CONTRIBUTING.md) guidelines.

## :hearts: Made With

*   [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library

## Inspired by

*   [looterz/grimd](https://github.com/looterz/grimd)

## License

[MIT](https://github.com/semihalev/sdns/blob/main/LICENSE)
