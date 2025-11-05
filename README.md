<p align="center">
  <img src="https://github.com/semihalev/sdns/blob/main/logo.png?raw=true" width="200">
</p>

<h1 align="center">SDNS :rocket:</h1>

<p align="center">
  A high-performance, recursive DNS resolver server with DNSSEC support, focused on preserving privacy.
</p>

<p align="center">
  <a href="https://github.com/semihalev/sdns/actions"><img src="https://img.shields.io/github/actions/workflow/status/semihalev/sdns/go.yml?style=flat-square"></a>
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

*   [Docker Package](https://github.com/semihalev/sdns/packages/188181) (updated every release)
*   [Docker Hub](https://hub.docker.com/r/c1982/sdns) (alternative)

```shell
$ docker run -d --name sdns -p 53:53 -p 53:53/udp sdns
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

## Configuration (v1.6.1)

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
| **dnstapsocket**     | Unix domain socket path for dnstap binary DNS logging. Leave empty to disable                                       |
| **dnstapidentity**   | Server identity string for dnstap messages. Defaults to hostname                                                    |
| **dnstapversion**    | Server version string for dnstap messages. Default: "sdns"                                                          |
| **dnstaplogqueries** | Log DNS queries via dnstap. Default: true                                                                           |
| **dnstaplogresponses** | Log DNS responses via dnstap. Default: true                                                                        |
| **dnstapflushinterval** | Dnstap message flush interval in seconds. Default: 5                                                             |

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
- Optional "killer mode" for extreme performance

**Configuration:**
```toml
[kubernetes]
enabled = true
cluster_domain = "cluster.local"  # Default: cluster.local
killer_mode = false               # Enable for maximum performance
# kubeconfig = "/path/to/kubeconfig"  # Optional, uses in-cluster config by default
```

**Killer Mode Features:**
When `killer_mode` is enabled:
- Zero-allocation wire-format caching
- Lock-free ML-based query prediction
- Sharded registry for concurrent operations
- Predictive cache prefetching
- 50,000+ QPS on single core

For detailed information, see the [Kubernetes middleware documentation](middleware/kubernetes/README.md).

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
*   **Kubernetes DNS integration with killer mode performance**
*   **Automatic TLS certificate reloading without downtime**

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
*   \[ ] DNS64 DNS Extensions for NAT from IPv6 Clients to IPv4 Servers described at RFC 6147
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

Tests were performed on the following DNS resolvers: SDNS 1.5.1, PowerDNS Recursor 5.0.2, BIND 9.19.12, and Unbound 1.17.1.

### Benchmark Results

| Resolver | Version | QPS    | Avg Latency | Lost Queries | Runtime  | Response Codes                                      |
| -------- | ------- | ------ | ----------- | ------------ | -------- | --------------------------------------------------- |
| SDNS     | 1.5.1   | 712/s  | 136ms       | 2 (0.004%)   | 70.2s    | NOERROR: 67.82%, SERVFAIL: 1.64%, NXDOMAIN: 30.55% |
| PowerDNS | 5.0.2   | 578/s  | 156ms       | 20 (0.04%)   | 86.5s    | NOERROR: 67.64%, SERVFAIL: 1.92%, NXDOMAIN: 30.43% |
| BIND     | 9.19.12 | 405/s  | 200ms       | 156 (0.31%)  | 123.0s   | NOERROR: 67.84%, SERVFAIL: 1.62%, NXDOMAIN: 30.54% |
| Unbound  | 1.17.1  | 338/s  | 237ms       | 263 (0.53%)  | 147.0s   | NOERROR: 68.20%, SERVFAIL: 1.20%, NXDOMAIN: 30.60% |

### Performance Summary

SDNS demonstrates superior performance across all key metrics:
- **Highest throughput**: 712 queries per second (23% faster than PowerDNS, 76% faster than BIND, 111% faster than Unbound)
- **Lowest latency**: 136ms average (13-43% lower than competitors)
- **Best reliability**: Only 2 lost queries out of 50,000 (99.996% success rate)
- **Fastest completion**: 70.2 seconds total runtime

With Kubernetes killer mode enabled, SDNS can achieve:
- **50,000+ QPS** on a single core for Kubernetes DNS queries
- **Sub-100μs latency** for cached responses
- **Zero allocations** in the hot path
- **90%+ cache hit rates** with ML-based prediction

## Contributing

We welcome pull requests. If you're considering significant changes, please start a discussion by opening an issue first.

Before submitting patches, please review our [CONTRIBUTING](https://github.com/semihalev/sdns/blob/main/CONTRIBUTING.md) guidelines.

## :hearts: Made With

*   [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library

## Inspired by

*   [looterz/grimd](https://github.com/looterz/grimd)

## License

[MIT](https://github.com/semihalev/sdns/blob/main/LICENSE)
