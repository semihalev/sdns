<p align="center">
  <img src="https://github.com/semihalev/sdns/blob/master/logo.png?raw=true" width="200">
</p>

<h1 align="center">SDNS :rocket:</h1>

<p align="center">
  A high-performance, recursive DNS resolver server with DNSSEC support, focused on preserving privacy.
</p>

<p align="center">
  <a href="https://github.com/semihalev/sdns/actions"><img src="https://img.shields.io/github/actions/workflow/status/semihalev/sdns/go.yml?style=for-the-badge"></a>
  <a href="https://goreportcard.com/report/github.com/semihalev/sdns"><img src="https://goreportcard.com/badge/github.com/semihalev/sdns?style=for-the-badge"></a>
  <a href="http://godoc.org/github.com/semihalev/sdns"><img src="https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge"></a>
  <a href="https://codecov.io/gh/semihalev/sdns"><img src="https://img.shields.io/codecov/c/github/semihalev/sdns?style=for-the-badge"></a>
  <a href="https://github.com/semihalev/sdns/releases"><img src="https://img.shields.io/github/v/release/semihalev/sdns?style=for-the-badge"></a>
  <a href="https://github.com/semihalev/sdns/blob/master/LICENSE"><img src="https://img.shields.io/github/license/semihalev/sdns?style=for-the-badge"></a>
</p>

---

## Installation

Use the `go get` command to install `sdns`:

```shell
go get github.com/semihalev/sdns
```

#### Pre-build Binaries

You can download the latest release from the [Github Repo](https://github.com/semihalev/sdns/releases/latest).

#### Docker

- [Docker Package](https://github.com/semihalev/sdns/packages/188181) (updated every release)
- [Docker Hub](https://hub.docker.com/r/c1982/sdns) (alternative)

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

> **Note:** Pre-built binaries, Docker packages, brew taps, and snaps are automatically created by Github [workflows](https://github.com/semihalev/sdns/actions).

## Building from Source

```shell
$ go build
```

## Testing

```shell
$ make test
```

## Flags

| Flag              | Desc                                                                           |
| ----------------- | ------------------------------------------------------------------------------ |
| -c, --config PATH | Location of the config file. If it doesn't exist, a new one will be generated. |
| -v, --version     | Show the version of the sdns.                                                  |
| -h, --help        | Show this help and exit.                                                       |

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

## Configuration (v1.3.3)

| Key                  | Description                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **version**          | Configuration version                                                                                               |
| **directory**        | sdns working directory (must grant write access to sdns user)                                                       |
| **bind**             | DNS server binding address Default: :53                                                                             |
| **bindtls**          | DNS-over-TLS server binding address Default: :853                                                                   |
| **binddoh**          | DNS-over-HTTPS server binding address Default: :8053                                                                |
| **binddoq**          | DNS-over-QUIC server binding address Default: :853                                                                  |
| **tlscertificate**   | Path to the TLS certificate file                                                                                    |
| **tlsprivatekey**    | Path to the TLS private key file                                                                                    |
| **outboundips**      | Outbound IPv4 addresses (randomly chosen if multiple entries provided)                                              |
| **outboundip6s**     | Outbound IPv6 addresses (randomly chosen if multiple entries provided)                                              |
| **rootservers**      | DNS Root IPv4 servers                                                                                               |
| **root6servers**     | DNS Root IPv6 servers                                                                                               |
| **rootkeys**         | Trusted DNSSEC anchors                                                                                              |
| **fallbackservers**  | Failover resolver IPv4 or IPv6 addresses with port (leave blank to disable) Example: "8.8.8.8:53"                   |
| **forwarderservers** | Forwarder resolver IPv4 or IPv6 addresses with port (leave blank to disable) Example: "8.8.8.8:53"                  |
| **api**              | HTTP API server binding address (leave blank to disable)                                                            |
| **blocklists**       | Remote blocklist address list (downloaded to the blocklist folder)                                                  |
| **blocklistdir**     | [DEPRECATED] Directory creation is automated in the working directory                                               |
| **loglevel**         | Log verbosity level (crit, error, warn, info, debug)                                                                |
| **accesslog**        | Location of the access log file (leave blank to disable) Default: Common Log Format                                 |
| **nullroute**        | IPv4 address for forwarding blocked queries                                                                         |
| **nullroutev6**      | IPv6 address for forwarding blocked queries                                                                         |
| **accesslist**       | Client whitelist for query permissions                                                                              |
| **querytimeout**     | Maximum wait duration for DNS query response Default: 10s                                                           |
| **timeout**          | Network timeout duration for each DNS lookup Default: 2s                                                            |
| **hostsfile**        | Enable serving zone data from a hosts file (leave blank to disable)                                                 |
| **expire**           | Default error cache TTL (in seconds) Default: 600                                                                   |
| **cachesize**        | Cache size (total records in cache) Default: 256000                                                                 |
| **prefetch**         | Cache prefetch before expiry (threshold: 10%-90%, 0 to disable)                                                     |
| **maxdepth**         | Maximum iteration depth per query Default: 30                                                                       |
| **ratelimit**        | Query-based rate limit per second (0 to disable) Default: 0                                                         |
| **clientratelimit**  | Client IP address-based rate limit per minute (no limit if client supports EDNS cookie) Default: 0                  |
| **blocklist**        | Manual blocklist entries                                                                                            |
| **whitelist**        | Manual whitelist entries                                                                                            |
| **cookiesecret**     | DNS cookie secret (RFC 7873) - auto-generated if not set                                                            |
| **nsid**             | DNS server identifier (RFC 5001) - useful for operating multiple sdns instances (leave blank to disable)            |
| **chaos**            | Enable responses to version.server, version.bind, hostname.bind and id.server chaos txt queries                     |
| **qname_min_level**  | Qname minimize level (0 to disable - higher values increase complexity and impact response performance)             |
| **emptyzones**       | Enable response to RFC 1918 zone queries. For details, see http://as112.net/                                        |

## Plugin Configuration

In sdns, you have the ability to add custom plugins. The sequence of the plugins and the middlewares has a mutual impact on their execution. Config keys must be strings, and values can be of any type. Plugins are loaded before the cache middleware in the specified order.

The plugin interface is straightforward. For additional information, please refer to the [example plugin](https://github.com/semihalev/sdnsexampleplugin).

### Example Configuration
```toml
[plugins]
     [plugins.example]
     path = "/path/to/exampleplugin.so"
     config = {key_1 = "value_1", intkey = 2, boolkey = true, keyN = "nnn"}
     [plugins.another]
     path = "/path/to/anotherplugin.so"
```

## Server Configuration Checklist

- Increase the file descriptor limit on your server
  
## Features

-   Linux/BSD/Darwin/Windows supported
-   DNS RFC compatibility
-   DNS lookups within listed ipv4 and ipv6 auth servers
-   DNS caching with prefetch support
-   DNSSEC validation
-   DNS over TLS support (DoT)
-   DNS over HTTPS support (DoH) with HTTP/3 support
-   DNS over QUIC support (DoQ)
-   Outbound IP selection
-   Middleware Support, you can add, your own middleware
-   RTT priority within listed servers
-   Failover forwarders while returning failured responses
-   Forwarder support
-   EDNS Cookie Support (client&lt;->server)
-   EDNS NSID Support
-   Full IPv6 support (client&lt;->server, server&lt;->server)
-   Query based ratelimit
-   IP based ratelimit
-   Access list
-   Access log
-   Prometheus basic query metrics
-   Black-hole for malware responses
-   HTTP API support
-   Cache Purge API and query support
-   Answer chaos txt queries for version.bind and hostname.bind
-   Empty zones support described at RFC 1918
-   External plugins supported

## TODO

-   [x] More tests
-   [x] Try lookup NS address better way
-   [x] DNS over TLS support
-   [x] DNS over HTTPS support
-   [x] Full DNSSEC support
-   [x] RTT optimization
-   [x] Access list
-   [x] Periodic priming queries described at RFC 8109
-   [x] Full IPv6 support (server&lt;->server communication)
-   [x] Query name minimization to improve privacy described at RFC 7816
-   [x] DNAME Redirection in the DNS described at RFC 6672
-   [x] Automated Updates DNSSEC Trust Anchors described at RFC 5011
-   [ ] DNS64 DNS Extensions for NAT from IPv6 Clients to IPv4 Servers described at RFC 6147
-   [x] DNS over QUIC support described at RFC 9250

## Performance

### Benchmark Environment

- **Server Specifications:**
    - Processor: Intel Xeon E5-2609 v4 CPU
    - Memory: 32GB

### Benchmarking Tool

- **Tool Name:** [DNS-OARC dnsperf](https://www.dns-oarc.net/tools/dnsperf)
- **Benchmark Configuration:**
    - Query Data Volume: 50,000 sample queries

### Benchmark Comparisons
Benchmarks were performed on the following DNS resolvers: sdns-1.3.3, pdns-recursor-4.8.4, bind-9.19.12, unbound-1.17.1.

### Benchmark Results

| Resolver | RESPONSE | LOST | NOERROR | SERVFAIL | NXDOMAIN | Run Time  | QPS   |
| -------- | -------- | ---- | ------- | -------- | -------- | --------- | ----- |
| SDNS     | 100%     | 1    | 35,164  | 866      | 13,969   | 87s47ms   | 571/s |
| PowerDNS | 99.99%   | 6    | 35,140  | 893      | 13,961   | 88s83ms   | 563/s |
| Bind     | 99.74%   | 132  | 35,024  | 885      | 13,959   | 127s64ms  | 390/s |
| Unbound  | 99.49%   | 253  | 35,152  | 624      | 13,971   | 174s64ms  | 284/s |


## Contributing

We welcome pull requests. If you're considering significant changes, please start a discussion by opening an issue first.

Ensure that your changes are accompanied by corresponding tests.

## :hearts: Made With

-   [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library

## Inspired by 
-   [coredns/coredns](https://github.com/coredns/coredns)
-   [looterz/grimd](https://github.com/looterz/grimd)

## License

[MIT](https://github.com/semihalev/sdns/blob/master/LICENSE)
