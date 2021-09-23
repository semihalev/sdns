
[![Go](https://github.com/semihalev/sdns/workflows/Go/badge.svg)](https://github.com/semihalev/sdns/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square)](https://goreportcard.com/report/github.com/semihalev/sdns)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/semihalev/sdns)
[![codecov](https://codecov.io/gh/semihalev/sdns/branch/master/graph/badge.svg)](https://codecov.io/gh/semihalev/sdns)
[![GitHub version](https://badgen.net/github/release/semihalev/sdns)](https://github.com/semihalev/sdns/releases)

## :rocket: Privacy important, fast, recursive dns resolver server with dnssec support

<img src="https://github.com/semihalev/sdns/blob/master/logo.png?raw=true" width="200">

## Installation

```shell
go get github.com/semihalev/sdns
```

#### Pre-build Binaries

Download the latest release from [Github Repo](https://github.com/semihalev/sdns/releases/latest)

#### Docker Image

1. [Docker Package](https://github.com/semihalev/sdns/packages/188181) (update every release)
2. [Docker Hub](https://hub.docker.com/r/c1982/sdns) (alternative)

```shell
$ docker run -d --name sdns -p 53:53 -p 53:53/udp sdns
```

#### Homebrew for macOS

```shell
$ brew install sdns
$ brew install semihalev/tap/sdns (update every release)
```

Run as service

```shell
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

> **Tip:** Pre-build binaries, docker package, brew tap and snap automatically create by Github [workflows](https://github.com/semihalev/sdns/actions)

## Building

```shell
$ go build
```

## Testing

```shell
$ make test
```

## Flags

| Flag   | Desc                                                                          |
| ------ | ----------------------------------------------------------------------------- |
| config | Location of the config file, if config file not found, a config will generate |
| v      | Show version information                                                      |

## Debug Environment

```shell
$ export SDNS_DEBUGNS=true && export SDNS_PPROF=true && ./sdns
```

SDNS_DEBUGNS enviroment useful when you want to check authoritive servers RTT times. 
Usage: send HINFO query for zones with chaos class.

Example Output:
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

## Configuration (v1.1.0)

| Key                 | Desc                                                                                                                           |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **version**         | Config version                                                                                                                 |
| **blocklists**      | List of remote blocklists address list. All lists will be download to blocklist folder.                                        |
| **blocklistdir**    | List of locations to recursively read blocklists from (warning, every file found is assumed to be a hosts-file or domain list) |
| **loglevel**        | What kind of information should be logged, Log verbosity level crit,error,warn,info,debug                                      |
| **accesslog**       | The location of access log file, left blank for disabled. SDNS uses Common Log Format by default.                              |
| **bind**            | Address to bind to for the DNS server. Default :53                                                                             |
| **bindtls**         | Address to bind to for the DNS-over-TLS server. Default :853                                                                   |
| **binddoh**         | Address to bind to for the DNS-over-HTTPS server. Default :8053                                                                |
| **tlscertificate**  | TLS certificate file path                                                                                                      |
| **tlsprivatekey**   | TLS private key file path                                                                                                      |
| **outboundips**     | Outbound ipv4 addresses, if you set multiple, sdns can use random outbound ipv4 address by request based                       |
| **outboundip6s**    | Outbound ipv6 addresses, if you set multiple, sdns can use random outbound ipv6 address by request based                       |
| **rootservers**     | DNS Root IPv4 servers                                                                                                          |
| **root6servers**    | DNS Root IPv6 servers                                                                                                          |
| **rootkeys**        | Trusted anchors for DNSSEC                                                                                                     |
| **fallbackservers** | Failover resolver ipv4 or ipv6 addresses with port, left blank for disabled: Example: "8.8.8.8:53"                             |
| **forwarderservers**| Forwarder resolver ipv4 or ipv6 addresses with port, left blank for disabled: Example: "8.8.8.8:53"                            |
| **api**             | Address to bind to for the http API server, left blank for disabled                                                            |
| **nullroute**       | IPv4 address to forward blocked queries to                                                                                     |
| **nullroutev6**     | IPv6 address to forward blocked queries to                                                                                     |
| **accesslist**      | Which clients allowed to make queries                                                                                          |
| **timeout**         | Network timeout for each dns lookups in duration Default: 2s                                                                   |
| **hostsfile**       | Enables serving zone data from a hosts file, left blank for disabled                                                           |
| **expire**          | Default error cache TTL for in seconds Default: 600                                                                            |
| **cachesize**       | Cache size (total records in cache) Default: 256000                                                                            |
| **maxdepth**        | Maximum iteration depth for a query Default: 30                                                                                |
| **ratelimit**       | Query based ratelimit per second, 0 for disabled. Default: 0                                                                   |
| **clientratelimit** | Client ip address based ratelimit per minute, 0 for disable. if client support edns cookie no limit. Default: 0                |
| **blocklist**       | Manual blocklist entries                                                                                                       |
| **whitelist**       | Manual whitelist entries                                                                                                       |
| **cookiesecret**    | DNS cookie secret (RFC 7873), if no cookiesecret set, it will be generate automatically                                        |
| **nsid**            | DNS server identifier (RFC 5001), it's useful while operating multiple sdns. left blank for disabled                           |
| **chaos**           | Enable to answer version.server, version.bind, hostname.bind and id.server chaos txt queries.                                  |
| **qname_min_level** | Qname minimize level.If higher, it can be more complex and impact the response performance. If set 0, qname min will be disable|
| **emptyzones**      | Empty zones return answer for RFC 1918 zones. Please see http://as112.net/ for details.                                        |

## Plugins Configuration

You can add your own plugins to sdns. The plugin order is very important. The orders of plugins and middlewares will effect each other. Config keys should be string and values can be anything. The plugins will load before cache middleware with their orders.

Plugin interface is very simple. For more information, you can look the [example plugin](https://github.com/semihalev/sdnsexampleplugin)

### Example Config
```toml
[plugins]
     [plugins.example]
     path = "/myplugindir/exampleplugin.so"
     config = {key_1 = "value_1",intkey = 2,boolkey = true,keyN = "nnn"}
     [plugins.another]
     path = "/myplugindir/anotherplugin.so"
```

## Server Configuration Checklist

-   Increase file descriptor on your server

## Features

-   Linux/BSD/Darwin/Windows supported
-   DNS RFC compatibility
-   DNS lookups within listed ipv4 and ipv6 auth servers
-   DNS caching
-   DNSSEC validation
-   DNS over TLS support (DoT)
-   DNS over HTTPS support (DoH)
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
-   [ ] Automated Updates DNSSEC Trust Anchors described at RFC 5011
-   [ ] DNS64 DNS Extensions for NAT from IPv6 Clients to IPv4 Servers described at RFC 6147

## Performance

These benchmarks were run on a server with Intel Xeon E5-2609 v4 cpu and 32GB memory on localhost. DNS-OARC dnsperf (https://www.dns-oarc.net/tools/dnsperf) tool used with 50.000 sample query data.

| Resolver | RESPONSE | NOERROR | SERVFAIL | NXDOMAIN | RUN TIME  |  QPS  |
| ------   | -------- | ------- | -------- | -------- | --------- | ----- |
| SDNS     | %99,88   | %73,60  | %1,36    | %25,04   | 101s480ms | 492/s |
| PowerDNS | %99,59   | %72,76  | %1,40    | %25,84   | 123s930ms | 402/s |
| Bind     | %99,40   | %72,98  | %1,09    | %25,94   | 115s150ms | 431/s |
| Unbound  | %99,14   | %73,19  | %0,90    | %25,90   | 178s80ms  | 278/s |

<img src="https://github.com/semihalev/sdns/blob/master/benchmarks.png?raw=true">

## Who Used

_CubeDNS_ public open resolver project using sdns on multi location. The project supported both UDP and TCP also DoT and DoH.

| Proto  | Servers                                  |
| ------ | ---------------------------------------- |
| IPv4   | 195.244.44.44, 195.244.44.45             |
| IPv6   | 2a0a:be80::cbe:4444, 2a0a:be80::cbe:4445 |
| DoH    | https://cubedns.com/dns-query            |

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## :hearts: Made With

-   [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library

## Inspired by 
-   [coredns/coredns](https://github.com/coredns/coredns)
-   [looterz/grimd](https://github.com/looterz/grimd)

## License

[MIT](https://github.com/semihalev/sdns/blob/master/LICENSE)
