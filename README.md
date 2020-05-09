[![Travis](https://img.shields.io/travis/semihalev/sdns.svg?style=flat-square)](https://travis-ci.org/semihalev/sdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square)](https://goreportcard.com/report/github.com/semihalev/sdns)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/semihalev/sdns)
[![codecov](https://codecov.io/gh/semihalev/sdns/branch/master/graph/badge.svg)](https://codecov.io/gh/semihalev/sdns)
[![GitHub version](https://badge.fury.io/gh/semihalev%2Fsdns.svg)](https://github.com/semihalev/sdns/releases)

## :rocket: Privacy important, fast recursive dns resolver server with dnssec support

<img src="https://github.com/semihalev/sdns/blob/master/logo.png?raw=true" width="250">

## Installation

```shell
go get github.com/semihalev/sdns
```

or

[download](https://github.com/semihalev/sdns/releases)

or run with [Docker image](https://github.com/semihalev/sdns/packages)

```shell
docker run -d --name sdns -p 53:53 -p 53:53/udp -p 853:853 -p 8053:8053 -p 8080:8080 sdns
```

-   Port 53 DNS server
-   Port 853 DNS-over-TLS server
-   Port 8053 DNS-over-HTTPS server
-   Port 8080 HTTP API

## Building

```shell
$ go build
```

## Testing

```shell
$ make test
```

## Flags

| Flag   | Desc                                                           |
| ------ | -------------------------------------------------------------- |
| config | Location of the config file, if not found it will be generated |

## Debug Environment

```shell
$ export SDNS_DEBUGNS=true && export SDNS_PPROF=true && ./sdns
```

SDNS_DEBUGNS enviroment useful when you want to check authoritive servers RTT times. 
Usage: send HINFO query for zones.

Example Output:
```shell
$ dig hinfo example.com

; <<>> DiG 9.10.6 <<>> hinfo example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45590
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1400
;; QUESTION SECTION:
;example.com.			IN	HINFO

;; AUTHORITY SECTION:
example.com.		5	IN	HINFO	"ns" "IPv4:199.43.135.53:53 rtt:145ms health:[GOOD]"
example.com.		5	IN	HINFO	"ns" "IPv4:199.43.133.53:53 rtt:143ms health:[GOOD]"
example.com.		5	IN	HINFO	"ns" "IPv6:[2001:500:8d::53]:53 rtt:5s health:[POOR]"
example.com.		5	IN	HINFO	"ns" "IPv6:[2001:500:8f::53]:53 rtt:5s health:[POOR]"
```

## Configuration (v1.0.0)

| Key                 | Desc                                                                                                                           |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **version**         | Config version                                                                                                                 |
| **blocklists**      | List of remote blocklists                                                                                                      |
| **blocklistdir**    | List of locations to recursively read blocklists from (warning, every file found is assumed to be a hosts-file or domain list) |
| **loglevel**        | What kind of information should be logged, Log verbosity level crit,error,warn,info,debug                                      |
| **accesslog**       | The location of access log file, left blank for disabled. SDNS uses Common Log Format by default.                              |
| **bind**            | Address to bind to for the DNS server. Default :53                                                                             |
| **bindtls**         | Address to bind to for the DNS-over-TLS server. Default :853                                                                   |
| **binddoh**         | Address to bind to for the DNS-over-HTTPS server. Default :8053                                                                |
| **tlscertificate**  | TLS certificate file path                                                                                                      |
| **tlsprivatekey**   | TLS private key file path                                                                                                      |
| **outboundips**     | Outbound ipv4 addresses, if you set multiple, sdns can use random outbound ipv4 address                                        |
| **outboundip6s**    | Outbound ipv6 addresses, if you set multiple, sdns can use random outbound ipv6 address                                        |
| **rootservers**     | DNS Root IPv4 servers                                                                                                          |
| **root6servers**    | DNS Root IPv6 servers                                                                                                          |
| **rootkeys**        | DNS Root keys for dnssec                                                                                                       |
| **fallbackservers** | Failover resolver ipv4 or ipv6 addresses with port, left blank for disabled: Example: "1.1.1.1:53"                             |
| **api**             | Address to bind to for the http API server, left blank for disabled                                                            |
| **nullroute**       | IPv4 address to forward blocked queries to                                                                                     |
| **nullroutev6**     | IPv6 address to forward blocked queries to                                                                                     |
| **accesslist**      | Which clients allowed to make queries                                                                                          |
| **timeout**         | Query timeout for each dns lookups in duration Default: 2s                                                                     |
| **hostsfile**       | Enables serving zone data from a hosts file, left blank for disabled                                                           |
| **expire**          | Default cache TTL in seconds Default: 600                                                                                      |
| **cachesize**       | Cache size (total records in cache) Default: 256000                                                                            |
| **maxdepth**        | Maximum recursion depth for authservers. Default: 30                                                                           |
| **ratelimit**       | Query based ratelimit per second, 0 for disabled. Default: 0                                                                   |
| **clientratelimit** | Client ip address based ratelimit per minute, 0 for disable. if client support edns cookie no limit. Default: 0                |
| **blocklist**       | Manual blocklist entries                                                                                                       |
| **whitelist**       | Manual whitelist entries                                                                                                       |
| **cookiesecret**    | DNS cookie secret (RFC 7873), if no cookiesecret set, it will be generate automatically                                        |
| **nsid**            | DNS server identifier (RFC 5001), it's useful while operating multiple sdns. left blank for disabled                           |
| **chaos**           | Enable to answer version.server, version.bind, hostname.bind and id.server chaos txt queries.                                  |

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
-   Cache Purge API and queru support
-   Answered chaos txt queries for version.bind and hostname.bind

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
-   [ ] Automated Updates DNSSEC Trust Anchors described at RFC 5011
-   [ ] DNS64 DNS Extensions for NAT from IPv6 Clients to IPv4 Servers described at RFC 6147

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
