# SDNS

[![Travis](https://img.shields.io/travis/semihalev/sdns.svg?style=flat-square)](https://travis-ci.org/semihalev/sdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square)](https://goreportcard.com/report/github.com/semihalev/sdns)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/semihalev/sdns)
[![codecov](https://codecov.io/gh/semihalev/sdns/branch/master/graph/badge.svg)](https://codecov.io/gh/semihalev/sdns)
[![GitHub version](https://badge.fury.io/gh/semihalev%2Fsdns.svg)](https://github.com/semihalev/sdns/releases)

:dizzy: Lightweight, fast recursive dns server with dnssec support

Based on [kenshinx/godns](https://github.com/kenshinx/godns), [looterz/grimd](https://github.com/looterz/grimd)

<img src="https://github.com/semihalev/sdns/blob/master/logo.png?raw=true" width="300">

## Installation

```shell
go get github.com/semihalev/sdns
```

or

[download](https://github.com/semihalev/sdns/releases)

or run with [Docker image](https://hub.docker.com/r/c1982/sdns/)

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

## Configs

| Key             | Desc                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| version         | Config version                                                                                                                 |
| blocklists      | List of remote blocklists                                                                                                      |
| blocklistdir    | List of locations to recursively read blocklists from (warning, every file found is assumed to be a hosts-file or domain list) |
| loglevel        | What kind of information should be logged, Log verbosity level crit,error,warn,info,debug                                      |
| bind            | Address to bind to for the DNS server. Default :53                                                                             |
| bindtls         | Address to bind to for the DNS-over-TLS server. Default :853                                                                   |
| binddoh         | Address to bind to for the DNS-over-HTTPS server. Default :8053                                                                |
| tlscertificate  | TLS certificate file path                                                                                                      |
| tlsprivatekey   | TLS private key file path                                                                                                      |
| outboundips     | Outbound ip addresses, if you set multiple, sdns can use random outbound ip address                                            |
| rootservers     | DNS Root servers                                                                                                               |
| root6servers    | DNS Root IPv6 servers                                                                                                          |
| rootkeys        | DNS Root keys for dnssec                                                                                                       |
| fallbackservers | Fallback servers IP addresses                                                                                                  |
| api             | Address to bind to for the http API server, leave blank to disable                                                             |
| nullroute       | IPv4 address to forward blocked queries to                                                                                     |
| nullroutev6     | IPv6 address to forward blocked queries to                                                                                     |
| accesslist      | Which clients allowed to make queries                                                                                          |
| timeout         | Query timeout for dns lookups in duration Default: 5s                                                                          |
| connecttimeout  | Connect timeout for dns lookups in duration Default: 2s                                                                        |
| hostsfile       | Enables serving zone data from a hosts file, leave blank to disable                                                            |
| expire          | Default cache TTL in seconds Default: 600                                                                                      |
| cachesize       | Cache size (total records in cache) Default: 256000                                                                            |
| maxdepth        | Maximum recursion depth for nameservers. Default: 30                                                                           |
| ratelimit       | Query based ratelimit per second, 0 for disable. Default: 0                                                                    |
| clientratelimit | Client ip address based ratelimit per minute, 0 for disable. if client support edns cookie no limit. Default: 0                |
| blocklist       | Manual blocklist entries                                                                                                       |
| whitelist       | Manual whitelist entries                                                                                                       |

## Server Configuration Checklist

-   Increase file descriptor on your server

## Features

-   Linux/BSD/Darwin/Windows supported
-   DNS RFC compatibility
-   DNS lookups within listed servers
-   DNS caching
-   DNSSEC validation
-   DNS over TLS support
-   DNS over HTTPS support
-   Middleware Support
-   RTT priority within listed servers
-   EDNS Cookie Support (client&lt;->server)
-   Basic IPv6 support (client&lt;->server)
-   Query based ratelimit
-   IP based ratelimit
-   Access list
-   Prometheus basic query metrics
-   Black-hole internet advertisements and malware servers
-   HTTP API support
-   Outbound IP selection

## TODO

-   [x] More tests
-   [x] Try lookup NS address better way
-   [x] DNS over TLS support
-   [x] DNS over HTTPS support
-   [x] Full DNSSEC support
-   [x] RTT optimization
-   [x] Access list
-   [x] Periodic priming queries described at RFC 8109
-   [ ] Automated Updates DNSSEC Trust Anchors described at RFC 5011
-   [ ] Full IPv6 support (server&lt;->server communication)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Made With

-   [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library

## License

[MIT](https://github.com/semihalev/sdns/blob/master/LICENSE)
