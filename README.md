# SDNS

[![Travis](https://img.shields.io/travis/semihalev/sdns.svg?style=flat-square)](https://travis-ci.org/semihalev/sdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square)](https://goreportcard.com/report/github.com/semihalev/sdns)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/semihalev/sdns)
[![codecov](https://codecov.io/gh/semihalev/sdns/branch/master/graph/badge.svg)](https://codecov.io/gh/semihalev/sdns)

:dizzy: Lightweight, fast recursive dns server with dnssec support

Based on [kenshinx/godns](https://github.com/kenshinx/godns), [looterz/grimd](https://github.com/looterz/grimd)

<img src="https://github.com/semihalev/sdns/blob/master/logo.png?raw=true" width="350">

## Installation

```shell
go get github.com/semihalev/sdns
```

or

[download](https://github.com/semihalev/sdns/releases)

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
|--------|----------------------------------------------------------------|
| config | Location of the config file, if not found it will be generated |

## Configs

| Key             | Desc                                                                                                                           |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------|
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
| api             | Address to bind to for the http API server disable for left blank                                                              |
| nullroute       | IPv4 address to forward blocked queries to                                                                                     |
| nullroutev6     | IPv6 address to forward blocked queries to                                                                                     |
| accesslist      | Which clients allowed to make queries                                                                                          |
| timeout         | Query timeout for dns lookups in duration Default: 5s                                                                          |
| connecttimeout  | Connect timeout for dns lookups in duration Default: 2s                                                                        |
| expire          | Default cache TTL in seconds Default: 600                                                                                      |
| cachesize       | Cache size (total records in cache) Default: 256000                                                                            |
| maxdepth        | Maximum recursion depth for nameservers. Default: 30                                                                           |
| ratelimit       | Query based ratelimit per second, 0 for disable. Default: 30                                                                   |
| blocklist       | Manual blocklist entries                                                                                                       |
| whitelist       | Manual whitelist entries                                                                                                       |

## Server Configuration Checklist

* Increase file descriptor on your server

## Features

* Linux/BSD/Darwin/Windows supported
* DNS RFC compatibility
* DNS lookups within listed servers
* DNS caching
* DNSSEC validation
* DNS over TLS support
* DNS over HTTPS support
* RTT priority within listed servers
* Basic IPv6 support (client<->server)
* Query based ratelimit
* Access list
* Black-hole internet advertisements and malware servers
* HTTP API support
* Outbound IP selection

## TODO

* [x] More tests
* [x] Try lookup NS address better way
* [x] DNS over TLS support
* [x] DNS over HTTPS support
* [x] Full DNSSEC support
* [x] RTT optimization
* [x] Access list
* [x] Periodic priming queries described at RFC 8109
* [ ] Automated Updates DNSSEC Trust Anchors described at RFC 5011
* [ ] Full IPv6 support (server<->server communication)

## Made With

* [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library
