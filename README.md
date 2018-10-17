# SDNS

[![Travis](https://img.shields.io/travis/semihalev/sdns.svg?style=flat-square)](https://travis-ci.org/semihalev/sdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square)](https://goreportcard.com/report/github.com/semihalev/sdns)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/semihalev/sdns)
[![codecov](https://codecov.io/gh/semihalev/sdns/branch/master/graph/badge.svg)](https://codecov.io/gh/semihalev/sdns)

Lightweight, fast recursive dns server with dnssec support

Based on [kenshinx/godns](https://github.com/kenshinx/godns), [looterz/grimd](https://github.com/looterz/grimd)

![Logo](https://github.com/semihalev/sdns/blob/master/logo.png?raw=true)

## Installation

```shell
$ go get github.com/semihalev/sdns
```
or

[download](https://github.com/semihalev/sdns/releases)

## Building

```shell
$ go build
```

## Flags

| Flag        | Desc           | 
| ------------- |-------------| 
| config | Location of the config file, if not found it will be generated |

## Server Configuration Checklist

* Increase ulimit on your server

## Features

* Linux/BSD/Windows/Darwin supported
* DNS RFC compatibility
* Concurrent DNS lookups within listed servers
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

- [x] More tests
- [ ] Try lookup NS address better way
- [x] DNS over TLS support
- [x] DNS over HTTPS support
- [x] Full DNSSEC support
- [x] RTT optimization
- [ ] Full IPv6 support (server<->server communication)
- [x] Access list
- [ ] Client based ratelimit

## Made With

* [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library
