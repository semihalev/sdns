---
layout: doc
title: Overview
category: Configuration
order: 1
description: How the file is organised, and where to find a given setting.
---

Configuration is one TOML file. Most settings are top-level keys; features with
several knobs of their own get a block.

Starting sdns without a configuration file writes `sdns.conf` in the current
working directory and uses it. That generated file carries a comment above every setting and is the
authoritative description of the version you are running. These pages describe
the same settings with more room for the reasoning behind them.

## Where settings live

| Page | Covers |
|---|---|
| [Server and listeners]({{ '/docs/configuration/server/' | relative_url }}) | Bind addresses, TLS, outbound source IPs, API, logging |
| [Resolution and DNSSEC]({{ '/docs/configuration/resolution/' | relative_url }}) | Root servers, validation, QNAME minimisation, timeouts, depth |
| [Cache and TTLs]({{ '/docs/configuration/cache/' | relative_url }}) | Cache size, prefetch, stale answers, failure caching |
| [Access control and blocking]({{ '/docs/configuration/access-control/' | relative_url }}) | ACLs, rate limits, blocklists, hosts file, reflection defence |
| [Configuration key index]({{ '/docs/reference/config-keys/' | relative_url }}) | Every key, alphabetically, with its default |

Feature blocks — `[rpz]`, `[recursion_firewall]`, `[ecs]`, `[dns64]`,
`[kubernetes]`, `[[views]]`, `[[forward_zone]]`, `[plugins]` — are documented on
their own feature pages, since the settings only make sense alongside what the
feature does.

## Validate before you restart

```bash
sdns -t -c /etc/sdns.conf
```

The gate reads the file the way the server will. Addresses are parsed, ports are
resolved through the same lookup a dial uses, CIDRs and enumerations are checked,
TLS files are opened, and policy zones are compiled with the loaders the server
runs. It reports **every** problem it finds, not just the first, and exits 1 if
there was one.

An unknown key — a typo, or a setting an older sdns understood — fails `-t`.
Startup only warns about it. The asymmetry is deliberate: you want the strict
answer when you are checking a change, and you do not want a stale key left in
the file to turn an upgrade into an outage.

## Versioning

```toml
version = "1.8.2"
```

This is the configuration *schema* version, not the sdns version. It only
changes when the schema does.

When sdns finds a version it does not recognise it logs a warning and loads the
file **unchanged**. Nothing is migrated and no backup is written. Generate a
fresh configuration alongside the new binary and carry your settings across by
hand; `sdns -t` reports any key that no longer exists.

## Durations and sizes

Durations are Go duration strings: `"2s"`, `"10s"`, `"5m"`, `"24h"`. A bare
number where a duration is expected is a validation error rather than a silent
interpretation as nanoseconds.

Counts are plain integers. Where `0` means something other than zero — usually
"use the built-in default" or "disabled" — the generated file says so above the
key, and so do these pages.
