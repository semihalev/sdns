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
working directory and uses it. That generated file carries a comment above
nearly every setting and is the authoritative description of the version you
are running. The few keys it leaves out are in the
[configuration key index]({{ '/docs/reference/config-keys/' | relative_url }}).
These pages describe the same settings with more room for the reasoning behind
them.

## Where settings live

| Page | Covers |
|---|---|
| [Server and listeners]({{ '/docs/configuration/server/' | relative_url }}) | Bind addresses, TLS, outbound source IPs, API, logging |
| [Resolution and DNSSEC]({{ '/docs/configuration/resolution/' | relative_url }}) | Root servers, validation, QNAME minimisation, timeouts, depth |
| [Cache and TTLs]({{ '/docs/configuration/cache/' | relative_url }}) | Cache size, prefetch, stale answers, failure caching |
| [Access control and blocking]({{ '/docs/configuration/access-control/' | relative_url }}) | ACLs, rate limits, blocklists, hosts file, reflection defence |
| [Configuration key index]({{ '/docs/reference/config-keys/' | relative_url }}) | Every key, with its default and what leaving it out means |

Feature blocks (`[rpz]`, `[recursion_firewall]`, `[ecs]`, `[dns64]`, `[ddr]`,
`[kubernetes]`, `[[views]]`, `[[forward_zone]]`, `[plugins]`) are documented on
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

An unknown key, a typo, or a setting an older sdns understood, fails `-t`.
Startup only warns about it. The asymmetry is deliberate: you want the strict
answer when you are checking a change, and you do not want a stale key left in
the file to turn an upgrade into an outage.

## Reloading without a restart

```bash
systemctl reload sdns       # the packaged unit sends SIGHUP
kill -HUP "$(pidof sdns)"   # anywhere else
```

On `SIGHUP` sdns reads the file again and passes it through the same gate as
`sdns -t`, unknown keys included. A file that fails changes nothing: the error
is logged and the running configuration stays. The TLS certificate is reloaded
on the same signal.

These keys take effect without a restart:

| Key | On reload |
|---|---|
| `loglevel` | The new level applies at once |
| `accesslist` | The new list replaces the old one |
| `clientratelimit` | Every client starts the new rate with a full quota |
| `whitelist` | The new list replaces the old one |
| `blocklist` | Added entries are blocked. An entry removed from the file stays blocked, since the API may have saved it too; remove it through the API |
| `[[views]]` | The new views replace the old ones |
| `rpz.mode` | `shadow` and `enforce` switch at once |

Any other changed key needs a restart. It is listed in the reload's log line
on every reload until the server restarts or the file goes back. Either all
the live keys of a reload apply or none do: when one of them is refused, nothing
changes. `dns_config_reloads_total` counts reloads by outcome.

## Upgrading

The file carries no version. One generated before 1.9.1 starts with a
`version` line; it is ignored and can be deleted.

An upgrade loads the file **unchanged**. Nothing is migrated and no backup is
written. Run `sdns -t` against it with the new binary: it reports any key that
no longer exists and any value the new release refuses. A deprecated key logs a
warning at startup. New settings take their defaults until you add them; to see
them, generate a fresh configuration alongside the new binary and compare.

## State directory

```toml
directory = "db"
```

Where sdns keeps what it writes: the RFC 5011 trust anchor database
(`trust-anchor.db` and `trust-anchor-tombstones.db`), downloaded blocklists in
`blacklists/`, the local root copy (`root.zone`, with `hyperlocal_root`) and
the cache snapshot (`cache.snapshot`, with `cache_persist`). A missing
directory is created, but not a missing parent. A relative path is relative to
the process working directory, so a service should give an absolute one. It is
required: a file that leaves it out or empty is refused.

## Durations and sizes

Durations are Go duration strings: `"2s"`, `"10s"`, `"5m"`, `"24h"`. A bare
number where a duration is expected fails to decode when the file is loaded,
rather than being read silently as nanoseconds. A bare `0` is the exception: it
decodes as zero.

Counts are plain integers. Where `0` means something other than zero, usually
"use the built-in default" or "disabled", the generated file says so above the
key, and so do these pages.
