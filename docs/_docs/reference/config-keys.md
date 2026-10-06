---
layout: doc
title: Configuration key index
category: Reference
order: 2
description: Every setting, its default, what an unset key means, and where it is explained.
---

The Default column is the value the generated configuration file ships. Two
markers stand in for a value:

- *(commented)*: the generated file carries the key commented out. That does
  not always mean off; the Meaning column says what applies until you set it,
  a derived or built-in value for some keys.
- *(not generated)*: the generated file does not carry the key at all, and the
  value shown is what sdns applies at load.

A key you leave out of your own file takes its zero value (`false`, `0` or
empty), with the meaning the row gives that value, unless the row says
otherwise. Many keys ship a value other than their zero value, so leaving one
out is not the same as keeping the default. The ones where that is easy to
miss:

- `accesslist` omitted, or `[]`, allows every client.
- `api` omitted disables the API; `prefetch` omitted turns prefetching off;
  `chaos` omitted turns the CHAOS answers off.
- `expire` omitted leaves only the fixed caps of 24 hours and 3 hours.
- `cachesize` omitted gives 1024 answers.
- `reflexblockmode` omitted only logs, at debug level.
- `domainmetricslimit` omitted tracks every domain, without a limit.
- `ecs.cache_limit_ttl` omitted leaves scope-keyed entries uncapped.
- `directory` and `rootservers` are refused when omitted, and so is `rootkeys`
  while sdns validates recursively.

`dnssec` (`"on"`), `rfc8198` and `rfc9520` (`true`) and `loglevel` (`"info"`)
take the shipped value when omitted.

The page that explains each top-level key is listed under
[Where each key is explained](#where-each-key-is-explained).

## Top level

| Key | Default | Meaning |
|---|---|---|
| `version` | `"1.9.0"` | The configuration version of the sdns that generated the file; a different value only logs a warning at startup |
| `directory` | `"db"` | Writable state: `trust-anchor.db`, `trust-anchor-tombstones.db`, `root.zone` with `hyperlocal_root`, `cache.snapshot` with `cache_persist`, and the downloaded blocklists in `blacklists/` |
| `bind` | `":53"` | UDP and TCP listener; one `"host:port"` or a list. Unset or empty still listens on `":53"` |
| `bindtls` | *(commented)* | DoT listener, usually `":853"`; one address or a list; not started while unset |
| `binddoh` | *(commented)* | DoH listener, usually `":443"`; one address or a list; also opens UDP on the same address for HTTP/3, so it cannot share a port with `binddoq`; not started while unset |
| `binddoq` | *(commented)* | DoQ listener, usually `":853"`; one address or a list; not started while unset |
| `tlscertificate` | *(commented)* | PEM certificate; required when `bindtls`, `binddoh` or `binddoq` is set, unused otherwise; reloaded on `SIGHUP` and when the certificate file's modification time moves forward (a key change alone needs `SIGHUP`) |
| `tlsprivatekey` | *(commented)* | PEM private key; required with `tlscertificate` |
| `outboundips` | `[]` | IPv4 source addresses for recursive queries to authoritative servers (not forwarders, forward zones or fallback servers); each must be an address of this machine |
| `outboundip6s` | `[]` | IPv6 source addresses for recursive queries to authoritative servers; each must be an address of this machine; used only with IPv6 access on |
| `rootservers` | full list | IPv4 root servers; refused when no root server is configured |
| `root6servers` | full list | IPv6 root servers |
| `dnssec` | `"on"` | `"on"` or `"off"`; omitted means `"on"` |
| `rootkeys` | published KSKs | Root trust anchors in DNSKEY presentation format; refused when empty while sdns validates recursively or with `hyperlocal_root` |
| `rfc8198` | `true` | Aggressive NSEC/NSEC3 reuse; kill switch only, omitted means `true`. Off regardless with `dnssec = "off"` or `forwarderservers` set |
| `rfc9520` | `true` | Cache resolution failures; kill switch only, omitted means `true` |
| `serve_stale` | `false` | Serve expired answers when resolution fails |
| `serve_stale_max_ttl` | `"24h"` | Measured from TTL expiry; `"0"` removes this bound; omitted means `"24h"` |
| `serve_stale_mode` | `"failure"` | `"failure"` serves stale only after resolution fails; `"immediate"` serves it at once and refreshes in the background, needs `serve_stale = true` (`sdns -t` refuses it otherwise) |
| `fallbackservers` | `[]` | Tried after a SERVFAIL from normal resolution |
| `forwarderservers` | `[]` | Set to make sdns a forwarder instead of a recursor. Each entry is `"ip:port"`, `"tls://ip:port"`, `"tls://ip:port#name"` (the certificate must be valid for `name`, a host name, not an IP address; RFC 8310) or an `"https://"` DoH URL. See [Views and forwarding]({{ '/docs/features/views/' | relative_url }}) |
| `api` | `"127.0.0.1:8080"` | HTTP API and metrics; `""` or omitted disables |
| `bearertoken` | *(commented)* | Requires `Authorization: Bearer` on API requests |
| `loglevel` | `"info"` | `error`, `warn`, `info`, `debug`; omitted means `"info"` |
| `accesslog` | *(commented)* | CLF query log path; empty disables |
| `blocklists` | `[]` | Blocklist URLs, downloaded once at startup; restart to refresh |
| `blocklistdir` | `""` | Deprecated; created under `directory` |
| `blocklist` | `[]` | Manually blocked names |
| `whitelist` | `[]` | Names the blocklist never blocks; RPZ policy still applies to them |
| `nullroute` | `"0.0.0.0"` | Answer for blocked A queries |
| `nullroutev6` | `"::0"` | Answer for blocked AAAA queries |
| `block_aaaa` | `false` | Suppress normal client IN/AAAA queries with unsigned NODATA, ahead of local answers, cache and DNS64; internal resolution and IPv6 transports are unaffected |
| `accesslist` | `["0.0.0.0/0", "::0/0"]` | Clients allowed to query, narrow this; `[]` or omitted allows every client |
| `hostsfile` | `""` | Serve entries from a hosts file |
| `timeout` | `"2s"` | Per upstream query; `"0"` or omitted means `"2s"` |
| `querytimeout` | `"10s"` | For one whole client query; `"0"` or omitted means `"10s"` |
| `expire` | `600` | Seconds; lifetime cap of RFC 8020 subtree cuts and RFC 8198 proofs (fixed caps of 24 hours and 3 hours sit above it; `0` or omitted leaves only those). Neither mechanism runs with `dnssec = "off"` or `forwarderservers` set. Resolution failures use `failure_cache_*` |
| `cachesize` | `256000` | Cached answers (messages), not records; `0` or omitted means 1024, 1 to 1023 is refused. Adds `cachesize / 16` RFC 8020 cut entries and `cachesize / 32` RFC 8198 proof entries |
| `cache_persist` | `false` | Save the answer cache at a clean shutdown and restore it at startup |
| `prefetch` | `10` | Refresh threshold percent; `0` or omitted disables; 10 to 90, other values are rejected |
| `maxdepth` | `30` | Recursion depth ceiling; `0` or omitted means 30 |
| `maxconcurrentqueries` | `10000` *(not generated)* | Queries the resolver may have outstanding to authoritative servers at once; separate from the ingress bounds; `0` means 10000. See [Server and listeners]({{ '/docs/configuration/server/' | relative_url }}#server-resources) |
| `ipv6access` | probed *(not generated)* | Forced on when the startup IPv6-transit probe succeeds; set `true` to override a probe that misjudges the network |
| `cookiesecret` | random *(not generated)* | DNS cookie secret (RFC 7873, RFC 9018); 32 hex digits are the SipHash key itself, which is what sharing cookies with other DNS software in an anycast set needs; any other text is hashed to a key, the same one for the same text, so sdns servers sharing one string share cookies; empty generates 16 random bytes at startup, so cookies change on every restart. See [Access control]({{ '/docs/configuration/access-control/' | relative_url }}#cookie-secret) |
| `ingressworkers` | *(commented)* | Handler workers of the plain DNS UDP listener only; derived at startup while unset |
| `ingressqueue` | *(commented)* | Ready-queue depth of the plain DNS UDP listener only; 64 while unset |
| `ingresstcpconns` | *(commented)* | TCP/DoT connection cap; derived at startup while unset |
| `memorytrim` | *(commented)* | Return burst memory to the OS after about two minutes idle; off while unset |
| `ratelimit` | `0` | Cache hits per second for each of 997 shared buckets that cached answers hash into (every ECS-scoped answer shares one bucket); a hit over the rate is dropped without a reply; misses are not limited; `0` disables |
| `clientratelimit` | `0` | Queries per minute per client address; loopback clients exempt; `0` disables |
| `domainmetrics` | `false` | Per-domain query counters |
| `domainmetricslimit` | `1000` | Domains tracked; `0` or omitted is unlimited |
| `nsid` | `""` | Server identifier (RFC 5001) |
| `chaos` | `true` | Answer `version.bind` and friends in the CHAOS class; omitted means `false` |
| `qname_max_minimize_count` | `10` | Minimised queries per lookup; `0` disables; omitted falls back to `qname_min_level`, and so disables when that is unset too; negative is refused |
| `qname_minimize_one_label` | `4` | How many add a single label; `0` selects 4; while minimisation is on, negative or larger than `qname_max_minimize_count` is refused |
| `qname_min_level` | *(not generated)* | Superseded; read only when the above is unset |
| `hyperlocal_root` | `false` | Serve the root from a verified local copy |
| `hyperlocal_root_sources` | *(commented)* | Override the transfer hosts; the built-in list applies while unset |
| `emptyzones` | `[]` | Locally served empty zones (RFC 6303); empty uses the built-in set |
| `tcpkeepalive` | `false` | Pool TCP connections to root and TLD servers |
| `roottcptimeout` | `"5s"` | Idle timeout for root connections; `"0"` or omitted means `"5s"` |
| `tldtcptimeout` | `"10s"` | Idle timeout for TLD connections; `"0"` or omitted means `"10s"` |
| `tcpmaxconnections` | `100` | Pooled connections; `0` uses 100 |
| `reflexenabled` | `false` | Amplification/reflection detection |
| `reflexblockmode` | `true` | `false`, or omitted, logs without blocking, at debug level only |
| `reflexlearningmode` | `false` | `true` logs without blocking, for tuning |
| `reflexthreshold` | *(commented)* | Suspicion score 0.0 to 1.0; 0.7 applies while unset |
| `dnstapsocket` | *(commented)* | Unix socket for binary query logging; dnstap is off while unset |
| `dnstapidentity` | *(commented)* | Server identity in dnstap frames; the host name while unset |
| `dnstapversion` | *(commented)* | Version string in dnstap frames; `"sdns"` while unset |
| `dnstaplogqueries` | *(commented)* | Log queries; off while unset |
| `dnstaplogresponses` | *(commented)* | Log responses; off while unset |
| `dnstapflushinterval` | *(commented)* | Buffer flush interval, seconds; 5 while unset |

### Where each key is explained

- [Configuration overview]({{ '/docs/configuration/overview/' | relative_url }}):
  `version`, `directory`.
- [Server and listeners]({{ '/docs/configuration/server/' | relative_url }}):
  `bind`, `bindtls`, `binddoh`, `binddoq`, `tlscertificate`, `tlsprivatekey`,
  `outboundips`, `outboundip6s`, `api`, `bearertoken`, `loglevel`,
  `accesslog`, the `dnstap*` keys, `nsid`, `chaos`, `ingressworkers`,
  `ingressqueue`, `ingresstcpconns`, `memorytrim`, `maxconcurrentqueries`.
- [Resolution and DNSSEC]({{ '/docs/configuration/resolution/' | relative_url }}):
  `rootservers`, `root6servers`, `ipv6access`, `dnssec`, `rootkeys`,
  `rfc8198`, `rfc9520`, the `qname_*` keys, `timeout`, `querytimeout`,
  `maxdepth`, `tcpkeepalive`, `roottcptimeout`, `tldtcptimeout`,
  `tcpmaxconnections`, `emptyzones`.
- [Cache and TTLs]({{ '/docs/configuration/cache/' | relative_url }}):
  `cachesize`, `prefetch`, `cache_persist`, `serve_stale`,
  `serve_stale_max_ttl`, `serve_stale_mode`, `expire`.
- [Access control and blocking]({{ '/docs/configuration/access-control/' | relative_url }}):
  `accesslist`, `ratelimit`, `clientratelimit`, `cookiesecret`, the `reflex*`
  keys, `blocklists`, `blocklist`, `whitelist`, `nullroute`, `nullroutev6`,
  `blocklistdir`, `block_aaaa`, `hostsfile`, `domainmetrics`, `domainmetricslimit`.
- [Views and forwarding]({{ '/docs/features/views/' | relative_url }}):
  `fallbackservers`, `forwarderservers`.
- [Local root zone]({{ '/docs/features/hyperlocal-root/' | relative_url }}):
  `hyperlocal_root`, `hyperlocal_root_sources`.

## `[[views]]` *(commented)*

| Key | Meaning |
|---|---|
| `zone` | Name for the view |
| `mode` | `overlay` (default, also omitted or empty) or `authoritative-owner`; the latter selects an IN owner before type and answers missing types locally |
| `networks` | Client CIDRs this view applies to |
| `answers` | Zone-file lines; wildcards allowed |

See [Views and forwarding]({{ '/docs/features/views/' | relative_url }}).

## `[[forward_zone]]` *(commented)*

| Key | Meaning |
|---|---|
| `name` | Zone to forward; required |
| `servers` | Recursive upstreams; at least one required. Same forms as `forwarderservers`: `"ip:port"`, `"tls://ip:port"`, `"tls://ip:port#name"` or an `"https://"` DoH URL |

See [Views and forwarding]({{ '/docs/features/views/' | relative_url }}).

## `[rpz]` *(commented)*

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch |
| `mode` | `"shadow"` | `shadow` counts, `enforce` applies |

### `[[rpz.zone]]`

| Key | Meaning |
|---|---|
| `name` | Label for the zone, used in metrics |
| `file` | Path to a zone file; mutually exclusive with `source` |
| `source` | `host:port` of an AXFR primary |
| `origin` | Zone apex; required for relative feeds and for AXFR |
| `tsig_key` | `name:algorithm:base64-secret` |
| `policy` | `given`, `passthru`, `nxdomain`, `nodata`, `drop`, `tcp-only`, `cname`, `disabled` |
| `cname` | Rewrite target; required when `policy = "cname"` |

See [Response Policy Zones]({{ '/docs/features/rpz/' | relative_url }}).

## `[kubernetes]`

| Key | Default | Note |
|---|---|---|
| `enabled` | `false` | |
| `cluster_domain` | `"cluster.local"` | |
| `kubeconfig` | *(commented)* | |
| `demo` | `false` | **Never enable in production**, answers synthesised names that look real, and works independently of `enabled` |
| `killer_mode` | *(not generated)* | Deprecated and ignored; still parsed so old files load |
| `ttl.service` | `30` | `0` or omitted means 30 |
| `ttl.pod` | `30` | `0` or omitted means 30 |
| `ttl.srv` | `30` | `0` or omitted means 30 |
| `ttl.ptr` | `30` | `0` or omitted means 30 |

## `[ddr]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Advertise the encrypted listeners at `_dns.resolver.arpa` (RFC 9462) |
| `name` | `""` | Designated resolver name; empty takes the certificate's first DNS name |
| `doh_port` | `0` | The port a reverse proxy publishes DoH on; 0 takes the DoH listener's own. Required to advertise a DoH listener bound to loopback |
| `doh_alpn` | `[]` | The HTTP versions the proxy serves, `"h2"` and/or `"h3"`; empty takes the listener's own |
| `ipv4hint` | `[]` | IPv4 addresses clients reach the resolver at, carried as hints; empty carries none |
| `ipv6hint` | `[]` | IPv6 addresses clients reach the resolver at, carried as hints; empty carries none |

See [Encrypted transports]({{ '/docs/features/encrypted-transports/' | relative_url }}).

## `[dns64]`

| Key | Default |
|---|---|
| `enabled` | `false` |
| `prefixes` | `["64:ff9b::/96"]` |
| `client_networks` | `[]` (all clients) |
| `exclude_zones` | `[]` |
| `exclude_aaaa_networks` | `["::ffff:0:0/96"]` |
| `exclude_a_networks` | IANA special-purpose list |

## `[ecs]`

| Key | Default | Note |
|---|---|---|
| `enabled` | `false` | |
| `forward_v4` | `24` | `0` selects 24 |
| `forward_v6` | `56` | `0` selects 56 |
| `client_networks` | `[]` (all clients) | |
| `cache_limit_ttl` | `"5m"` | TTL ceiling on scope-keyed entries; `0` or omitted leaves them uncapped |
| `min_scope_v4` | `24` | Scope floor for the cache key; `0` uses `forward_v4` |
| `min_scope_v6` | `56` | Scope floor for the cache key; `0` uses `forward_v6` |

## `[recursion_firewall]`

| Key | Default |
|---|---|
| `mode` | `"shadow"` |
| `max_outbound_queries` | `128` |
| `max_internal_queries` | `32` |
| `max_dnskey_candidates` | `4` |
| `max_rrset_signature_checks` | `8` |
| `max_signature_checks` | `32` |
| `max_ds_digests` | `32` |
| `max_nsec3_hashes` | `32` |
| `max_concurrent_crypto` | `32` |
| `failure_cache_size` | `4096` |
| `failure_cache_min_ttl` | `"5s"` |
| `failure_cache_max_ttl` | `"5m"` |

The `failure_cache_*` settings are active regardless of `mode`.

## `[plugins]` *(commented)*

Each block under `[plugins]` names one plugin; the block's own name is the
label, and the keys inside it are:

| Key | Meaning |
|---|---|
| `path` | Path to the `.so` built with `-buildmode=plugin` |
| `config` | Inline table the plugin reads from the configuration its `New` receives, as `cfg.Plugins[name].Config` |

```toml
[plugins]
    [plugins.example]
    path   = "exampleplugin.so"
    config = {key_1 = "value_1", key_2 = 2, key_3 = true}
```

Plugins run ahead of the cache, in no defined order among themselves. See
[Plugins]({{ '/docs/development/plugins/' | relative_url }}).
