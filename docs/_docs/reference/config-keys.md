---
layout: doc
title: Configuration key index
category: Reference
order: 2
description: Every setting, its default, and where it is explained.
---

Defaults are what the generated configuration file ships. A key marked
*(commented)* is present in the generated file but commented out, meaning the
feature is off until you uncomment it.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `version` | `"1.8.2"` | Configuration schema version, not the sdns version |
| `directory` | `"db"` | Writable state: trust anchors, blocklists, local root copy |
| `bind` | `":53"` | UDP and TCP listener |
| `bindtls` | *(commented)* | DoT listener, usually `":853"` |
| `binddoh` | *(commented)* | DoH listener, usually `":443"` |
| `binddoq` | *(commented)* | DoQ listener, usually `":853"` |
| `tlscertificate` | *(commented)* | PEM certificate, required for DoT/DoH/DoQ |
| `tlsprivatekey` | *(commented)* | PEM private key |
| `outboundips` | `[]` | IPv4 source addresses for outbound queries |
| `outboundip6s` | `[]` | IPv6 source addresses for outbound queries |
| `rootservers` | full list | IPv4 root servers |
| `root6servers` | full list | IPv6 root servers |
| `dnssec` | `"on"` | `"on"` or `"off"` |
| `rootkeys` | published KSKs | Root trust anchors in DNSKEY presentation format |
| `rfc8198` | `true` | Aggressive NSEC/NSEC3 reuse; kill switch only |
| `rfc9520` | `true` | Cache resolution failures; kill switch only |
| `serve_stale` | `false` | Serve expired answers when resolution fails |
| `serve_stale_max_ttl` | `"24h"` | Measured from TTL expiry; `"0"` removes this bound |
| `fallbackservers` | `[]` | Tried after a SERVFAIL from normal resolution |
| `forwarderservers` | `[]` | Set to make sdns a forwarder instead of a recursor |
| `api` | `"127.0.0.1:8080"` | HTTP API and metrics; `""` disables |
| `bearertoken` | *(commented)* | Requires `Authorization: Bearer` on API requests |
| `loglevel` | `"info"` | `error`, `warn`, `info`, `debug` |
| `accesslog` | *(commented)* | CLF query log path; empty disables |
| `blocklists` | `[]` | Blocklist URLs, downloaded periodically |
| `blocklistdir` | `""` | Deprecated; created under `directory` |
| `blocklist` | `[]` | Manually blocked names |
| `whitelist` | `[]` | Names that bypass all blocking |
| `nullroute` | `"0.0.0.0"` | Answer for blocked A queries |
| `nullroutev6` | `"::0"` | Answer for blocked AAAA queries |
| `accesslist` | `["0.0.0.0/0", "::0/0"]` | Clients allowed to query — narrow this |
| `hostsfile` | `""` | Serve entries from a hosts file |
| `timeout` | `"2s"` | Per upstream query |
| `querytimeout` | `"10s"` | For one whole client query |
| `expire` | `600` | Legacy error-cache ceiling; superseded by `failure_cache_*` |
| `cachesize` | `256000` | Cached records |
| `prefetch` | `10` | Refresh threshold percent; `0`, or 10–90 — other values are rejected |
| `maxdepth` | `30` | Recursion depth ceiling |
| `maxconcurrentqueries` | `10000` | Upstream fan-out semaphore; separate from the ingress bounds |
| `ipv6access` | probed | Forced on when the startup IPv6-transit probe succeeds; set `true` to override a probe that misjudges the network |
| `cookiesecret` | generated | RFC 7873 cookie secret; 16 random bytes when empty |
| `ingressworkers` | *(commented)* | Handler workers per listener; derived at startup |
| `ingressqueue` | *(commented)* | Ready-queue depth; derived at startup |
| `ingresstcpconns` | *(commented)* | TCP/DoT connection cap; derived at startup |
| `memorytrim` | *(commented)* | Return burst memory to the OS after a long idle |
| `ratelimit` | `0` | Queries per second, whole server; `0` disables |
| `clientratelimit` | `0` | Queries per minute per client; `0` disables |
| `domainmetrics` | `false` | Per-domain query counters |
| `domainmetricslimit` | `1000` | Domains tracked; `0` is unlimited |
| `nsid` | `""` | Server identifier (RFC 5001) |
| `chaos` | `true` | Answer `version.bind` and friends in the CHAOS class |
| `qname_max_minimize_count` | `10` | Minimised queries per lookup; `0` disables |
| `qname_minimize_one_label` | `4` | How many add a single label; `0` selects 4 |
| `qname_min_level` | — | Superseded; read only when the above is unset |
| `hyperlocal_root` | `false` | Serve the root from a verified local copy |
| `hyperlocal_root_sources` | *(commented)* | Override the built-in transfer hosts |
| `emptyzones` | `[]` | AS112 zones; empty uses the built-in set |
| `tcpkeepalive` | `false` | Pool TCP connections to root and TLD servers |
| `roottcptimeout` | `"5s"` | Idle timeout for root connections |
| `tldtcptimeout` | `"10s"` | Idle timeout for TLD connections |
| `tcpmaxconnections` | `100` | Pooled connections; `0` uses 100 |
| `reflexenabled` | `false` | Amplification/reflection detection |
| `reflexblockmode` | `true` | `false` logs without blocking |
| `reflexlearningmode` | `false` | `true` logs without blocking, for tuning |
| `reflexthreshold` | *(commented)* | Suspicion score 0.0–1.0; default 0.7 |
| `dnstapsocket` | *(commented)* | Unix socket for binary query logging |
| `dnstapidentity` | *(commented)* | Server identity in dnstap frames |
| `dnstapversion` | *(commented)* | Version string in dnstap frames |
| `dnstaplogqueries` | *(commented)* | Log queries |
| `dnstaplogresponses` | *(commented)* | Log responses |
| `dnstapflushinterval` | *(commented)* | Buffer flush interval, seconds |

## `[[views]]` *(commented)*

| Key | Meaning |
|---|---|
| `zone` | Name for the view |
| `networks` | Client CIDRs this view applies to |
| `answers` | Zone-file lines; wildcards allowed |

See [Views and forwarding]({{ '/docs/features/views/' | relative_url }}).

## `[[forward_zone]]` *(commented)*

| Key | Meaning |
|---|---|
| `name` | Zone to forward; required |
| `servers` | Recursive upstreams; at least one required |

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
| `enabled` | `false` |
| `cluster_domain` | `"cluster.local"` |
| `kubeconfig` | *(commented)* |
| `demo` | `false` | **Never enable in production** — answers synthesised names that look real, and works independently of `enabled` |
| `killer_mode` | — | Deprecated and ignored; still parsed so old files load |
| `ttl.service` | `30` |
| `ttl.pod` | `30` |
| `ttl.srv` | `30` |
| `ttl.ptr` | `30` |

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
| `cache_limit_ttl` | `"5m"` | TTL ceiling on scope-keyed entries |
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

```toml
[plugins]
    [plugins.example]
    path   = "exampleplugin.so"
    config = {key_1 = "value_1", key_2 = 2, key_3 = true}
```

Load order affects processing order. See
[Plugins]({{ '/docs/development/plugins/' | relative_url }}).
