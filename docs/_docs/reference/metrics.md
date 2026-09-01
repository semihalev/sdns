---
layout: doc
title: Metrics
category: Reference
order: 3
description: Every metric sdns exports, what it means, and the queries worth building a dashboard from.
---

sdns exports 60 metrics in Prometheus format on the API listener, alongside the
Go runtime and process collectors.

```toml
api = "127.0.0.1:8080"
```

```bash
curl http://127.0.0.1:8080/metrics
```

Names and help strings on this page were read from a running instance, not
from the source, so they are what your scrape will actually see.

## A note on what appears when

Counters with labels materialise on first use. A metric that has never been
incremented — `rpz_action_total` before any policy match, `dns_queries_total`
before the first query — is absent from the scrape rather than present at zero.
Alerts should therefore use `absent()` deliberately or tolerate the gap, and a
dashboard panel that is empty on a fresh process is not necessarily broken.

Feature-gated metrics only register when the feature is configured at all.

---

## Traffic

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_queries_total` | counter | `qtype`, `rcode` | Queries processed |
| `dns_domain_queries_total` | counter | `domain` | Queries per domain — only with `domainmetrics = true` |
| `dns_recovery_panics_total` | counter | | Panics caught by the recovery middleware |

`dns_queries_total` split by `rcode` is the health of the resolver in one line.
`dns_recovery_panics_total` should be zero forever; anything else is a bug worth
reporting.

`dns_domain_queries_total` has unbounded cardinality on a public resolver, which
is what `domainmetricslimit` exists for.

## Cache

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_cache_hits_total` | counter | | Cache hits |
| `dns_cache_misses_total` | counter | | Cache misses |
| `dns_cache_hit_rate` | gauge | | Hit rate percentage |
| `dns_cache_size` | gauge | `type` | Entries currently held |
| `dns_cache_evictions_total` | counter | | Entries dropped under pressure |
| `dns_cache_prefetches_total` | counter | | Background refreshes of popular entries |
| `dns_cache_stale_answers_total` | counter | | Expired positive answers served after a resolution failure |
| `dns_cache_wire_fastpath_total` | counter | `outcome` | Hits attempted on the byte serving path, by outcome |
| `dns_cache_ecs_lookups_total` | counter | `outcome` | ECS-aware lookups, by outcome |
| `failure_cache_hits_total` | counter | | RFC 9520 cached resolution failures served |
| `nxdomain_cut_hits_total` | counter | | Descendant NXDOMAINs served from validated RFC 8020 cuts |
| `aggressive_negative_hits_total` | counter | `proof`, `rcode` | RFC 8198 answers synthesised from validated denial proofs |

The last three are answers that cost no upstream query and would otherwise have
been a full resolution each. They are the cheapest traffic the resolver serves,
and worth a panel of their own.

`dns_cache_wire_fastpath_total{outcome="..."}` shows how much of the hit traffic
is served straight from stored bytes rather than being re-encoded.

## Resolution and DNSSEC

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_resolver_failures_total` | counter | `reason` | Recursive resolution failures |
| `dns_resolver_dnssec_failures_total` | counter | `reason` | DNSSEC validation failures |
| `dns_circuit_breaker_trips_total` | counter | | Resolver circuit breaker opened (5 consecutive failures) |
| `dns_circuit_breaker_resets_total` | counter | | An open breaker closed again |
| `dns_trust_anchor_refresh_total` | counter | `result` | RFC 5011 refresh attempts, by terminal result |
| `dns_trust_anchor_lifecycle_total` | counter | `transition` | RFC 5011 anchor lifecycle transitions |
| `dns_resolution_shed_total` | counter | `scope` | Lookups shed at an in-flight ceiling before any upstream work |
| `dns_edns_errors_total` | counter | `reason` | EDNS protocol errors that rejected a query |

`dns_resolver_dnssec_failures_total` deserves an alert. Clients see only
SERVFAIL, so a zone that has broken its signing — or something interfering with
your traffic — is otherwise invisible.

`dns_trust_anchor_lifecycle_total` is quiet for years and then matters
enormously. Watch it around a root KSK rollover.

## Recursion work

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_recursion_fanout_ratio` | histogram | | Outbound attempts per resolution tree |
| `dns_recursion_firewall_exhaustions_total` | counter | `mode`, `reason` | Request trees that exhausted a work budget |
| `dnssec_work_per_request` | histogram | `operation`, `mode` | DNSSEC operations per completed request tree |
| `dnssec_work_total` | counter | `operation`, `mode` | Accepted or observed DNSSEC work across request trees |

Buckets: `dns_recursion_fanout_ratio` is 1–128, `dnssec_work_per_request` is
0–512.

These are the numbers to read before switching the
[recursion firewall]({{ '/docs/features/recursion-firewall/' | relative_url }})
from shadow to enforce. In shadow mode,
`dns_recursion_firewall_exhaustions_total` is exactly the set of requests
enforce would have failed — if it is nonzero for ordinary traffic, the limit is
too low for your workload.

The `mode` label distinguishes enforced from observed, so a shadow soak and the
enforcing run afterwards are directly comparable.

## Ingress and transports

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_ingress_plan` | gauge | `bound` | Serving bounds this process derived at startup |
| `dns_udp_ingress_drops_total` | counter | `reason` | UDP packets dropped before the handler |
| `dns_udp_ingress_overflow_total` | counter | `kind` | UDP queries served outside the fixed worker pool |
| `dns_udp_inline_total` | counter | `outcome` | UDP queries attempted on the reader's inline fast path |
| `dns_tcp_ingress_drops_total` | counter | `reason` | TCP events dropped before the handler |
| `dns_listener_errors_total` | counter | `proto` | Listener loops that exited with an error |
| `dns_doh_http_errors_total` | counter | `code` | DoH responses with a 4xx or 5xx status |

`dns_ingress_plan` is the most useful metric nobody looks at: it publishes what
the process actually decided about worker count, in-flight cap and connection
cap, given the machine's memory, CPUs and file-descriptor limit. If a container
is performing worse than the host it replaced, compare this gauge before
anything else.

Overflow is a capacity signal, not a bug — it means queries arrived faster than
the fixed pool accepted them and were served on their own goroutines.

## Policy and access

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_accesslist_denied_total` | counter | | Queries denied by the access list |
| `dns_ratelimit_exceeded_total` | counter | | Queries rejected by rate limiting |
| `dns_blocklist_hits_total` | counter | | Queries blocked by the blocklist |
| `dns_blocklist_entries` | gauge | | Blocklist size (exact names plus wildcard suffixes) |
| `reflex_blocked_total` | counter | | Queries blocked as amplification-attack suspects |
| `reflex_tracked_ips` | gauge | | IPs currently tracked by reflex |

### Response Policy Zones

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rpz_action_total` | counter | `zone`, `trigger`, `action`, `outcome` | Matches under winner-bounded counting |
| `rpz_zone_rules` | gauge | `zone`, `trigger` | Compiled rules per zone and trigger, set on load |
| `rpz_zone_rules_skipped` | gauge | `zone`, `reason` | Records a zone load stepped over |
| `rpz_reload_errors_total` | counter | `zone` | Loads or reloads that failed; the previous store keeps serving |
| `rpz_zone_serial` | gauge | `zone` | Serial of an AXFR-fed zone; `-1` for file zones and withdrawn feeds |

The `outcome` label is the whole point of shadow mode: `enforced` counts matches
that acted, `observed` counts matches that only would have. Summing over
`outcome` gives a zone's match rate in either mode, which is what makes a
shadow soak comparable to the enforcing run that follows it.

`rpz_zone_rules_skipped` climbing after a feed update means the publisher
started emitting something the loader will not accept — the zone still works,
with fewer rules than intended.

## Local root

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_localroot_answers_total` | counter | `kind` | Walk consultations answered from the local copy |
| `dns_localroot_transfers_total` | counter | `outcome` | Transfer attempts, by outcome |
| `dns_localroot_serial` | gauge | | Serial of the active copy; `-1` when none is active |
| `dns_localroot_copy_age_seconds` | gauge | | Age since last successful refresh; `-1` when none is active |

`dns_localroot_copy_age_seconds` is the one to alert on. Climbing steadily means
refreshes are failing and the copy is walking toward its SOA expire, after which
you silently go back to querying the root servers.

## Forwarding and failover

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_forwarder_failures_total` | counter | | Upstream forwarder exchange failures |
| `dns_forwarder_response_mismatch_total` | counter | | Responses dropped for question-section mismatch |
| `dns_failover_attempts_total` | counter | | Failover engaged after a SERVFAIL |
| `dns_failover_success_total` | counter | | Queries answered by a fallback server |

`dns_forwarder_response_mismatch_total` is a poisoning signal, not a
performance one. It should be zero.

## Other namespaces

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dns_hostsfile_lookups_total` | counter | | Lookups attempted against the hosts file |
| `dns_hostsfile_hits_total` | counter | | Lookups that matched |
| `dns_kubernetes_queries_total` | counter | | Queries entering the Kubernetes middleware |
| `dns_kubernetes_answered_total` | counter | | Queries it answered authoritatively |
| `dns_kubernetes_errors_total` | counter | | Lookup or response-build errors |
| `dns_kubernetes_write_errors_total` | counter | | Failed writes to the client (subset of the above) |
| `dns64_synthesised_total` | counter | | AAAA queries answered with synthesised records |
| `dns64_passthrough_total` | counter | `reason` | AAAA queries DNS64 left untouched |
| `dns64_a_lookup_failures_total` | counter | `reason` | Failures of the secondary A lookup |
| `dns64_ptr_translated_total` | counter | | `ip6.arpa` PTRs answered with a CNAME to `in-addr.arpa` |

`dns64_passthrough_total{reason="dnssec"}` is worth watching: it counts the
cases where synthesis was declined because it would have masked a validation
failure.

## Runtime

The standard Go collectors are exported too — `go_goroutines`,
`go_memstats_*`, `go_gc_duration_seconds`, `process_resident_memory_bytes`,
`process_open_fds` and the rest.

`process_open_fds` against the unit's `LimitNOFILE` is worth a panel: the
TCP/DoT connection cap is derived from that limit at startup, so a low limit
quietly gives you a smaller cap than the machine could carry.

---

## Queries worth starting from

**Hit rate over five minutes**

```promql
sum(rate(dns_cache_hits_total[5m]))
  / (sum(rate(dns_cache_hits_total[5m])) + sum(rate(dns_cache_misses_total[5m])))
```

**Share of answers that cost no upstream query**

```promql
sum(rate(nxdomain_cut_hits_total[5m]))
  + sum(rate(aggressive_negative_hits_total[5m]))
  + sum(rate(dns_localroot_answers_total[5m]))
```

**SERVFAIL rate**

```promql
sum(rate(dns_queries_total{rcode="SERVFAIL"}[5m]))
  / sum(rate(dns_queries_total[5m]))
```

**Fan-out p99 — how much work an average query causes**

```promql
histogram_quantile(0.99, sum(rate(dns_recursion_fanout_ratio_bucket[5m])) by (le))
```

**NSEC3 work p99, the number to calibrate the firewall against**

```promql
histogram_quantile(0.99,
  sum(rate(dnssec_work_per_request_bucket{operation="nsec3_hash"}[5m])) by (le))
```

**What enforcement would have failed, while still in shadow**

```promql
sum(rate(dns_recursion_firewall_exhaustions_total{mode="shadow"}[5m])) by (reason)
```

**RPZ match rate by zone, in either mode**

```promql
sum(rate(rpz_action_total[5m])) by (zone, action, outcome)
```

**Local root copy going stale**

```promql
dns_localroot_copy_age_seconds > 0
```

## Alerts worth having

| Condition | Why |
|---|---|
| `rate(dns_resolver_dnssec_failures_total[10m]) > 0` | Invisible to clients; they only see SERVFAIL |
| `rate(dns_recovery_panics_total[10m]) > 0` | Should never fire |
| `rate(dns_forwarder_response_mismatch_total[10m]) > 0` | Poisoning signal |
| `dns_localroot_copy_age_seconds` rising | Refreshes failing; falls back silently |
| `rate(dns_cache_evictions_total[10m])` up while `dns_cache_hit_rate` down | `cachesize` below the working set |
| `rate(dns_udp_ingress_overflow_total[5m])` sustained | Capacity, not correctness |
