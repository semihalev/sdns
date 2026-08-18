# Benchmarks

Measured 2026-08-18 at commit `8b36b91` (the 1.8.0 serving-path work, PR #572).
This document exists to make one set of claims precisely, with the method and
configurations needed to check them — not to advertise a bigger number than the
method supports.

**What these numbers are:** the cached-answer serving ceiling of each resolver
on one machine — how fast the server itself can answer once the answer is in
its cache. **What they are not:** a prediction of production throughput. Real
traffic mixes hits with misses, and a miss is bound by upstream latency, not by
the serving engine. What a resolver's engine controls is the hit path; that is
what this measures.

## Environment

| | |
|---|---|
| Host | 2× Intel Xeon E5-2620 v4 @ 2.10 GHz (32 logical cores), 64 GB RAM |
| OS | Ubuntu 26.04 LTS, stock kernel and sysctls — no network tuning |
| Load generator | dnsperf 2.15.0, on the same host over loopback |
| sdns build | Go 1.26.5, `go build`, no build flags |

Client and server share the machine, so every number includes the load
generator's own CPU cost, identically for every contender.

## Method

- **Corpus:** 2,349 names pre-verified to be served from cache (plus separate
  corpora: 1,143 names covered by cached negative answers, 63 names with
  cached SERVFAIL). Warm-hit corpora decay as TTLs expire, so every
  measurement is preceded by a fresh warm pass; numbers taken against a stale
  cache measure recursion, not serving, and come out far lower.
- **Protocol per contender:** start fresh → warm the corpus (parallel `dig`
  pass) → one 10-second throwaway run → the measured runs, 20 seconds each.
  Median and best of the series are reported.
- **UDP load shape:** `dnsperf -c 128 -T 8 -l 20`. The flow count matters: with
  only 20 flows (`-c 20`), kernel reuseport hashing leaves most of a 32-socket
  receiver idle and the results measure hash luck. 128 flows approximates real
  traffic, which carries thousands. (For reference, the 20-flow shape puts
  sdns and PowerDNS at parity around 370–400k and does not change the ordering
  of the others.)
- **TCP load shape:** `dnsperf -m tcp -c 20 -T 4 -l 20`, pipelined persistent
  connections.
- **DNSSEC validation enabled in all four resolvers** (AD flag spot-checked
  through each). IPv6 upstream disabled everywhere (the host has no v6
  transit); irrelevant to cached serving.

## Contenders

| Resolver | Version | Serving configuration |
|---|---|---|
| sdns | 1.8.0 @ `8b36b91` | stock generated config (bind/API/paths only); full middleware chain runs per query |
| PowerDNS Recursor | 5.4.1 | `threads=8`, `reuseport=yes`, `dnssec=validate`; warm hits served by the packet cache |
| Unbound | 1.24.2 | `num-threads: 8`, `so-reuseport: yes`, cache slabs = 8, `msg-cache-size: 256m`, `rrset-cache-size: 512m`, `minimal-responses: yes` |
| Knot Resolver | 6.2.0 | 8 `kresd` instances on one port (SO_REUSEPORT), shared 512 MB LMDB cache |

Two fairness notes, one in each direction. PowerDNS's packet cache echoes a
stored packet — deliberately less work per query than sdns's full chain, so
its number represents its lightest possible path, as does ours. And each
contender was given a reasonable performance configuration, not an exhaustive
tuning pass; a specialist could likely move any of these numbers some percent.

## Results

### UDP, cached answers (`-c 128 -T 8`, 3×20 s)

| Resolver | median qps | best qps |
|---|---|---|
| **sdns 1.8.0** | **424k** | **444k** |
| PowerDNS Recursor 5.4.1 | 371k | 390k |
| Unbound 1.24.2 | 343k | 346k |
| Knot Resolver 6.2.0 | 191k | 192k |

sdns with the untouched default configuration measures in the same band
(median 406k over three runs) — the result does not depend on tuning knobs.
Answer classes beyond plain hits, measured on sdns freshly warmed: negative
answers (NXDOMAIN from cached denial) 409k, cached SERVFAIL 399k.

### TCP, cached answers (`-c 20 -T 4`, 5×20 s)

| Resolver | median qps | best qps |
|---|---|---|
| **sdns 1.8.0** | **226k** | **273k** |
| Knot Resolver 6.2.0 | 142k | 146k |
| Unbound 1.24.2 | 136k | 149k |
| PowerDNS Recursor 5.4.1 | 56k | 57k |

### Efficiency and scaling: server-process CPU per query

Each server process's own CPU time was read from `/proc` (utime+stime deltas
across each 20-second run) — so the load generator's cost, which every
loopback number otherwise includes, is excluded here by construction. All
rows below come from the same harness cycle (`contrib/bench/resolver_bench.py`:
readiness gate, verified warm, throwaway run, 3×20 s).

**Equal budget (~8 cores).** sdns pinned to the same core budget the C
daemons configure (`GOMAXPROCS=8` vs `threads=8`):

| resolver | median qps | busy cores | qps per busy core |
|---|---|---|---|
| **sdns 1.8.0 @ GOMAXPROCS=8** | **394k** | 7.9 | ~50k |
| PowerDNS Recursor 5.4.1, 8 threads | 371k | 6.6 | ~56k |
| Unbound 1.24.2, 16 threads | 362k | 8.0 | ~45k |
| Unbound 1.24.2, 8 threads | 343k | 6.0 | ~55k |
| Knot Resolver 6.2.0, 8 workers | 191k | 6.7 | ~27k |

**Scaled up.** Each resolver allowed more workers:

| resolver | median qps | best qps | busy cores | qps per busy core |
|---|---|---|---|---|
| **sdns @ GOMAXPROCS=16** | **462k** | 475k | 13.3 | ~35k |
| sdns @ GOMAXPROCS=12 | 439k | **487k** | 11.1 | ~40k |
| PowerDNS Recursor, 16 threads | 441k | 474k | 9.2 | ~48k |
| sdns, runtime default (32) | 418k | 446k | 13.8 | ~30k |
| Knot Resolver, 16 instances | 253k | 253k | 11.6 | ~22k |

Three findings worth stating plainly. First, at an equal core budget sdns
leads while running its full middleware chain against PowerDNS's packet
echo. Second, per-core efficiency is a property of each configuration, not
an intrinsic constant — PowerDNS's echo does the least work per query of
the four and earns the best per-core number for it. Third, sdns's own
scaling curve bends: ~50k qps/core at 8 procs falling to ~30k at the
runtime default of 32 on this dual-socket host, which makes the default
*worse* than a bounded `GOMAXPROCS` (418k vs 462k median). On multi-socket
machines, capping `GOMAXPROCS` near the physical core count of one socket
region is measurably better; flattening that curve (shared-counter and
NUMA effects) is tracked as future engine work.

### Run-to-run spread

20-second runs on a busy OS have real variance; the full series behind the
medians spanned roughly ±7% for sdns UDP (423–444k), ±6% for PowerDNS
(346–390k), ±3% for Unbound, ±2% for Knot, and ±15% for sdns TCP (195–273k).
Single-run numbers from any resolver should be read with that in mind.

## What changed in 1.8.0

The same harness, applied to sdns itself across the 1.8.0 serving-path work
(each row A/B-measured against its predecessor at the time; early rows used
the 20-flow shape, so rows are comparable to their neighbors, not across the
whole column):

| build | UDP cached answers |
|---|---|
| 1.8.0 baseline before PR #572 | 268k |
| + sharded slab caches | 287k |
| + fetch-add lease admission | 306k |
| + batch-slot persistence | ~330k |
| + inline wire-hit serving on the reader | 424k median / 444k best |

TCP moved from ~100k to the 226k median above in the same PR, by removing a
per-connection query budget that forced a reconnect storm under pipelining.

## Reproducing

```sh
# corpus: one name per line; verify each serves from cache before trusting it
dnsperf -s <addr> -p <port> -d hits.txt -c 128 -T 8 -l 20          # UDP
dnsperf -s <addr> -p <port> -m tcp -d hits.txt -c 20 -T 4 -l 20    # TCP
```

Warm first, discard a throwaway run, take at least three measurements, report
the median, and state the flow count — it is the parameter that moves these
numbers the most.
