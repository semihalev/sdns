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

The miss path is measured separately in [Cold cache](#cold-cache-resolution-rather-than-serving),
added 2026-08-22. The two sections answer different questions and their numbers
are not comparable to each other.

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

**The 8-way concurrency class.** sdns run with `GOMAXPROCS=8` to match the
8-worker configurations of the C daemons. This bounds how many threads Go
executes simultaneously — it is a concurrency limit, not CPU pinning; no
process here is bound to specific cores:

| resolver | median qps | busy cores | qps per busy core |
|---|---|---|---|
| **sdns 1.8.0 @ GOMAXPROCS=8** | **394k** | 7.9 | ~50k |
| PowerDNS Recursor 5.4.1, 8 threads | 371k | 6.6 | ~56k |
| Unbound 1.24.2, 8 threads | 343k | 6.0 | ~55k |
| Knot Resolver 6.2.0, 8 workers | 191k | 6.7 | ~27k |

(Unbound configured with 16 threads still consumed only ~8 busy cores and
reached 362k / ~45k per core — its observed CPU envelope stays in this
class even when its configuration leaves it.)

**Scaled up.** Each resolver allowed more workers:

| resolver | median qps | best qps | busy cores | qps per busy core |
|---|---|---|---|---|
| **sdns @ GOMAXPROCS=16** | **462k** | 475k | 13.3 | ~35k |
| sdns @ GOMAXPROCS=12 | 439k | **487k** | 11.1 | ~40k |
| PowerDNS Recursor, 16 threads | 441k | 474k | 9.2 | ~48k |
| sdns, runtime default (32) | 418k | 446k | 13.8 | ~30k |
| Knot Resolver, 16 instances | 253k | 253k | 11.6 | ~22k |

Three findings worth stating plainly. First, in the same concurrency
class sdns leads while running its full middleware chain against
PowerDNS's packet echo. Second, per-core efficiency is a property of each
configuration, not an intrinsic constant — PowerDNS's echo does the least
work per query of the four and earns the best per-core number for it.
Third, sdns's own scaling curve bends: ~50k qps/core at 8 procs falling
to ~30k at the runtime default of 32, and doubling the concurrency from
8 to 16 buys only ~17% more throughput. What the measurements establish
is precisely this: on this dual-socket, 32-logical-CPU host, bounding
Go's parallelism below the runtime default materially improves throughput
(418k median at the default vs 462k at `GOMAXPROCS=16`). The shape is
consistent with scheduler, shared-state and cache-coherence costs; an
affinity-controlled check (the process bound to one NUMA node with
`numactl`) measured no improvement over the unbound runs, so memory
placement alone does not explain the bend. Flattening the curve is
tracked as future engine work.

### Run-to-run spread

20-second runs on a busy OS have real variance; the full series behind the
medians spanned roughly ±7% for sdns UDP (423–444k), ±6% for PowerDNS
(346–390k), ±3% for Unbound, ±2% for Knot, and ±15% for sdns TCP (195–273k).
Single-run numbers from any resolver should be read with that in mind.

## Cold cache: resolution rather than serving

Everything above measures the hit path. This measures the other half — what a
miss costs — by running a corpus the resolver has never seen against an empty
cache. It is a different question, and the answer belongs to a different part
of the code: how quickly the resolver walks root → TLD → zone, and which
upstream it picks at each step.

Measured 2026-08-22 at commit `676ac14`, on the same host as above.

### Method

- **Corpus:** `queryfile-50000`, 50,000 names, one full pass per run. It
  resolves to roughly 67% NOERROR, 32% NXDOMAIN and 1.7% unresolvable. A
  corpus that is largely dead names is the wrong instrument for the serving
  benchmark and the right one here, because dead names still cost a full
  delegation walk.
- **Cold start per run:** every resolver is restarted before every run. Knot
  keeps its cache in LMDB on disk, so that file is deleted too; without that
  its second run would start warm.
- **Alternating, three rounds:** `sdns → PowerDNS → Unbound → Knot`, repeated
  three times, 45 s between runs. Upstream latency varies with the hour, so
  running one resolver's three runs back to back would charge that hour to
  that resolver. Medians are reported.
- **Load:** `dnsperf -S 1 -T 100 -t 10 -c 1000`, identical for all four.
- **Readiness gate:** a run is only recorded if the resolver answered a probe
  query first, so a failed start cannot be recorded as a slow one.

Three things had to be equalised, and getting them wrong the first time
changed the answer by more than the result itself:

- **File-descriptor limit, 65536 for all four**, verified per run by reading
  `/proc/<pid>/limits` and printed alongside each result. At the shell default
  of 1024 the resolvers are not equally handicapped — a cold run's concurrency
  is bound by outgoing sockets, and a resolver configured for more of them
  than the limit allows is silently clamped. Under that limit PowerDNS
  measured 529 qps; with it raised, 799.
- **Per-upstream timeout, 750 ms for both sdns and PowerDNS.** Unbound and Knot
  time out adaptively from measured RTT and have no equivalent single knob;
  Unbound's starting point for an unmeasured server is 376 ms, so it is
  already the more aggressive of the two policies.
- **QNAME minimisation off in all four.** All four implement it and each
  bounds it differently. RFC 9156 §2.3 does require a bound — *"Resolvers
  supporting QNAME minimisation MUST implement a mechanism to limit the
  number of outgoing queries per user request"* — and it names values:
  MAX_MINIMISE_COUNT with a RECOMMENDED value of 10, and MINIMISE_ONE_LAB
  with "a good value is 4". What the implementations do not share is the
  knob: sdns exposes a label depth (`qname_min_level`, default 3), the
  others expose a boolean or their own parameters, so the recommended
  values cannot simply be dialled in on all four. Turning it off removes
  the variable instead. **This is not a configuration to run in
  production** — it is a privacy regression, and it is off here to compare
  resolution engines rather than to recommend a setting.

### Results

Medians of three rounds:

| | queries/sec | avg latency | unanswered | lost | spread |
|---|---|---|---|---|---|
| **sdns 1.8.0** | **868** | **0.111 s** | 869 (1.74%) | **0 / 0 / 0** | 3.2% |
| PowerDNS Recursor 5.4.1 | 799 | 0.118 s | 882 (1.76%) | 1 / 0 / 0 | 2.0% |
| Knot Resolver 6.2.0 | 583 | 0.121 s | 884 (1.77%) | 234 / 203 / 188 | 6.4% |
| Unbound 1.24.2 | 447 | 0.127 s | 874 (1.75%) | 526 / 489 / 473 | 5.3% |

**"Unanswered" counts SERVFAIL and lost queries together**, and it is the
column that makes the rest readable. Counting SERVFAIL alone puts Unbound
first at 0.78% — but it left 489 queries with no answer at all, which from a
client is worse than a SERVFAIL, not better. Summed, all four land between
1.74% and 1.77%: they resolved the same corpus to the same outcomes, and the
residue is names that genuinely do not resolve. That is what makes this a
like-for-like comparison rather than four different amounts of work.

Average latency is reported for completed queries only, so a resolver that
abandons a query improves its own average by doing so; the wall clock and the
lost column are where that shows up.

### Caveats

- One pass per resolver per round, not a repeated measurement within a round.
  A cold run cannot be repeated quickly — the cache has to be emptied and the
  upstreams re-walked — so the spread column is across rounds, which also
  carries the hour's drift.
- Cold-cache throughput is dominated by upstream latency, not by the local
  machine. These numbers describe how well each resolver walks the tree on
  this network from this host, and should not be read as a portable ranking.
- The minimisation caveat above is not a footnote: with each resolver's own
  minimisation policy enabled, the numbers and possibly the ordering differ.
  Measuring that would mean establishing what each one actually sends —
  observable on the wire, since the minimised queries are visible in a
  capture — rather than trusting four differently-named settings to mean the
  same thing.

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

For the cold-cache section, the shape is different: no warm pass, one full
pass over a corpus the resolver has never seen, and a restart before every
run.

```sh
ulimit -n 65536                       # or the comparison measures this, not the resolver
# restart the resolver here; delete its on-disk cache if it keeps one
dnsperf -s <addr> -p <port> -S 1 -T 100 -t 10 -c 1000 -d queryfile-50000
```

Alternate the resolvers rather than blocking them, record queries lost
alongside SERVFAIL, and check that the two summed agree across contenders
before comparing throughput — if they do not, the resolvers are not doing the
same work and the throughput numbers do not mean what they appear to.
