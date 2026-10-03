---
layout: doc
title: Response Policy Zones
category: Features
order: 1
description: Policy feeds that rewrite, deny or drop answers, by name, by client address, or by the address in the answer.
---

RPZ expresses DNS policy as a zone. The rules are ordinary resource records in
the standard encoding, which means commercial and community feeds load
unmodified, whether you fetch them as a file or transfer them over AXFR.

```toml
[rpz]
enabled = true
mode    = "shadow"

[[rpz.zone]]
name   = "badfeed"
file   = "/var/lib/sdns/badfeed.zone"
policy = "given"
```

## Start in shadow

`mode = "shadow"` evaluates every rule and counts every match, and changes no
answer. `mode = "enforce"` applies them.

Shadow exists because a policy feed you have not run against your own traffic is
an unknown. Watch `rpz_action_total` for a day; the counts are exactly what
enforcement would have done. When the numbers look like what you intended,
switch to `enforce`.

Policy applies to the recursive service: client queries with RD=1 in class IN.
A query with RD=0, a question in another class, and the lookups sdns makes on
its own behalf are not checked against it.

## What can trigger a rule

**The query name.** The classic trigger: a rule owned by `evil.example.rpz.zone.`
matches a query for `evil.example`.

**The client's address.** A rule under `rpz-client-ip` matches on who is asking,
which is how you carve out a network from a policy, or apply one only to it.

**An address in the answer.** A rule under `rpz-ip` matches on what the answer
turned out to contain, the case a name-based feed cannot cover, because the
name is new and only the hosting address is known bad.

Answer-address rules are evaluated after resolution, against the answer that
came back. The cache still holds what the authority actually said; the policy is
applied to the response the client receives, not to the stored copy. Two clients
under different policies therefore share one cache entry and still get their own
answers.

## Actions

The feed's own rules select an action. A zone may override them all:

| `policy` | Effect |
|---|---|
| `given` | Use whatever the feed's rule says (the default) |
| `passthru` | Match, count, but answer normally |
| `nxdomain` | Answer NXDOMAIN |
| `nodata` | Answer NOERROR with no records |
| `drop` | Send nothing at all |
| `tcp-only` | Over UDP, answer truncated, forcing the client to retry over TCP; over any other transport, answer normally |
| `cname` | Rewrite every match to `cname` (which must then be set) |
| `disabled` | Load and count the zone, never act on it |

`disabled` is per-zone what `shadow` is server-wide: it lets you add a feed and
watch it in isolation while other zones stay in enforce.

A rewritten answer says so. An NXDOMAIN, a NODATA or a local data answer,
`cname` included, carries the policy zone's SOA in its Additional section, EDE
17 (Filtered) with the text `rpz: filtered by zone <name>` for a client that
uses EDNS, and the AD bit cleared. A `tcp-only` reply is the bare truncated
header and carries none of these.

## Multiple zones

Zones are evaluated in the order written. The first enabled zone with a match
wins, and no later zone can override it. A `disabled` zone never wins: its
match is counted and the walk continues to the next zone. Order your feeds
from most trusted to least.

## File zones

```toml
[[rpz.zone]]
name   = "urlhaus"
file   = "/var/lib/sdns/urlhaus.rpz"
origin = "rpz.urlhaus.abuse.ch."
policy = "given"
```

Files are reloaded automatically when replaced, so a download cron is enough to
keep a feed current, no restart and no signal. A replacement that fails to
load, or that compiles no rules at all, is logged and counted in
`rpz_reload_errors_total`, and the previous rules keep serving.

`origin` matters for downloaded feeds. Many publish their SOA as `@` with the
rules relative to it, leaving the apex for the consuming server to supply. Those
files need `origin`. A file whose SOA carries an absolute owner name does not.
Getting this wrong is not silent: the zone fails to compile and `sdns -t` says
so, which is the point of running it before a restart.

## AXFR zones

```toml
[[rpz.zone]]
name     = "vendorfeed"
source   = "203.0.113.5:53"
origin   = "rpz.vendor.example."
tsig_key = "feedkey.:hmac-sha256.:c2VjcmV0"
```

An AXFR-fed zone names its primary and its apex, and never a file. It follows
the feed's own SOA schedule: refresh, retry, and withdrawal of the rules once
the zone passes SOA expire. Withdrawal fails open, an expired feed stops
applying rather than starting to deny.

`tsig_key` is `name:algorithm:base64-secret` and signs the transfer when the
provider requires it. A transfer whose serial has gone backwards is refused at
the probe rather than being applied. A transfer that fails, compiles no rules,
or whose SOA declares an expire of zero is not installed either: it is logged,
the installed copy keeps serving until its own expire, and the next attempt
comes after the SOA retry interval.

## Watching it

```
rpz_action_total        matches by zone and action
rpz_zone_rules          rules currently loaded per zone
rpz_zone_rules_skipped  rules the loader could not use
rpz_zone_serial         serial of each AXFR zone, -1 for file zones and withdrawn feeds
rpz_reload_errors_total failed or empty file loads, AXFR feeds withdrawn at expire
```

`rpz_reload_errors_total` does not count a failed transfer: the feed retries
on its SOA schedule, and a run of failures shows up as the counter moving once,
when the copy passes its expire and is withdrawn. Watch the log, or
`rpz_zone_serial` standing still, for the failures themselves.

Rules under `rpz-nsdname` and `rpz-nsip` are not evaluated. The loader skips
them and counts them in `rpz_zone_rules_skipped` with
`reason="trigger-unsupported"`, so a feed that carries them shows a steady
count there from its first load. The zone still works, without those rules.
A feed made only of such rules compiles no rules at all, so `sdns -t` refuses
it as a file zone, and as an AXFR zone it is never installed.

`rpz_zone_rules_skipped` climbing after a feed update usually means the feed
started emitting a record type or an encoding this loader does not accept; the
zone still works, with fewer rules than the publisher intended.
