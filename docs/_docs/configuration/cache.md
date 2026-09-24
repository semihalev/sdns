---
layout: doc
title: Cache and TTLs
category: Configuration
order: 4
description: Cache size, prefetching, expired answers and what the TTL you receive actually means.
---

## Size and prefetch

```toml
cachesize = 256000
prefetch  = 10        # percent; 0 disables
```

`cachesize` is a record count, not a byte budget. The default holds a busy
resolver's working set comfortably; raising it costs memory roughly in
proportion.

`prefetch` refreshes an entry in the background when a query arrives and the
entry has less than that percentage of its original TTL left. It trades a small
amount of upstream traffic for hits that stay warm on popular names.

The value must be `0`, which turns prefetching off, or between 10 and 90.
Anything else is a configuration error rather than being clamped, so `sdns -t`
rejects it.

## Across restarts

```toml
cache_persist = false
```

With `cache_persist = true`, sdns writes its answers to `cache.snapshot` in the
working `directory` when it shuts down cleanly, and loads them back before it
starts answering, so a restart or an upgrade does not begin with an empty cache.
Off by default.

A restored answer gets no more trust than one fresh from the network. Each
keeps only the lifetime it had left, less the time sdns was down, and its
delegation lease is aged the same way, separately; an answer whose lease ran
out while sdns was down is gone, not stale. Each then goes through the same
admission as an upstream answer, under the limits and the signature rules in
force at the new start, which can only shorten it. ECS-scoped answers and
answers with less than ten seconds left are not saved.

The file is LZ4 compressed and carries a CRC-32C over everything in it. It is
set aside whole, and the cache starts empty as it would have without it, when
the checksum fails, when it was written in the future by the clock's account,
or when it was written under different trust anchors, DNSSEC mode, root,
fallback or forwarder servers, forward zones or empty zones. A file that is
merely damaged costs a cold start, never a wrong answer.

**What it costs.** For a million answers, half of them signed, saving takes
under a second and loading about two, on ordinary hardware; the file is around
110 MB. Loading happens before the listeners open, so startup takes that much
longer. The load stops after ten seconds whatever it has reached, which bounds
it under normal disk access, not against a disk that stalls.

**Shutdown takes longer.** The save runs after the listeners have drained,
which may itself take up to ten seconds, and stops adding answers after three
more; the process then waits at most two further seconds for the file to be
finished and exits regardless. A save that does not finish in time leaves the
previous file in place. Whatever stops the service must allow for that: the
shipped systemd unit sets no `TimeoutStopSec`, so the manager's
`DefaultTimeoutStopSec` applies, and it needs headroom over those fifteen
seconds.

Only a clean shutdown saves. After a crash the next start loads the file from
the last clean one, aged by the whole time since.

## Which TTL you receive

The TTL sdns serves is the answer's own remaining TTL, counted down from when
it was cached. It is not the smallest TTL of everything consulted on the way to
the answer, a short-lived delegation record on the path does not shorten the
answer.

There is one deliberate ceiling: a learned delegation lease. When the parent
granted a delegation for a bounded time, no answer under that delegation is
served past the point the parent's grant expires. That is why a long-TTL record
under a short-lived delegation can come back with less than you expected, the
cut, not the record, is the binding constraint.

## What a hit contains

A hit is served from what the cache stored, and the cache stores only what it
can vouch for. Four things follow from that, and they are visible from a
client.

An entry keeps the signatures that cover its records inside their validity
period. A signature that has lapsed, or one whose inception has not arrived,
goes out in the first response exactly as the authority sent it and is absent
from every hit. This is what a key rollover looks like from the outside: the
outgoing key's signature disappears from cached answers as soon as it expires,
while the incoming key's keeps the answer authenticated.

An explicit `RRSIG` query is the one case where the signatures are the answer
itself, so such an answer is cached only when every signature in it can be
kept. Otherwise each query for it goes upstream.

A signed RRset in the additional section, a mail exchanger's address for
instance, is served complete with its signatures or not at all. It stays only
when its signatures cover the whole of the entry's lifetime and its records
arrived with at least that much TTL; a shorter-lived one is left out rather
than served past what its signature permits. Unsigned glue is unaffected.

A query without the DO bit receives no `RRSIG`, `NSEC` or `NSEC3` record it did
not ask for, in any section, on a miss and on a hit alike, and from a
synthesized denial as well (RFC 4035 §3.2.1). A query for one of those types
keeps exactly that type and loses the others.

## Serving expired answers

```toml
serve_stale         = false
serve_stale_max_ttl = "24h"
```

When resolution ends in SERVFAIL, sdns may answer from an expired positive entry
rather than failing (RFC 8767). Off by default.

`serve_stale_max_ttl` is measured from the moment the answer's TTL expired, and
defaults to 24 hours. An explicit `"0"` leaves the delegation lease as the only
upper bound; in whole-server forwarder mode, which learns no delegation cut,
`"0"` permits retention until the entry is evicted.

The delegation lease is a hard ceiling here too, so this cannot revive data past
a known parent-granted cut. It is failure-triggered and positive-only: a stale
NXDOMAIN is never served. The full design is on the
[Serve stale]({{ '/docs/features/serve-stale/' | relative_url }}) page.

## Negative caching

A name that does not exist is an answer worth keeping, and RFC 2308 says how
long for: the lifetime comes from the SOA in the denial, bounded by the smaller
of its TTL and its MINIMUM field.

That value is a ceiling, not a target. RFC 2308 says how long a resolver *may*
cache the denial, so sdns applies no minimum on top of it: a zone that
publishes a one-second negative TTL gets one second, and a denial carrying no
lifetime at all is not cached.

A denial does not have to arrive as an empty answer to be one. The common shape
on the wire is a CNAME chain that never reaches the type you asked for, and the
SOA at the end of it is what says how long that holds, not the alias TTL in
front of it.

A denial arriving without an SOA is not cached at all. There is nothing to
derive a lifetime from, and RFC 2308 is explicit that caching it anyway is what
lets two misconfigured servers pass the denial back and forth indefinitely.

Ordinary answers do take a five-second floor, and it is worth being straight
about what that is: RFC 1035 §3.2.1 makes a record's TTL the point at which the
source should be consulted again, so holding a one-second record for five is a
deliberate deviation. It is a defensible one, about this resolver's own data
and nobody else's namespace, and it is the difference between a hot short-TTL
name being re-resolved on every single query or once every five seconds. A
denial is not the same case: there the TTL is a zone's statement about a name
it is authoritative for.

The floor is a preference, not a right, and it stops at anything the protocol
fixes. On signed data RFC 4035 §5.3.3 caps the lifetime at the smallest of four
values, and none of them may be exceeded: the RRset's TTL as received, the
RRSIG's own TTL, the RRSIG's Original TTL field, and the time left before the
signature expires. The floor never lifts an entry past that, so a signed record
that arrives with a one-second TTL is held for one second. An answer served
after its signature has lapsed is bogus to every validator downstream, which is
not a freshness question at all.

Which signature sets that bound matters. A signature counts only inside its own
validity period, and only for the RRset it covers, under the zone that made
it. During a key rollover an RRset carries a signature from the outgoing key
beside one from the incoming key; once the outgoing one expires it bounds
nothing, because the incoming one still covers the RRset, and the answer is
held for as long as that one permits. An RRset that no valid signature covers
is not admitted at all. Signatures in the additional section bound neither the
lifetime nor the AD bit: what the resolver vouches for is the answer and
authority sections (RFC 4035 §3.2.3).

The lower bound is settled once, where all of that evidence is in hand, and
every layer after it may only shorten. A second floor applied at admission
cannot see any of it, and would quietly undo the work.

One consequence worth stating: an answer this cache serves never carries a TTL
of zero. Zero tells the client not to reuse the answer, and a cache that says so
while reusing it is contradicting itself; for a denial RFC 2308 §5 rules it out
directly. An entry down to its last fraction of a second is served as one
second, which is the finest a DNS message can express, and then it is gone.
The one exception is a delegation lease in its last fraction of a second:
that bound is the parent's, not this cache's to round, so the answer goes out
with a TTL of zero rather than a second the parent never granted.

The two mechanisms that *reuse* a denial for names it was never asked about are
bounded the same way, and were already. Both are on by default and both are
covered under
[Resolution and DNSSEC]({{ '/docs/configuration/resolution/' | relative_url }}):
RFC 8020 lets one NXDOMAIN answer every name beneath it, and RFC 8198 answers
later denials from a validated NSEC or NSEC3 record already held. For these,
sdns takes the smallest value across every component of the proof, the SOA,
the records in the authority section, the signatures over them, and the
delegation lease, and applies no floor on top, because a floor there would let
a cache setting extend an authenticated denial past the proof that authorised
it. Answering one name from another's denial is a claim about a whole subtree,
and it expires with the weakest thing supporting it. They are counted by
`nxdomain_cut_hits_total` and `aggressive_negative_hits_total`.

## Failure caching

```toml
expire = 600      # legacy; retained for compatibility
```

`expire` is a legacy error-cache ceiling kept so old configuration files still
load. Recursive resolution failures are governed by the RFC 9520 failure cache
in the `[recursion_firewall]` block instead, see the
[recursion firewall]({{ '/docs/features/recursion-firewall/' | relative_url }}).

## Purging

```bash
curl http://127.0.0.1:8080/api/v1/purge/example.com./A
```

Drops one name and type from the cache. There is no purge-everything endpoint;
restarting is the way to empty the cache entirely, with `cache_persist` off, or
with `cache.snapshot` removed while sdns is stopped.

## Watching it

```
dns_cache_size              current entries
dns_cache_hits_total        hits
dns_cache_misses_total      misses
dns_cache_hit_rate          percentage, 0-100
dns_cache_evictions_total   entries dropped under pressure
dns_cache_prefetches_total  background refreshes
dns_cache_stale_answers_total  answers served past expiry
dns_cache_wire_fastpath_total  hits served straight from stored bytes
dns_cache_snapshot_entries_total  answers saved and restored across a restart
dns_cache_snapshot_seconds     how long the last save and restore took
```

A rising `dns_cache_evictions_total` with a falling hit rate is the signal that
`cachesize` is too small for the working set.
