# Durable Ghost/Phoenix-Domain Protection

Status: authoritative implementation specification  
Advisory: GHSA-mqfw-f48p-2vc8

This document replaces the earlier scratchpad design and its tentative
numeric-version, RR-rewrite, and eager-generation alternatives.

## Security invariants

1. A learned delegation expires at one immutable absolute `ExpiresAt` and
   cannot outlive any ancestor delegation used to reach it.
2. A cached response cannot be served past the shortest learned delegation
   cut observed while producing its request tree.
3. An asynchronous prefetch result can replace only the exact answer-cache
   entry that triggered it.
4. Zero `time.Time` means unbounded and is used only where no learned
   delegation applies (root/configured, forwarder, and local-answer paths).

All expiry arithmetic retains Go's monotonic clock reading. Protocol
timestamps may use UTC; cache lifetime arithmetic must use `time.Now()`
without `UTC`, `In`, or other monotonic-stripping transformations.

## Locked design

### Delegation deadlines

`authority.Delegation` stores `ExpiresAt time.Time`. Resolver writes use
`SetUntil` so an inherited deadline is stored verbatim rather than converted
back to a duration and re-anchored.

Resolution state carries `(cutDeadline, cutKey)`. A local referral is combined
with its ancestor as:

```text
(childDeadline, childKey) = minCut(ancestorDeadline, ancestorKey,
                                   localDeadline, localKey)
```

Zero deadlines are unbounded. Equal deadlines keep the first identity, so a
descendant that inherits the exact ancestor expiry retains the ancestor key.
`searchCache` returns a small result containing servers, DS, level, deadline,
and delegation key.

### Answer binding

`CacheEntry` stores immutable `cutUntil` and `cutKey` fields. Resolver RRsets
are not rewritten before insertion. Read-time effective lifetime is:

```text
min(stored + ttl, cutUntil)
```

`ToMsg`, `TTL`, and `IsExpired` use that effective lifetime, including when
the delegation cut is shorter than the configured five-second minimum TTL.

The pooled `middleware.Chain.ResponseMeta` atomically folds the earliest
immutable `(deadline, key)` pair across resolver, CNAME, and internal-subquery
legs. Cache write-back occurs after synchronous CNAME chasing, then reads the
winning pair. Direct resolver `subQuery` writes use the same metadata.

### Late asynchronous writes

`PrefetchRequest.Entry` is the exact triggering `*CacheEntry`. Prefetch
write-back uses pointer identity under the cache segment lock:

```text
ReplaceIfCurrent(key, expected=req.Entry, replacement)
```

If another result has replaced or removed that entry, the refresh is dropped.
A prefetched SERVFAIL never replaces a valid positive entry. Expiry cleanup
uses conditional deletion so a stale reader cannot delete a newer value.

Phase 2 intentionally covers asynchronous prefetch refreshes. The ordinary
external cache-miss path uses per-key request deduplication and is outside this
pointer-CAS refresh contract. If a future asynchronous writer bypasses that
path, it must capture an explicit expected entry/token before it is allowed to
publish.

### Phase 3

Active pre-expiry invalidation remains deferred. `cutKey` is carried and stored
now so a future generation design has stable lineage identity, but no mutable
generation registry or O(n) subtree sweep is part of Phases 1–2. Mid-lease
re-delegation is therefore bounded by the parent-granted lease; unchanged,
withdrawn, and re-delegated parent state is observed when that deadline is
reached.

## Delivered phases and acceptance coverage

| Phase | Delivered behavior | Primary regression |
|---|---|---|
| #513 | Parent lease honored; no one-hour floor; non-positive TTL skipped; progressing referrals only; coherent NS RRset; minimum NS/DS TTL | `ghost_domain_test.go`, `authority/cache_test.go` |
| 1a | Descendants inherit the shortest immutable ancestor deadline | `phoenix_t2_test.go` |
| 1b | Positive, negative, CD, ECS, CNAME, forwarder/local-zero answer-cache binding | `cache/cutuntil_test.go` |
| 2 | Pointer-CAS late-prefetch protection and full withdrawal pipeline | `ghost_answer_prefetch_test.go`, `cache/cutuntil_test.go` |
| deferred 3 | Optional active pre-expiry generation invalidation | Not implemented |

The critical acceptance set is:

1. Short ancestor plus 12-hour nested referral: exact inherited expiration.
2. Long answer under a short cut, including the five-second minimum-TTL floor.
3. CNAME chain crossing two cuts: the shortest deadline and its key win.
4. Forwarder/local answers with a zero deadline remain unbounded, including
   after pooled-chain reuse.
5. Delayed prefetch cannot replace a newer parent NXDOMAIN.
6. At the deadline, unchanged, withdrawn, and re-delegated parent states are
   re-observed; the former child is not used after re-delegation/withdrawal.
7. Concurrent metadata folding, replacement, expiry deletion, and queue
   shutdown pass under the Go race detector.

## References

- [Phoenix Domain (NDSS 2023)](https://www.ndss-symposium.org/wp-content/uploads/2023-5-paper.pdf)
- [IETF NS revalidation draft](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-ns-revalidation-13)
- [ISC/BIND parent-derived expiry note](https://kb.isc.org/docs/aa-00620)
