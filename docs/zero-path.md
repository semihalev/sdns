# The Zero Path — contract

This document is the normative contract for SDNS's allocation-free serve
path ("the strict path"). Code and gates implement it; changes to the rules
land here first. Scope, initially: hard zero **Go heap-object** allocation
for served cache hits on **UDP and TCP**, in the **default middleware
chain**, on **linux/amd64 with the pinned toolchain**. DoT is measured
against pinned budgets, not zero (stock `crypto/tls` draws record buffers
from a global pool the server cannot own). Other platforms run the same
gates with functional expectations.

The claim is staged: Z1 covers strict-wire-eligible exact hits; Z2a extends
to every exact-entry hit class; Z2b covers composite answers (NXDOMAIN cut,
failure cache, aggressive denial) and opens the headline rule:

> In the compatible default configuration, a cache hit is answered through
> job-backed `CommitWire`, or it is a policy no-response terminal. There is
> no Msg/Pack/Unpack fallback for hits. (`cache_hit_msg_fallback == 0`)

## 1. Measurement envelope

The envelope is the full job lifecycle: **immediately before job acquire →
RX → dispatch/middleware → TX → observer unwind → Finish → immediately
after slot release**. Wrapper-internal allocations are inside the envelope.

The gate (`internal/zerogate`) measures it process-wide: the server runs as
a separate subprocess (allocation counters are process-global) with a fully
silent control plane; marks are taken after **two** forced GCs (the second
empties `sync.Pool` victim caches); the verdict over ≥1M served operations
is `MallocsAfter − MallocsBefore` compared with the active stage's budget —
and equal to **zero**, not a rounded per-op figure, once a flavor's stage
pins it. End-of-window accounting identity: replies == operations, zero
client-observed drops/errors; TCP windows pre-open enough connections that
the per-connection query budget covers the run without a redial.

Flavors gated separately: UDP IPv4/IPv6 × specific/wildcard bind, TCP
persistent. Hit-class corpora from Z2a: NOERROR, NODATA, NXDOMAIN,
CNAME (cache-contained), DNSSEC DO/no-DO, EDE/failure, ECS/CD,
oversized/TC, additional-section, QTYPE=RRSIG.

CI: the `allocgate` job — non-race (the `-race` matrix cannot run
`!race`-tagged allocation pins), Go version pinned in lockstep with
`go.mod`'s toolchain directive.

## 2. Ownership: the job slab

The unit of ownership is the **job**: one preallocated, ring-managed slab
carrying all per-request strict-path state — RX/TX buffers, the request
view, chain cursor, writer state (absorbing the chain pool, the edns writer
pool, and framing buffers for strict use), address + pktinfo scratch with a
cached classic address view, the noalloc context carrier, canonical-hash
scratch, and TX completion state. Nothing on the strict path comes from a
`sync.Pool`: GC empties pools, and the gate counts every malloc.

Rules:

- **Single owner per stage** (reader → worker → writer), transfers explicit.
- **Finish is the only release point**: it fires when middleware unwind is
  complete AND the job's TX is complete (or a no-TX terminal is reached),
  clears writer state, and returns the slot. `Chain.Reset` — which runs at
  the *start* of the next request — is a defensive backstop, never the
  mechanism.
- **Terminal classification** (every path reaches Finish exactly once):

  | Event | Class |
  |---|---|
  | strict path declines the packet (eligibility) | `FastPathIneligible` → materialize and continue; **not** a terminal — the job stays owned |
  | malformed packet, unpack failure, `MSG_TRUNC` discard | Abort → Finish |
  | handler `Cancel` without a write, policy no-response | Finish(txNotRequired) |
  | write error, TX never started | Abort → Finish |
  | panic | recover at the worker boundary → Abort → Finish |
  | shutdown wake, forced close | Abort → Finish (exactly-once via the job's completion slot) |

- **Borrowed data never escapes**: observers that keep bytes or addresses
  copy them (`WireWriter` doc; dnstap copies wire bodies and must copy
  addresses into owned storage). A watchdog counts slots outstanding past
  deadline.
- **Deadline includes queue wait**: the job records `readTime`; the
  effective deadline is `readTime + QueryTimeout`.

## 3. Response-buffer lease

`middleware.WireBodyLeaser` (`BeginWire(size, reserve) → CommitWire /
AbortWire`) is the pre-build lease: response bytes are born in the buffer
the writer hands out. `CommitWire` has `WriteWire` semantics **including
post-write retention** — the base writer keeps the body for lazy `Msg()`
until the request finishes, which is why a lease is never returned to any
pool at commit time. `CacheEntry.serveWireInto(dst, …)` builds a hit into a
leased buffer and refuses (rather than allocates) on insufficient capacity.

## 4. Request-lifetime carrier

`contextutil.Carrier` is the request-lifetime anchor: the pin table and
value provider that request-scoped machinery rides on. Implementations:
`*LazyDeadline` (ordinary requests) and the server's job carrier (strict
path; recycled between requests; no `Done` channel — cancellation is not
observable on a path that never blocks). All access goes through the
package helpers, which behave identically on either.

**Materialization is a state detach.** When a request leaves the strict
path (composite cache miss, or the first legacy middleware), a real context
is built, parented on a stable context — never on the job carrier — and
each carrier value moves under a written policy:

| Value | Policy |
|---|---|
| deadline (`readTime + QueryTimeout`) | scalar copy |
| recursion-work pin (`pending`/ledger/`closed`) | ownership transfer to a detached ledger host created before the child context publishes |
| ResponseMeta provider | detached heap ResponseMeta; the cache writer snapshot rebinds to it |
| resolution-attempt guard | rides the detached meta's ledger host |
| NSEC3 memo state | detached clone (or fresh — a memo is a cache) |
| request ID, ECS markers | scalar copy |

Strict-capable middleware must not use ordinary `context.WithValue`,
`WithCancel`, or `AfterFunc`; a handler that needs them is legacy and
forces materialization before it runs — arbitrary derived values cannot be
enumerated and detached afterwards.

## 5. Canonical cache key

One algorithm everywhere, byte-level normative (`internal/cache/key_wire.go`):

    preimage = [qclass:2 BE][qtype:2 BE][cd:1][folded presentation qname]
               (+ ECS: [family 4|6][prefix bits][address bytes, bit-rounded])
    key      = xxhash64(preimage)

The folded presentation qname is the string miekg's `UnpackDomainName`
would decode, ASCII A–Z lowered: specials `. ' @ ; ( ) " \ ␠` are
backslash-escaped, bytes outside 0x20–0x7E become `\DDD`, everything else
passes literally. `KeyWire`/`KeyWireWithPrefix` compute it from
uncompressed wire names allocation-free, bit-identical to
`Key`/`KeyString`/`KeyWithPrefix` — entries written through either path
resolve through the other, no flush across the boundary.

Consumers: wire lookup, cache insert, dedup, ECS-scoped keys, prefetch,
the collision verifier, and (Z2b) the failure-cache lookup/record/retry
hash paths.

**Collision verification covers the full preimage**: QNAME
(case-insensitive) + QTYPE + QCLASS + CD + the exact normalized ECS scope
(family, prefix bits, masked address bytes) held by the entry. A chosen
xxhash collision must not cross ECS audiences or CD partitions.

## 6. Default-chain handler matrix

Verdicts for the strict path (default configuration; from the front-door
audit). There is one handler contract — `ServeDNS(ctx, ch)` over the
unified `middleware.Request` — so *wire-capable* means the handler's body
reads only parsed request facts (accessors) on the wire branch and calls
`ch.Materialize` only when it genuinely needs the decoded message;
*post-Next safe* = its after-`Next` reads survive the wire→Msg transition
through accessors; *ctx-clean* = no ordinary ctx primitives.

| Handler | Default state | wire-capable | post-Next safe | ctx-clean | Notes |
|---|---|---|---|---|---|
| recovery | active | yes | yes (panic path only) | yes | deferred recover only |
| metrics | active | needs qtype/rcode accessors | yes | yes | label lookup must take the direct-counter path (its two-label pool is not strict-eligible) |
| dnstap | inert (no socket) | yes when inert | yes | yes | enabled: async queue **must copy addresses** (today it aliases the addr's IP slice) and bodies (already does); enabling it is allowed to disable the zero guarantee otherwise |
| accesslist | active (allow-all) | yes (RemoteIP only) | yes | yes | ranger walk must not allocate on the strict path |
| ratelimit | inert (rate 0) | yes when inert | yes | yes | enabled: per-IP limiter + cookie work disables zero unless reworked |
| reflex | not registered | — | — | — | |
| edns | active | needs OPT-in-place reads (Z1 dual EDNS state) | yes | ~ (`MarkClientECS` WithValue on ECS requests → scalar-copy marker on the carrier) | its writer wrap moves into the job writer state |
| accesslog | inert (no file) | yes when inert | yes | yes | enabled: line build allocates → disables zero (documented) |
| chaos | active | yes (two field checks) | yes | yes | CHAOS answers are policy terminals off the strict path |
| hostsfile | not registered | — | — | — | |
| views | inert (0 views) | yes when inert | yes | yes | |
| blocklist | inert (0 entries) | yes when inert | yes | yes | enabled: `Exists` uses `CanonicalName` (allocs) → wire-walk rework or documented cost |
| as112 | active | needs a wire suffix check ("arpa.") | yes | yes | non-arpa fast path is one suffix compare |
| kubernetes | stub | yes (nil check) | yes | yes | |
| dns64 | not registered | — | — | — | |
| cache | active | Z1's core work | — | yes | exact entries, cache-contained chases, RFC 8020 cuts and RFC 9520 failures serve from bytes; **RFC 8198 aggressive denial is the one composite residual** — while its proof index holds any entry, a candidate wire query materializes so the Msg-path evaluators answer in order (their per-lookup allocations are the #558 successor work) |
| failover (post-cache) | passthrough writer | n/a on hits | n/a | no (`EnsureResolutionAttemptGuard` may derive) | hits never reach it once the strict path answers before the chain proceeds |
| prefetch (feature) | on (prefetch 10, the shipped default) | n/a | n/a | n/a | a hit inside the refresh threshold leaves the byte path by design — the refresh queue needs a request copy — so the guarantee is for hits outside it. The gate runs with the feature enabled and a corpus TTL that never reaches the threshold |

## 7. Bounds and shutdown

- `IngressWorkers`, `IngressQueue`, `MaxInboundInFlight` are new,
  deliberately separate from `MaxConcurrentQueries` (the resolver's
  upstream fan-out semaphore). One documented equation ties workers, queue
  depth, in-flight jobs, and buffer classes (UDP small ≤4KB `StrictRXCap`;
  TCP/DoT large ≤65,535B, **prefix-first acquisition**: the 2-byte length
  is read into connection-owned scratch and validated before a large job is
  taken) to startup RSS.
- UDP load shedding: no slot ⇒ per-reader reserved discard buffer, drop,
  count. `MSG_TRUNC` ⇒ drop+count. `MSG_CTRUNC`: specific bind continues;
  wildcard bind drops+counts (the destination address is unknowable).
- Workers are fixed for the server's lifetime — no per-N retirement. The
  "stacks stay grown" assumption is measured (stack-growth proxy) at every
  gate, not assumed.
- Shutdown is a server-scope three-phase barrier: `StopAdmission` (close
  accepts, wake blocking reads with an already-past deadline, await reader
  ACKs, close the ready queue) → `Drain` (join counter over workers,
  connections, jobs, TX queues) → `Close`; drain-deadline overrun forces
  `ForceClose → Abort/Finish per job → final join`.
