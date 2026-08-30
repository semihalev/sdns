# RPZ — Response Policy Zones for SDNS

Task #32. Targets the semantics of draft-vixie-dnsop-dns-rpz (the
Vixie/Schryver format as implemented by BIND, Unbound, Knot Resolver and
PowerDNS). Every claim about the existing tree was verified against the code
on 2026-08-30 (main `6e07d49`); file:line references are to that commit.

This is revision 9, the implementation baseline: eight external review
rounds, 30 findings, all verified and accepted, none refuted. Every decision
those rounds produced lives in the design sections below where it applies;
§11 keeps the one-line history of what each round changed.

## 1. Goal

Let an operator subscribe SDNS to policy zones — locally maintained or
commercially fed — that rewrite, deny, or drop answers for named triggers,
using the standard RPZ zone encoding, so existing feeds work unmodified.

**Non-goals for this arc:** RPZ as a *publisher* (SDNS never serves policy
zones); the NSDNAME/NSIP triggers (phase 5+, see §7); applying QNAME policy to
names discovered while chasing CNAMEs (deliberate absence, §8); a policy web
UI (the API grows nothing in v1).

## 2. Constraints the architecture imposes

These three shaped every decision below; a reviewer should check each design
point against them.

**C1 — The hot path serves wire bytes and must not be made to decode.**
Cache hits are served from stored wire with hard-zero allocation pins
(`middleware/cache`, CI "Allocation gates" job). Any RPZ check that runs per
query must operate the way `blocklist` and `as112` already do: a folded-key
lookup built with `internal/dnsname.AppendFoldedKey` on a stack buffer —
never `dns.UnpackDomainName`, never materializing the message. Consequence:
QNAME and CLIENT-IP triggers are nearly free; response-data triggers (IP)
are not, and get a different evaluation point (§5.6).

**C2 — A rewritten answer must never carry DNSSEC credibility.** The rewrite
is by definition not the signed truth. Rewritten responses: AD always clear,
no RRSIGs, the policy zone's SOA in the additional section (the draft's
mechanism for identifying the rewrite's source), plus EDE code 17 (Filtered —
`dns.ExtendedErrorCodeFiltered`, verified present in miekg/dns v1.1.73)
naming the policy zone in the extra text. The SOA is the standard signal;
the EDE is a modern courtesy beside it, not a substitute.

**C3 — The cache holds unmodified truth; policy is applied to the client's
response.** This is both the draft's requirement and the cache's own
contract: admission code in `middleware/cache/cache.go` states explicitly
that "every admission above must see the response as the resolver produced
it". A rewrite must therefore never be what the cache stores — storing it
would hand one client's policy outcome to every client (wrong the moment a
CLIENT-IP PASSTHRU exists) and would outlive the policy that produced it.
Consequence: response-trigger verdicts live *beside* the entry, not in it
(§5.6). Query-time triggers (QNAME, CLIENT-IP) run before the cache and take
effect immediately, including for hits and across reloads.

## 3. What already exists and is reused

| Need | Existing piece | Where |
| --- | --- | --- |
| Zero-alloc folded name key | `dnsname.AppendFoldedKey` | `internal/dnsname`; used by `middleware/metrics/metrics.go:117` |
| Exact + wildcard name maps, whitelist precedence | blocklist's two-map shape | `middleware/blocklist/blocklist.go:94` (`wild` suffix map), `:376` (whitelist wins) |
| Compiled CIDR containment, zero-alloc | `internal/ipset` | used by accesslist, views |
| Client identity | `ch.Writer.RemoteIP()` | `middleware/views/views.go:88` |
| Drop with no reply | `ch.Cancel()` and return | `middleware/accesslist/accesslist.go:66` — job release is independent of writing (`server/udp_engine.go:31` "every job path ends in exactly one release") |
| AXFR + SOA schedule + RFC 1982 anti-rollback | localroot transfer machinery | `middleware/resolver/localroot/transfer.go` (`axfr`, `probeSerial`), `manager.go` (refresh/retry/expire scheduling, `serialNewer`) |
| Atomic store swap on reload | `atomic.Pointer[T]` idiom | `middleware/resolver/resolver.go:68` (`localRoot`) |
| Shadow→enforce rollout | recursion firewall's mode split | `middleware/recursion_work.go` |
| Client-only exclusion from internal sub-pipelines | `ClientOnly() bool` marker | `middleware/wiring.go:23`; middleware.Setup auto-wires it |
| Config-time file/zone checking | single `Validate()` gate | `config/validate.go` (PR #592) |
| File-watch reload | fsnotify | already a dependency (`go.mod`) |

## 4. Package layout

```
internal/rpz/          — pure policy engine, no middleware imports
  store.go             — immutable compiled store; one per loaded generation
  parse.go             — RPZ zone file → rules (miekg ZoneParser; config/reload path only, not hot)
  match.go             — folded-key lookups; trigger precedence
  action.go            — the six actions as data (what to synthesize)
middleware/rpz/        — chain seat, response synthesis, metrics, reload
config/                — [rpz] section + Validate() additions
```

The engine is `internal/` so the middleware imports it and the config
validator can too (same pattern and same reason as `internal/emptyzones`:
config cannot import middleware).

## 5. Design

### 5.1 Trigger encoding (parse.go)

Standard RPZ owner-name encodings, relative to the policy zone's origin:

| Trigger | Owner form under origin | Phase |
| --- | --- | --- |
| QNAME | `evil.example.com` | 1 |
| CLIENT-IP | `24.0.2.0.192.rpz-client-ip` (prefixlen, then reversed octets; v6 reversed 16-bit hextets with `zz` for `::`) | 2 |
| IP (response) | same encoding under `rpz-ip` | 4 |
| NSDNAME / NSIP | under `rpz-nsdname` / `rpz-nsip` | 5+ (not this arc) |

One encoding subtlety the draft calls out (§4.1.1): `zz` compresses the
**last** run of zero fields, not the first as standard `::` notation does —
an address with two equal zero runs encodes differently under `zz` than a
naive `::`-style implementation would guess. The phase 2 parse round-trip
tests carry a fixture for exactly this case.

Unknown trigger markers (`rpz-nsdname`, `rpz-nsip` in v1) are counted and
skipped per rule, never a load failure: a commercial feed must load even when
it carries trigger types we don't evaluate yet. A malformed *owner encoding*
(bad prefix length, bad reversed address) is likewise counted+skipped — one
bad rule must not take down a 5M-rule feed. `rpz_zone_rules_skipped{zone,reason}`
makes both visible.

### 5.2 Action encoding (action.go)

By RDATA, per the draft:

| RDATA | Action | v1 behavior |
| --- | --- | --- |
| `CNAME .` | NXDOMAIN | synthesize NXDOMAIN, EDE 17 |
| `CNAME *.` | NODATA | synthesize NOERROR/empty answer, EDE 17 |
| `CNAME rpz-passthru.` | PASSTHRU | stop RPZ evaluation, continue chain |
| `CNAME rpz-drop.` | DROP | `ch.Cancel()`, no reply (accesslist mechanism) |
| `CNAME rpz-tcp-only.` | TCP-Only | `Proto() == "udp"`: TC=1 empty answer; all non-UDP transports (today `tcp`, `tls`, `doh`, `doh3`, `doq` — the labels the listeners actually return, `server/listener_tls.go:46`, `listener_doh3.go:34`): PASSTHRU. Stated as a predicate, not a protocol list, so a future transport cannot fall through the gap |
| `CNAME` into any other `rpz-*` label | **unsupported action** | rule skipped + counted (`rpz_zone_rules_skipped{reason="unknown-action"}`) — never served |
| other record data | Local Data | full semantics below |

The `rpz-*` label space is the action namespace, so a CNAME target under an
unrecognized `rpz-*` name is a future or nonstandard action code, not data;
treating it as Local Data would answer clients with a bogus `rpz-something.`
name. Likewise not action data: **SOA and NS** (zone housekeeping — the
apex SOA/NS are required records of the policy zone itself), **DNAME**, and
the **DNSSEC types** (RRSIG/NSEC/NSEC3/DNSKEY, present when a feed is
signed). All are skipped without failing the load, under the same counter.

**Local Data, in full** (draft §3.6 — the walled-garden case, so a common
feed shape, not an edge). The governing rule: the answer is synthesized **as
if the policy zone were authoritative for the client's qname** — so the
owner of every synthesized answer record is the *client's qname*, always,
and only RDATA and TTL come from the policy record. This matters most where
the trigger owner is not a name at all: a CLIENT-IP or response-IP rule's
owner is an address encoding, and a wildcard QNAME rule's owner is the
wildcard — none of which may ever leak into an answer as an owner name.

- The requested qtype's RRset(s) at the matching rule are served, owners
  rewritten to the qname as above.
- **QTYPE=ANY** serves *all* of the rule's local RRsets.
- When the rule holds a **CNAME** and the requested type is absent, the
  CNAME is served — and, because a recursive answering RD=1 must chase, the
  target is resolved through the existing internal-query path
  (`middleware.Queryer`, the same seam dns64 uses for its secondary A
  lookup — `middleware/dns64/dns64.go:90`) and the chain appended. The
  chased portion is the resolver's real answer for the target and is
  cached normally under the *target's* name; only the synthetic CNAME link
  is policy.
- A **wildcard CNAME** rule (an RDATA target containing the wildcard)
  **prepends the matching qname to the de-wildcarded target** — the
  draft's own example rewrites `EVIL.EXAMPLE.ORG` to
  `EVIL.EXAMPLE.ORG.EXAMPLE.COM` — before chasing.
- Only when the rule holds records but none satisfy the request (and no
  CNAME) is the answer NODATA.

Local-data TTLs come from the policy zone as written — no clamp in v1 (§8).

### 5.3 Matching (match.go) and precedence

Per-zone compiled store:

- `exact map[string]rule` — folded qname key → rule
- `wild map[string]rule` — folded suffix (from `*.name`) → rule; matched by
  the same parent-walk blocklist uses
- an **action-carrying longest-prefix-match structure** for IP triggers
  (phase 2 CLIENT-IP, phase 4 IP), new in `internal/rpz`. `internal/ipset`
  is *not* reusable here: its `Contains` answers only bool
  (`internal/ipset/ipset.go:117`) and it coalesces overlapping prefixes,
  while RPZ needs the matched rule back and needs overlapping prefixes kept
  distinct (each carries its own action). Candidate shape: per-prefix-length
  maps of masked `netip.Addr` keys, walked longest-first over the lengths
  actually present. That walk is bounded by the feed, not by us — an
  adversarially shaped v6 feed carries up to 128 distinct lengths, and
  CLIENT-IP runs on every query — so "few in practice" is a hope, not a
  bound, and the structure choice is settled by measurement in phase 2:
  a stated per-query probe budget, benchmarked against a worst-case feed;
  if the length-map walk misses the budget, a payload-carrying radix
  replaces it (speed is an exit criterion, not an aspiration).

Precedence, per the draft:

1. **Across zones:** configured order; the first zone containing any match
   wins. No cross-zone "best match". (But see §5.4: a *later* zone's
   query-time match can only be finalized once *earlier* zones' response
   triggers have had their chance, and §5.5: a `disabled` zone's match does
   not consume the query.)
2. **Within a zone, across trigger types:** CLIENT-IP > QNAME > IP
   (> NSDNAME > NSIP when they exist).
3. **Within QNAME:** exact beats wildcard; among wildcards, the longest
   (most labels).
4. **Within IP triggers:** longest prefix; on equal length, the numerically
   smallest address compared as a 128-bit value, IPv4 prefixes mapped with
   +96 — never a textual comparison.

The per-query cost for a non-matching query — the overwhelming majority —
is one folded-key build plus one map probe per zone (plus the parent walk
when wildcards exist), zero allocations. This gets a pinned allocation test
exactly like blocklist's.

### 5.4 Chain seat and query-time flow

`rpz` registers **immediately after `blocklist`** in
`middleware/defaults/defaults.go`. Consequences, both deliberate:

- Blocklist wins on overlap (it answers first). RPZ PASSTHRU exempts a name
  from *RPZ*, not from the blocklist — RPZ is an additional policy layer,
  not a whitelist over existing blocking (open decision D2 if the reviewer
  disagrees).
- RPZ runs ahead of the cache, so QNAME/CLIENT-IP policy applies to every
  client query including cache hits, and reloads take effect immediately
  (C3).

The middleware declares `ClientOnly() bool { return true }`: internal
sub-queries (QM probes, glue chases, trust-anchor refreshes) are never
policy-checked — rewriting those would corrupt resolution itself.

**Policy applies to RD=1 client queries only** (`Request.RD()`,
`middleware/request.go:168` — a wire header bit, no decode). `ClientOnly`
excludes internal traffic but not an external RD=0 query; the draft's
subscriber behavior is recursive-service policy. SDNS's resolver already
refuses external RD=0, but the cache
sits ahead of that refusal, so the RD gate in rpz is load-bearing, not
belt-and-braces. (Refusal site: `middleware/resolver/handler.go:143`.)

**When may a query-time match answer without recursing?** Not
unconditionally — the first design got this wrong and review caught it.
Zone order outranks trigger type (rule 1), so a QNAME match in zone *k* can
still be displaced by a response-trigger match in any zone *earlier* than
*k*, which cannot be known before recursion; the draft gives exactly this
example. The rule is therefore:

> A CLIENT-IP/QNAME match in zone *k* is final immediately **iff no zone
> before *k* carries any response trigger** (IP/NSDNAME/NSIP). Otherwise it
> is held as a *candidate*: the chain proceeds — to resolution on a miss,
> to the cache on a hit — and the candidate meets the response-trigger
> candidates (fresh on a miss, sidecar-carried on a hit, §5.6) in one
> serve-time merge where the best match under rules 1–2 wins. The held
> candidate survives the cache either way; a hit whose entry matched no
> response trigger still answers with the held QNAME action.

Each zone's "carries response triggers" bit is computed at load, so the
test is one flag scan over the zones ahead of the match — and in phases 1–2
no response triggers exist anywhere, so every match is final immediately
and the fast path is universal. Deployments that keep qname-only feeds
first (the common shape) keep the fast path even after phase 4.

### 5.5 Shadow mode

`mode = "shadow"` is the default, mirroring the recursion firewall: every
match is counted and logged at Debug, nothing is rewritten. `enforce` acts.
An operator turns on a 5M-rule commercial feed in shadow, watches the
counters for a day, then flips.

The counting semantic, precisely: **per query, one count per zone, for
the zones the hypothetical enforcement selection would evaluate — up to
and including the first enabled winner — and no further.** Each counted
zone contributes the action it would have taken (its best match under
§5.3's rules — one decision per zone, not one per rule). The winner is
labeled `outcome="enforced"` when it acted and `outcome="observed"` in
shadow mode; zones evaluated before it that matched — `disabled` zones,
and losers under precedence — count as `observed`; zones *after* the
winner are not counted **in either mode**.

Cutting at the winner is forced by §5.4 and is the only semantic both
modes can honor: on the immediate-answer path enforcement never recurses,
so later zones' response-trigger matches are unknowable there — while
shadow, which recurses for the truth anyway, would see them. Counting
what only one mode can know is exactly the incomparability the label was
built to prevent, and buying the information for enforce mode would mean
recursing for telemetry — the fast path traded for a counter. What the
cut costs is explicit: a zone positioned after a busy winner undercounts
relative to its raw match rate. What it buys is the guarantee the
soak-then-flip workflow actually needs — the numbers predict what changes
when the operator flips, because they count precisely the decisions
enforcement will make.

Per-zone `policy = "disabled"` gives the same observability for one zone
while others enforce — and, per draft §6.1, a disabled zone's match **must
not consume the query**: it is logged as what *would* have happened and then
excluded from selection, so a lower-precedence zone's rule still enforces.
Concretely, selection collects candidates across zones, logs any from
disabled zones, and picks the best among the enabled ones; "first zone wins"
(rule 1) is applied over enabled zones only. A disabled zone behaving as an
accidental global PASSTHRU is the regression the phase 1 tests pin.

### 5.6 Response-IP: truth in the cache, verdict beside it (phase 4)

The first design ("rewrite before the cache stores it") was wrong twice
over, and the review established both:

- **It is not implementable with writer order.** With rpz ahead of the
  cache, rpz's writer is the *outer* layer; the cache's `WriteMsg` stores
  the response (`SetFromResponseWithKey`/`Scoped`,
  `middleware/cache/cache.go:1826–:1835`) *before* forwarding to the
  wrapped writer (`:1880`). The rewrite would land after the store: cold miss
  filtered, every later wire hit serving the unfiltered truth.
- **It would be wrong even if implementable** (C3): the shared cache would
  carry one client's policy outcome into every client's answers, and a
  CLIENT-IP PASSTHRU client could never get the truth back.

The design follows the draft's model — the cache holds truth, policy is
applied to the client's response. The second review round corrected the
sidecar's *type*: it is not a final verdict but one input to a decision
that is only complete at serve time.

1. **The cache always stores what the resolver produced.** No RPZ code
   touches admission's stored bytes.

2. **The sidecar is an entry-local list of response-trigger *matches*,
   never a final action.** At evaluation it records, for *every* zone
   whose response triggers matched the entry's records — enabled,
   disabled, and shadow alike, uniformly — that zone's best match under
   §5.3's rules, or an explicit *none* when no zone matched. There is no
   privileged "best enabled candidate" field: the winner is computed at
   the serve-time merge, which selects under rule 1 over the enabled
   zones, so a zone flipping between `disabled` and enforce on reload
   changes selection, not the stored data. Uniformity is forced by a
   simpler fact: **the winner is a property of the query, not of the
   entry.** The same cached entry serves clients whose query-time
   triggers select different winning zones (a CLIENT-IP rule matches one
   client and not another), so the entry-local list cannot pre-filter by
   winner — it records every matching zone, and the merge applies §5.5's
   winner-bounded counting cut per query. A bare zone bitmap fails for
   the same family of reasons: the
   action series needs the action label, and two segments of one chase
   can match the same zone through different rules — neither is
   reconstructible from "zone X matched". The serve flow, in order:
   fold + per-zone dedupe (§5.6 item 4), find the first enabled winner
   across query-time and listed matches, then **count only the records
   up to and including the winner** (§5.5's cut) — all field reads and
   counter increments, no decode.

   **Candidates and observations alike carry their rank key, not just
   their outcome:** trigger type, prefix length, and the canonical
   128-bit matched address (IPv4 mapped, +96) beside zone index and
   action. The chase fold makes this necessary — two segments can carry
   same-zone IP candidates (`/32 PASSTHRU` on the target, `/24 NXDOMAIN`
   on the alias), and rules 2/4 of §5.3 cannot choose between them from
   `(zone, action)` alone. The rank key is what lets a fold anywhere
   re-run the precedence comparison the original evaluation ran.

   **The match list is lossless, not capped.** One record per matching
   zone per entry — the best match under §5.3's rules, which is also the
   counting semantic §5.5 defines — and the configured zone count is
   bounded (≤ 64, enforced by `Validate()`), so the list is sized by
   configuration, never by feed content. No overflow counter, because
   there is nothing to overflow.

   Finality is impossible earlier: a "clean" entry still loses to a QNAME
   candidate held under §5.4 (zone 1 carries response triggers that miss;
   zone 2's QNAME→NXDOMAIN must still fire), which a final-verdict model
   silently dropped.

   **The candidate is a value copy, never a pointer into the snapshot —
   and for Local Data that means a *deep* copy.** Copying a `[]dns.RR`
   copies the slice header and the interface values; the RR objects those
   interfaces point at still live in the old snapshot's allocations, and
   the invariant would be satisfied in name while pinning the store in
   fact. Local-data candidates therefore clone each record into fresh
   backing (`dns.Copy` or equivalent) at stamp time. A rule *reference*
   of any kind would pin the entire old policy store until the last entry
   stamped under it was served or evicted, and a few reloads of a 500 MB
   feed would stack retained generations; §10's "the swap drops the old
   reference" only holds if nothing else can reach the old store. The
   cost lands only where it matters: the overwhelming majority of
   candidates are *none* and carry nothing, and code-only actions carry a
   few bytes.

3. **The final action is chosen at serve time** by merging the query-time
   candidates (CLIENT-IP/QNAME, held per §5.4) with the sidecar
   candidate(s) under the ordinary precedence rules (§5.3, rules 1–2). A
   hit with all candidates *none* serves the stored wire exactly as today —
   a field check, no decode, C1 intact. A winning rewrite candidate
   synthesizes the policy answer per client (small, per-response, like
   blocklist's answers today).

4. **CNAME chains carry one candidate per segment.** The cache stores a
   chase as separate entries — `filterCacheableAnswer`
   (`middleware/cache/cache.go:1981`) splits the admission answer, and a
   wire hit recomposes alias + current target entries
   (`middleware/cache/entry_wire_chase.go`, `composeWireChase`). A single
   whole-answer verdict on the alias entry would go stale the moment the
   target entry refreshed under it. So each entry's candidate covers its
   own records only; the wire chase folds the match lists of every
   segment it composes, **deduplicating per zone by the rank key** — two
   segments matching the same zone collapse to that zone's single best
   match, so one query counts a zone exactly once; and a segment whose
   list is absent or generation-stale drops that hit to the Msg path,
   where it is evaluated and re-stamped.

5. **One atomic policy snapshot.** Rules and generation travel in a single
   immutable object behind one `atomic.Pointer` — read once per
   evaluation, so a candidate can never be computed from the old rules and
   stamped with the new generation (the reload race a separate
   store+counter pair permits). Entry sidecars are updated by CAS on a
   pointer beside the immutable `CacheEntry`; the serve that finds a stale
   candidate re-evaluates first and answers *that same query* from the
   fresh result — the old candidate is never served one last time.

6. **The evaluator hooks the `Store`, not the cache's ResponseWriter.**
   Admission has three doors, and only one of them is the writer:
   `SetFromResponseWithKey/Scoped` (the writer,
   `middleware/cache/cache.go:1826–:1835`), the resolver's direct
   `SetFromResponseWithCut` (`middleware/resolver/resolver.go:3077` via
   `middleware/wiring.go:73`), and prefetch's `ReplaceIfCurrent`
   (`middleware/cache/prefetch_queue.go:189`). Hooking the Store covers
   all three with one seam (self-declared via the `middleware.Setup`
   marker pattern, designed in phase 4's own PR). And because a fourth
   door may exist someday: **an absent sidecar means *unknown*, never
   *clean*** — such a hit takes the Msg path once, is evaluated, and is
   stamped.

The miss-path client response is rewritten by rpz's own writer (outer
layer — that ordering *is* correct for the client-facing copy), applying
the same serve-time merge, so the first client and every later client see
the same policy answer while the cache underneath holds the truth.

### 5.7 DNSSEC stance

Rewrites apply to all clients, DO=1 included: AD cleared, DNSSEC records
stripped, policy-zone SOA in the additional section, EDE 17 attached (C2).
A validating stub behind us will see the rewrite as bogus for signed names —
that is inherent to RPZ, and the SOA + EDE pair is the honest signal the
protocol provides for it. No `break-dnssec`-style
DO=1 exemption in v1: it would let any DO-setting client (which is most
modern stubs) bypass policy entirely, which defeats the operator's intent.
Flagged as open decision D3.

### 5.8 Zone sources and reload

- **Phase 1: local file.** Parsed with miekg's ZoneParser on load; compiled
  to the immutable store; swapped via `atomic.Pointer[store]`. The watch
  follows hostsfile's proven shape — parent directory watched, events
  filtered by basename, 100 ms debounce
  (`middleware/hostsfile/hostsfile.go:549,:575,:584`) — because a watch on
  the file itself dies with the old inode when a feed is replaced by
  atomic rename, which is exactly how feeds are pushed. Reload failures
  keep the old store and count `rpz_reload_errors_total{zone}` — a bad
  push never leaves the resolver unprotected or half-loaded.
- **Phase 3: AXFR.** The localroot transfer machinery is the right *model*
  but is not directly reusable: `axfr`/`probeSerial` are unexported, the
  zone name is hardcoded to the root, and the Manager is bound to root
  ZONEMD/trust-anchor verification and root-scale limits. Phase 3's first
  work item is therefore extracting a generic secondary-zone transfer +
  SOA-schedule core (an `internal/` package parameterized by zone name and
  verification hook) that localroot then also consumes — the same shape as
  the `internal/emptyzones` extraction. What carries over as design: SOA
  refresh/retry/expire scheduling, serial probe before transfer, RFC 1982
  anti-rollback. On SOA *expire* with no successful refresh, the zone's
  rules are withdrawn (fail-open on that zone) and a Warn names it —
  matching localroot's "a copy that cannot be refreshed is withdrawn".
  TSIG for feed auth is decided here, not in phase 1: the hyperlocal
  rejection of TSIG was root-specific (ZONEMD end-to-end beats channel
  auth; no root source offers TSIG) and does not transfer to commercial
  RPZ feeds, which have no ZONEMD and do offer TSIG. NOTIFY/IXFR remain
  out until an operator need shows (§8).

### 5.9 Config

```toml
[rpz]
enabled = true
mode = "shadow"                  # shadow | enforce

[[rpz.zone]]
name = "badfeed"                 # label for metrics/logs/EDE text
file = "/var/lib/sdns/badfeed.zone"
policy = "given"                 # given|passthru|nxdomain|nodata|drop|tcp-only|cname|disabled
# cname = "garden.example.com."  # required iff policy = "cname"
# phase 3 adds: source = "203.0.113.5:53" (+ optional tsig keyfile)
```

`policy` overrides every action in that zone; `given` uses what the rule
says. The set includes `cname` — the draft's §6.1 "CNAME domain" override
(SHOULD), which rewrites every match in the zone to the configured target,
the walled-garden override commercial deployments use; `Validate()` requires
`cname` to be a parseable FQDN exactly when `policy = "cname"`, and rejects
it otherwise, per the enablement-gate rules. Zone order in the file is
evaluation order.

`Validate()` additions follow the PR #592 rules: judged only when
`enabled`, with the same parser the runtime uses — `sdns -t` parses each
zone file and reports rule counts and skips, so a broken feed fails the
check run, not the daemon. The zone list is capped at 64 (§5.6 sizes the
sidecar observation list by this bound); BIND's own response-policy limit
is the same order, so no real deployment is constrained.

### 5.10 Metrics

```
rpz_action_total{zone,trigger,action,outcome}   # outcome: enforced|observed (§5.5)
rpz_zone_rules{zone,trigger}         # gauge, set on load
rpz_zone_rules_skipped{zone,reason}
rpz_reload_errors_total{zone}
rpz_zone_serial{zone}                # phase 3; -1 when file-sourced
```

The global mode is config state and needs no label: `outcome` carries what
matters — in shadow mode everything is `observed`; in enforce mode exactly
one match per acting query is `enforced` and the rest stay `observed`.

### 5.11 Performance and allocation contract

RPZ lands on a serving path that took a year of work to make
allocation-free, and it is not allowed to give any of that back. These are
commitments with named enforcement, not aspirations; a phase that cannot
meet its line does not merge.

| Path | Budget | Enforced by |
| --- | --- | --- |
| Non-matching query (the overwhelming majority — this is the product's steady state) | **0 heap allocations**; one stack folded-key build + one map probe per zone + parent walk only where wildcards exist | `AllocsPerRun` pin in `middleware/rpz`, the blocklist pattern; runs in the CI allocation gate |
| Cache hit, no candidate anywhere | **0 allocations beyond today's wire path** — the existing hit-class pins must stay green *unchanged*, which is itself the proof RPZ added nothing | existing `Alloc\|ServeRawHitClasses` gate |
| Sidecar "none" | **not an allocation**: the empty match list is a nil/inline field, so the no-match world pays no per-entry memory | asserted in the phase 4 seam's own pins |
| CLIENT-IP lookup | zero-alloc; probe count bounded and measured (§5.3) | phase 2 adversarial-feed benchmark, budget stated in the PR |
| Match + synthesis (rare by definition) | bounded, small, comparable to blocklist's answers today; never on the non-matching path | benchmark beside the synthesis code |
| Serve-time merge + counting | field reads and counter increments off compact structs; no decode, no map allocation | hit-path pins above cover it structurally |
| Load / reload | off the hot path; transiently two stores during swap, old generation collectible immediately (deep-copy invariant, §5.6) | phase 4 heap test; 5M-rule load-time measurement in phase 1 |

Two measurements sit above the unit level, per the bench discipline
(`contrib/bench/resolver_bench.py`, verified-warm, interleaved medians):

- **Phase 1, before any enforce rollout:** serving A/B on the bench box —
  rpz disabled vs rpz in shadow with a multi-million-rule feed loaded.
  Shadow is the honest worst case for the hot path: it pays every lookup
  and never short-circuits with an answer. The headline throughput
  numbers must hold; a regression the A/B can measure is a blocker, per
  the standing rule that speed is an exit criterion.
- **Phase 4:** the same A/B repeated once sidecars exist, because that is
  when the hit path gains its field reads.

Shadow and enforce cost the same on the non-matching path by
construction — the modes differ only after a match.

## 6. Phasing and exit criteria

Each phase is a separately mergeable PR with its own verification; later
phases touch nothing a prior phase pinned.

**Phase 1 — engine + QNAME + all six actions + file source + shadow/enforce.**
Exit: RPZ-encoded fixture zones load; each action verified end-to-end
against a loopback authority (per the no-live-network rule), Local Data
including QTYPE=ANY, the CNAME chase, and wildcard-target expansion;
precedence rules 1/3 mutation-tested with competing rules prescribing
different actions; a `disabled` zone shown not to consume a match a later
enforcing zone holds; a CNAME into an unrecognized `rpz-*` target skipped
and counted, never answered; a wildcard-rule Local Data answer carries the
client's qname as owner, never the wildcard; the `policy = "cname"`
override rewrites a whole zone's matches; the RD=0 gate pinned; rewrites
carry policy-zone SOA + EDE 17 and never AD; non-matching-query alloc pin
at zero; full suite + lint green; `sdns -t` reports zone health; the
§5.11 bench-box A/B (disabled vs shadow with a large feed) holds the
headline numbers before any enforce rollout.

**Phase 2 — CLIENT-IP trigger.**
Exit: v4/v6 prefix encodings (incl. `zz`) parse round-trip; within-zone
precedence rule 2 (CLIENT-IP over QNAME) mutation-tested; alloc pin still
zero; LPM lookup benchmarked against an adversarial all-lengths v6 feed
with a stated per-query budget — the length-map walk survives it or is
replaced by a radix before merge (§5.3); a CLIENT-IP rule carrying Local
Data answers with the client's qname as owner — the address-encoded
trigger owner never appears in a response.

**Phase 3 — AXFR source.**
Exit: transfer against a loopback RPZ server; serial rollback refused;
expire withdraws the zone with the metric trail; reload swap is atomic
under concurrent queries (`-race`).

**Phase 4 — response-IP via sidecar candidates (§5.6).**
Prerequisite: the Store admission/serve seam, designed and reviewed in this
phase's own PR. Exit:

- cache stores byte-identical with rpz on and off (truth invariant,
  asserted directly);
- all-candidates-none hits stay on the existing wire path with the alloc
  gates green;
- **the review's P0 scenario verbatim:** zone 1 carries response-IP rules
  that do *not* match the answer, zone 2 QNAME→NXDOMAIN matches — the hit
  must answer NXDOMAIN, not the stored truth (serve-time merge over a
  none-candidate sidecar);
- **the CNAME scenario verbatim:** an alias entry whose target entry is
  refreshed to an address that newly matches (and one that newly stops
  matching) — the chase hit reflects the current target, via per-segment
  candidates or the Msg-path drop, never a stale whole-answer verdict;
- a CLIENT-IP PASSTHRU client receives the truth while a plain client
  receives the rewrite from the same entry;
- reload atomicity: candidates computed under snapshot N are never stamped
  with generation N+1 (single-pointer snapshot, `-race` exercised across
  concurrent reload+serve), and the first serve that finds a stale
  candidate answers from the fresh evaluation, mutation-tested;
- admission via the resolver's direct store and via prefetch replacement
  both leave evaluated sidecars — or absent ones that the first hit
  treats as unknown, never clean;
- the §5.11 bench-box A/B repeated with sidecars live;
- old-generation collectibility: load a large feed, match, reload, force
  GC — the old snapshot's memory is returned. The matched entries **must
  include a Local Data candidate**: record deep-copying is exactly the
  clause a shallow-slice implementation would silently violate (§5.6);
- counting honors the winner-bounded cut (§5.5) identically on both
  paths: a zone *before* the winner that matched — disabled, or a
  precedence loser — is counted with the right `outcome` on wire hits;
  a zone *after* the winner is counted in neither mode, and in
  particular an immediate-answer enforce query and the same query in
  shadow produce identical per-zone counts;
- a chase whose segments match the same zone through different rules
  counts that zone once, with the rank-key-best match (fold dedup,
  §5.6).

Shadow-mode canary soak between phase 1 and enforce anywhere, same as the
recursion firewall rollout.

## 7. Explicitly deferred

NSDNAME/NSIP triggers (require inspecting delegation data mid-resolution —
a resolver-internal seam, not a middleware; design when wanted), NOTIFY,
IXFR, RPZ-publisher mode, per-view RPZ bindings, API endpoints.

## 8. Deliberate absences (recorded so they are not re-proposed)

- **QNAME policy on CNAME-chain names:** v1 checks the client's qname only.
  Chasing happens inside the resolver; hooking every chained name is a
  resolver seam with C1 implications. Absence is visible (draft feature),
  deliberate, and revisitable with NSDNAME.
- **max-policy-ttl clamp:** local-data TTLs come from the operator's own
  zone file; clamping what they explicitly wrote adds a knob without a
  driving need.
- **Cache invalidation on policy reload** (§5.6): not needed under the
  sidecar design — a stale candidate is *never applied*: the first serve
  that finds one re-evaluates under the current snapshot and answers that
  same query from the fresh result. The reload's residual cost is that one
  re-evaluation per entry, not a window of stale answers; no cache walking
  or flushing.
- **DO=1 exemption** (§5.7): would make policy bypassable by any modern stub.
- **A knob to disable the immediate-answer optimization** (draft SHOULD,
  BIND's `qname-wait-recurse`): the draft's stated motive is
  counterintelligence — an operator may want the upstream query to happen
  anyway so the policy's presence is not inferable. One boolean when an
  operator asks; the winner-bounded counting semantic (§5.5) is unaffected
  either way, so nothing in the design has to move.
- **Compound per-zone overrides** (`LOCAL-DATA-OR-PASSTHRU`,
  `LOCAL-DATA-OR-DISABLED` from the draft's override list): niche
  combinations of primitives v1 already has; added when a feed or an
  operator actually needs them.

## 9. Open decisions for the reviewer

- **D1 — v1 trigger scope.** Proposed: QNAME (phase 1) + CLIENT-IP
  (phase 2). Is shipping phase 1 alone as a first PR acceptable?
- **D2 — blocklist relationship** (§5.4). Proposed: independent layers,
  blocklist first, PASSTHRU does not override blocklist. The alternative
  (RPZ before blocklist, PASSTHRU as a global whitelist) changes the
  blocklist's current absoluteness.
- **D3 — DNSSEC stance** (§5.7). Proposed: rewrite for all, EDE 17, no
  DO=1 exemption. BIND's default differs (break-dnssec no).
- **D4 — TCP-Only on non-UDP transports** (§5.2). Proposed: every non-UDP
  transport satisfies the trigger's anti-spoofing intent (PASSTHRU) — the
  `Proto() == "udp"` predicate, not an enumerated list.

## 10. Risks

- **Feed scale.** Commercial feeds run 1–5M rules; the two-map shape costs
  roughly the same as blocklist at equal size (already proven at millions of
  entries). Load-time parse of 5M records via ZoneParser needs a one-off
  measurement in phase 1; reload is off the hot path but must not pin two
  full stores for long — the swap drops the old reference immediately,
  and that only frees anything because sidecars carry value copies, never
  pointers into the snapshot (§5.6): the collectibility of an old
  generation is an invariant of the sidecar's type, and phase 4 asserts it
  (load, match, reload, force GC, compare heap).
- **Ordering regressions.** The rpz slot in `defaults.go` sits in the
  client-facing prefix; a future reorder could silently move it behind the
  cache. Phase 1 adds a test asserting the seat (rpz before cache, after
  blocklist).
- **Trigger precedence bugs are silent.** Wrong precedence returns *a*
  policy answer, just the wrong one. Every precedence rule gets a fixture
  where the competing rules prescribe *different actions*, so a precedence
  swap changes observable output and the test goes red (the mutation
  discipline used throughout #592).

## 11. Review history

Eight rounds of external review shaped this document; each round's findings
were verified against the code before acceptance. One line per round:

1. (8 findings) Cross-zone precedence forced the candidate-hold rule; writer
   order proven unable to rewrite before the cache store; truth-in-cache
   established; Local Data specified; payload LPM replaces `ipset`; disabled
   zones don't consume; RD=1 gate; generic transfer core for phase 3.
2. (5) Sidecar became a *candidate* merged at serve time, not a verdict;
   per-segment candidates for CNAME chases; atomic policy snapshot; Store
   seam covers all admission doors; LPM probe budget.
3. (6) Unknown `rpz-*` targets are unsupported actions, never Local Data;
   bounded observability beside the candidate; value copies so old
   generations stay collectible; dir-watch reload; wording+refs.
4. (5) Local Data owner is always the client's qname; deep copy (not slice
   header) for the collectibility invariant; `CNAME domain` override into
   the grammar; observations carry action labels; TCP-Only as a predicate.
5. (3) Rank key (trigger, prefix len, 128-bit address) on candidates and
   observations; lossless per-zone lists under a ≤64-zone cap; `tls` label.
6. (1) Uniform all-zones match list — the winner is per-query, so the entry
   cannot pre-filter; `outcome=enforced|observed` replaces `mode`.
7. (1) Winner-bounded counting: only zones up to the first enabled winner
   count, in both modes — the immediate-answer path makes anything more
   unknowable to enforce mode. §5.11 performance contract consolidated.
8. (1, editorial) The serve flow restated to match the cut: merge + dedupe,
   find the winner, count only up to it. Review history compacted into this
   section; verdict: ready to implement.

After round 8, the full draft text was fetched and compared against this
document section by section. Confirmed verbatim: all trigger and action
encodings, all four precedence rules (including "smaller IP address" on the
prefix tie and most-labels among wildcards), Local Data ANY/CNAME semantics,
the excluded record types, SOA-in-additional, the DISABLED behavior, and
the immediate-answer optimization's safety condition (the draft's "cache
plus precedence sufficient for a final result" MAY, which §5.4's rule
instantiates). Newly captured from that pass: the `zz` last-run compression
subtlety (§5.1), the wildcard-CNAME *prepend* wording (§5.2), and two
recorded absences — the draft's SHOULD-level knob to disable the
immediate-answer optimization, and the compound per-zone overrides (§8).
