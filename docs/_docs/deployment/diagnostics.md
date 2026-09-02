---
layout: doc
title: Diagnostics
category: Deployment
order: 4
description: The two debug switches, and how to work out why a name will not resolve.
---

Two environment variables turn on facilities that are off in normal operation.
The shipped systemd unit sets both to `false` explicitly.

```
SDNS_DEBUGNS=true    # answer CHAOS HINFO with per-authority RTT and health
SDNS_PPROF=true      # serve Go's /debug/pprof on the API listener
```

Both are read once at startup, so changing either means restarting the process.
Either value is parsed as a boolean, so `1`, `t` and `TRUE` work as well as
`true`.

## `SDNS_DEBUGNS`, which authority would answer, and how well

With this on, a CHAOS-class HINFO query returns the delegation sdns holds for
that name, one record per server, in the order the resolver would try them.

```bash
dig @127.0.0.1 CH HINFO example.com
```

```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29636
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 4

;; AUTHORITY SECTION:
example.com.  0  CH  HINFO  "Host" "IPv4:199.43.135.53:53 rtt:142ms rank:151ms health:[GOOD]"
example.com.  0  CH  HINFO  "Host" "IPv4:199.43.133.53:53 rtt:145ms rank:153ms health:[GOOD]"
example.com.  0  CH  HINFO  "Host" "IPv6:[2001:500:8f::53]:53 rtt:147ms rank:158ms health:[GOOD]"
example.com.  0  CH  HINFO  "Host" "IPv6:[2001:500:8d::53]:53 rtt:148ms rank:160ms health:[GOOD]"
```

The records are in the **authority** section, not the answer section, and carry
TTL 0. There is no answer to a question like this.

### Reading a line

`rtt` is the smoothed round-trip time actually measured. `rank` is what the
ordering sorts on, and it is deliberately not the same number: a server that has
never been measured is priced at a seed value rather than treated as instant,
and an old measurement drifts back toward that seed. Printing both is what makes
the order explicable, when a server with the lowest `rtt` is not first, its
`rank` says why.

`health` has four states:

| State | Meaning |
|---|---|
| `GOOD` | Measured, answering, under one second |
| `POOR` | Measured, answering, one second or slower |
| `FAILING` | Not answering |
| `UNKNOWN` | Never measured |

`FAILING` is reported ahead of `POOR` on purpose. A server that does not reply
is charged a timeout, and a timeout is also what a very slow server costs, so
priced by latency alone the two are indistinguishable. The label is the part
that separates them.

### Two things that will confuse you

**It reads the cache, not the network.** The delegation shown is the one sdns
already holds. Ask about a zone it has never resolved and you get the root
servers, because that is what it would start from. Resolve the name first, then
ask:

```bash
dig @127.0.0.1 example.com A     # populate the delegation
dig @127.0.0.1 CH HINFO example.com
```

**The name must match exactly.** The lookup is for an NS entry under the name
you asked about. It does not walk up to the enclosing zone. `CH HINFO
www.example.com` shows the root servers unless `www.example.com` is itself a
cut. Ask about the zone apex.

## `SDNS_PPROF`, Go profiles on the API listener

```
GET /debug/pprof/          index
GET /debug/pprof/profile   CPU profile (?seconds=N)
GET /debug/pprof/heap      heap
GET /debug/pprof/trace     execution trace
GET /debug/pprof/cmdline
GET /debug/pprof/symbol
```

```bash
go tool pprof http://127.0.0.1:8080/debug/pprof/profile?seconds=30
go tool pprof http://127.0.0.1:8080/debug/pprof/heap
```

`/debug/` redirects to `/debug/pprof/`.

### `bearertoken` does not protect these routes

Every other API route checks the token. The pprof routes do not, because pprof
tooling does not send an `Authorization` header, so they stay open even when a
token is set.

That makes the advice elsewhere on this site incomplete for this case: a token
is enough for the blocklist and purge endpoints, and it is **not** enough once
pprof is on. With `SDNS_PPROF=true`, keep the API listener on loopback or behind
an authenticating proxy. A reachable pprof endpoint hands out heap contents and
lets anyone force a 30-second CPU profile on your resolver.

Leave it off unless you are actively profiling.

## When a name will not resolve

Work down this list; each step rules something out.

**1. Read the Extended DNS Error.** A SERVFAIL from sdns usually carries a
machine-readable reason (RFC 8914) that says far more than the rcode.

```bash
dig @127.0.0.1 problem.example A +dnssec
```

**2. Is it policy rather than resolution?** A blocked or rewritten name is not a
failure. Check `dns_blocklist_hits_total`, and if you run policy zones check
`rpz_action_total`, in shadow mode it tells you what a match *would* have done
without anything having happened.

**3. Is the failure being cached back at you?** The RFC 9520 failure cache holds
a failed resolution for 5 seconds, backing off exponentially to 5 minutes on
repetition. A zone that has just been fixed can keep failing for minutes. Drop
the entry rather than waiting:

```bash
curl http://127.0.0.1:8080/api/v1/purge/problem.example./A
```

**4. Is it DNSSEC?** `dns_resolver_dnssec_failures_total` broken out by `reason`
separates a genuinely broken signer from a validation problem of your own. To
confirm the name resolves when validation is not applied, ask with `+cd`, if
`+cd` succeeds and the plain query does not, it is validation.

**5. Are the authorities reachable?** This is what `SDNS_DEBUGNS` is for. All
servers `FAILING` means the zone or the path to it is down; a mix means the
resolver is already routing around the bad ones.

**6. Is the work budget stopping it?** With the
[recursion firewall]({{ '/docs/features/recursion-firewall/' | relative_url }})
in enforce, an expensive resolution can be terminated. Check
`dns_recursion_firewall_exhaustions_total` by `reason`.

**7. Is it a query type sdns declines?** `ANY` is answered NOTIMP by design.

## Confirming what is running

```bash
dig @127.0.0.1 CH TXT version.bind +short
```

Works while `chaos = true`, which is the default. Across a fleet this is the
difference between knowing a deploy landed and assuming it did.
