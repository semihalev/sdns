---
layout: doc
title: Middleware
category: Development
order: 2
description: The handler contract, the chain, and where a new middleware goes in it.
---

Every query is served by a chain of middlewares. Each is a `Handler`:

```go
type Handler interface {
    // Name must match the name used in Register so Pipeline.Get
    // can resolve the handler back.
    Name() string

    // ServeDNS processes a query. Call ch.Next to continue the chain,
    // or ch.Cancel / ch.CancelWithRcode to stop it.
    ServeDNS(ctx context.Context, ch *Chain)
}
```

A middleware either answers the query and stops the chain, or modifies
something and continues it:

```go
ch.Next(ctx)                    // continue
ch.Cancel()                     // stop, writing nothing further
ch.CancelWithRcode(rcode, do)   // write a reply with this rcode, then stop
```

Only `Next` takes the context. `do` on `CancelWithRcode` sets the DO bit on the
response's OPT record — it is not an authoritative flag.

## The default chain

```
recovery → metrics → dnstap → accesslist → ratelimit → reflex → edns
  → accesslog → chaos → hostsfile → views → blocklist → rpz → as112
  → kubernetes → dns64 → cache → failover → resolver → forwarder
```

The order lives in `middleware/defaults`, which is generated. It is a package
rather than an `init` in `main` specifically so that everything needing the real
chain can ask for it — the binary, the benchmarks, a test harness. When the list
lived in `main` each of those kept its own copy, and they drifted; a benchmark
quietly measuring five handlers fewer than production still reports a number.

`RegisterUpTo(name)` registers the chain up to but not including `name`, which
is how a harness replaces the tail with a stub while keeping everything ahead of
it real.

## Registering

```go
func init() {
    middleware.Register("myfilter", func(cfg *config.Config) middleware.Handler {
        return New(cfg)
    })
}
```

`Register` appends to the end. When placement matters:

- `RegisterAt(name, ctor, idx)` — at an index; out of range panics.
- `RegisterBefore(name, ctor, before)` — immediately before a named middleware;
  panics if the target is not registered.

Registering a name twice panics. That is intentional: a duplicate name means
`Pipeline.Get` cannot resolve the handler, and failing at startup is better than
resolving to the wrong one.

## Where to put a new middleware

Position is a design decision, not a detail:

- **Before `cache`** if it must see every query, including ones the cache would
  answer. Policy and filtering belong here — this is where dynamic plugins are
  inserted.
- **After `cache`** if it only concerns queries that actually need resolving.
- **Before `accesslist`** essentially never; nothing should run ahead of access
  control except recovery and instrumentation.

## Self-declaring middleware

A middleware that needs wiring beyond construction declares it through a marker
or setter interface that `middleware.Setup` looks for, rather than by adding a
branch to the server's startup code. Keeping the knowledge in the middleware is
what lets the chain stay a list.

## Testing one

Build a chain with just your handler and a stub behind it, feed it a
`*dns.Msg`, and assert on what came back. `middleware.HandlerFunc` adapts a
plain function into a `Handler`, which is enough for the stub.

No assertion library, and no network — see
[Building and testing]({{ '/docs/development/building/' | relative_url }}).
