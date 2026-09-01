---
layout: doc
title: Overview
permalink: /docs/
category: Getting Started
order: 0
description: What sdns is, and how these pages are arranged.
---

sdns is a recursive DNS resolver. It answers a query by walking the delegation
chain from the root, validates the answer against the DNSSEC trust anchors, and
caches it. It also speaks DNS over TLS, HTTPS and QUIC, and can be pointed at
upstream resolvers instead of resolving for itself.

## How the query path is built

Every request passes through a chain of middlewares. Each one may answer the
query, change it, or hand it to the next:

```
recovery → metrics → dnstap → accesslist → ratelimit → reflex → edns
  → accesslog → chaos → hostsfile → views → blocklist → rpz → as112
  → kubernetes → dns64 → cache → failover → resolver → forwarder
```

That order explains a good deal of the behaviour. Access control and rate
limiting run before anything expensive. A view answers before the blocklist or
a policy zone is consulted. Policy is decided before the cache, which is why
the cache can hold an unmodified answer while a client still receives a policed
one. The resolver runs only when nothing earlier produced an answer, and the
forwarder sits behind it as the whole-server alternative path.

## Where to start

If you are installing for the first time, read
[Installation]({{ '/docs/getting-started/installation/' | relative_url }}) and
then [Your first configuration]({{ '/docs/getting-started/first-config/' | relative_url }}).
Together they get you to a validating resolver you can query.

If you are looking for one specific setting, the **Configuration** pages group
every key by what it does. The
[configuration key index]({{ '/docs/reference/config-keys/' | relative_url }})
lists all of them alphabetically with their defaults.

If you are deciding whether a feature fits your deployment, the **Features**
pages describe what each one does, what it costs, and what it deliberately does
not do.

## Two conventions worth knowing up front

**Features ship off.** Every capability added after a release is disabled, or in
a counting-only shadow mode, until you enable it. An upgrade does not change how
your resolver answers.

**The configuration file is checked as a whole.** `sdns -t -c file` parses the
file the way the server will and reports every problem it finds at once, rather
than stopping at the first. It is worth running in the deploy pipeline, not only
by hand.
