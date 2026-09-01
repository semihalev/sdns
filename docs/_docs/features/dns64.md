---
layout: doc
title: DNS64
category: Features
order: 6
description: Synthesising AAAA records so IPv6-only clients can reach IPv4-only services.
---

```toml
[dns64]
enabled  = true
prefixes = ["64:ff9b::/96"]
```

An IPv6-only client asks for a AAAA record; the service only has an A record.
DNS64 (RFC 6147) synthesises a AAAA by embedding the IPv4 address inside a
Pref64 prefix, which a NAT64 gateway then translates. Off by default.

## When synthesis happens

When a client's AAAA query returns NOERROR with no data, or any nonzero RCODE
other than NXDOMAIN, sdns issues an A query for the same name and synthesises
one AAAA per (A record, prefix) pair.

Three cases deliberately pass through untouched:

- **NXDOMAIN.** The name does not exist. Synthesising anything would invent it.
- **SERVFAIL carrying a DNSSEC-failure Extended DNS Error.** DNS64 must never
  mask a validation failure (RFC 6147 §5.5), so a signed name that failed to
  validate stays failed.
- **Clients that set RD=0 or CD=1.** Both say "do not do anything clever on my
  behalf", and DNS64 is the definition of clever.

## Prefixes

```toml
prefixes = ["64:ff9b::/96"]
```

Lengths must be one of /32, /40, /48, /56, /64 or /96 (RFC 6052). List several
to synthesise one AAAA per prefix, so a client sees every reachable NAT64 path
in a single reply.

`64:ff9b::/96` is the IANA Well-Known Prefix and the usual choice. If DNS64 is
enabled with no prefixes configured, that is the runtime default.

## Scoping

```toml
client_networks = ["2001:db8:1::/48"]
exclude_zones   = ["example.com."]
```

`client_networks` limits synthesis to given client CIDRs; empty means every
client. Restrict it to your IPv6-only subnets so dual-stack clients keep their
original answers.

`exclude_zones` names zones that must never be synthesised. The match is by
suffix: `"example.com."` covers the zone and everything under it.

## Address exclusions

```toml
exclude_aaaa_networks = ["::ffff:0:0/96"]
exclude_a_networks    = ["10.0.0.0/8", "192.168.0.0/16", ...]
```

`exclude_aaaa_networks` filters AAAA records out of the upstream response before
deciding between pass-through and synthesis (RFC 6147 §5.1.4). The default is the
IPv4-mapped range: an upstream that wrongly returns `::ffff:...` AAAAs is treated
as having returned no AAAA at all, so sdns synthesises a routable address from
the corresponding A instead of handing the client something unusable.

`exclude_a_networks` lists IPv4 networks not to synthesise from when the
Well-Known Prefix is active, RFC 6147 forbids embedding non-global addresses in
it. The shipped defaults mirror the IANA Special-Purpose Address Registry.
Operator-chosen network-specific prefixes ignore this list, since the constraint
is specific to the Well-Known Prefix.
