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

In these cases no A lookup is made and nothing is synthesised; the reply goes
to the client as the resolver produced it:

- **NXDOMAIN.** The name does not exist. Synthesising anything would invent it.
- **SERVFAIL carrying a DNSSEC-failure Extended DNS Error.** DNS64 must never
  mask a validation failure (RFC 6147 §5.5), so a signed name that failed to
  validate stays failed.
- **Clients that set RD=0 or CD=1.** Both say "do not do anything clever on my
  behalf", and DNS64 is the definition of clever.
- **Truncated replies, and replies with no question section.**
- **Cached failures.** A failure served from the RFC 9520 failure cache (EDE 13,
  Cached Error) must not trigger a new outgoing query while its backoff runs,
  so no A lookup is made.
- **Failures local to the request**, including one that hit the resolution
  attempt limit. Asking again for the A record would only repeat them.
- **SERVFAIL from the recursion firewall.** When the work budget ends a
  resolution, the client gets that SERVFAIL rather than a second lookup.

A pass-through is not always byte for byte. AAAA records inside
`exclude_aaaa_networks` are removed even when the reply is otherwise passed
through (see below). When that removes anything, AD is cleared, and if the
upstream reply had AD set, EDE 4 (Forged Answer) is attached. The same holds
when the removal leaves no AAAA and the A lookup then fails: the stripped
reply that goes out instead carries no AD either.

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
exclude_a_networks    = ["10.0.0.0/8", "192.168.0.0/16"]  # list shortened here
```

`exclude_aaaa_networks` filters AAAA records out of the upstream response before
deciding between pass-through and synthesis (RFC 6147 §5.1.4). The default is the
IPv4-mapped range: an upstream that wrongly returns `::ffff:...` AAAAs is treated
as having returned no AAAA at all, so sdns synthesises a routable address from
the corresponding A instead of handing the client something unusable.

`exclude_a_networks` lists IPv4 networks not to synthesise from when the
Well-Known Prefix is active, since RFC 6052 §3.1 forbids embedding non-global
addresses in it. The shipped defaults mirror the IANA Special-Purpose Address
Registry. A list you set replaces those defaults rather than adding to them, so
copy the defaults into it when you only mean to extend them; an explicit `[]`
turns the exclusion off. Operator-chosen network-specific prefixes ignore this
list, since the constraint is specific to the Well-Known Prefix.

## Reverse lookups

A PTR query for an `ip6.arpa` name inside one of the configured prefixes is
translated (RFC 6147 §5.3.1). sdns extracts the embedded IPv4 address and
answers with a CNAME to the matching `in-addr.arpa` name, with a TTL of 600
seconds. It then looks up that PTR itself and, if the lookup succeeds, appends
the PTR records to the same reply; if it fails, the client gets the CNAME alone
and can follow it. Two failures are the exception and answer SERVFAIL instead:
a lookup the recursion firewall stopped for exceeding its work budget, and one
that hit the request's resolution attempt limit.

The same gates apply as for AAAA: RD=1, CD=0 and a client inside
`client_networks`. Under the Well-Known Prefix an address in
`exclude_a_networks` is not translated. An `ip6.arpa` name outside every
configured prefix resolves normally.

## Watching it

```
dns64_synthesised_total         AAAA queries answered with synthesised records
dns64_passthrough_total         queries left untouched, by reason
dns64_a_lookup_failures_total   secondary A lookups that gave nothing usable, by reason
dns64_ptr_translated_total      ip6.arpa PTR queries answered with a CNAME
```

`dns64_passthrough_total` with `reason="aaaa_present"` is the normal case: the
name has a real AAAA. The `internal`, `no_rd`, `cd_bit` and `client_excluded`
reasons are counted before the query type is checked, so they include queries
of every type, not only AAAA.
