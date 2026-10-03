---
layout: doc
title: Local root zone
category: Features
order: 2
description: Serving the root from a verified local copy instead of querying the root servers.
---

```toml
hyperlocal_root = true
# hyperlocal_root_sources = ["b.root-servers.net:53", "k.root-servers.net:53"]
```

The root zone is small, public, signed, and changes slowly. RFC 8806 says a
resolver may just keep a copy. sdns transfers it over AXFR from the root servers
and ICANN hosts that offer it (b, c, d, f, g and k.root-servers.net,
xfr.cjr.dns.icann.org and xfr.lax.dns.icann.org), verifies it, and answers from
the copy.

Off by default; one key turns it on.

## What it changes

Root referrals, NXDOMAINs for junk TLDs, and questions asked at the root itself
are answered locally. They cost no upstream query and disclose nothing to the
root servers.

On a resolver that sees a lot of made-up names (misconfigured clients, search
suffixes, malware) that is a meaningful share of the query load that stops
leaving the machine.

## How the copy is trusted

The transferred zone is verified against its own ZONEMD digest (RFC 8976),
chained to the root trust anchors you already validate with. A copy that does
not verify is not used.

The copy refreshes on the zone's own SOA schedule. Its horizon is the earlier of
SOA expire and the earliest signature expiration in the zone. A healthy copy is
transferred again once it has spent half its horizon, even if the serial has
not changed. If it cannot be refreshed and reaches its horizon, it is withdrawn
and resolution falls back to the real root servers unchanged. It is also
withdrawn at once if the trust anchors that verified it are no longer the ones
the resolver holds, and the next refresh verifies a copy under the current
anchors. There is no state in which a stale root keeps answering.

Delegations to the TLDs taken from the copy are leased like any other. One
used in the last tenth of its lease is renewed from the copy, so a busy TLD
does not drop out of the cache at the end of its lease. Renewals are counted in
`dns_resolver_refresh_total`.

## Across restarts

Every verified copy is also written to `root.zone` in the state `directory`, and
the next start serves from it right away instead of waiting for a transfer. The
file gets no trust of its own. It passes the same ZONEMD check against the
trust anchors held at startup, and it keeps the age it had: its expire is
counted from when it was transferred, not from when it was read back. A copy
that expired while sdns was down, one that no longer verifies, or a file that
fails its checksum is not used, the first transfer happens as it would on a
fresh install, and the file is overwritten with that verified copy.

Reading it back adds the time to parse and verify the zone to startup, well
under a second for the real root on ordinary hardware.

## Sources

`hyperlocal_root_sources` overrides the built-in transfer hosts. Give
`host:port` entries. You would set this to use an internal distribution point,
or to pin to specific root servers your network reaches well.

## Watching it

```
dns_localroot_answers_total     root consultations, by kind (referral, denial, ds, apex, fallback)
dns_localroot_serial            serial of the copy in use, -1 when none is active
dns_localroot_copy_age_seconds  age of the copy in use since its transfer, -1 when none is active
dns_localroot_transfers_total   transfer attempts, by outcome
dns_localroot_disk_total        saved copy loads and writes, by result
```

A `fallback` consultation is one the copy did not answer, so the walk went to
the real root servers: no verified copy was active, or the copy held no proof
for the question.

`dns_localroot_copy_age_seconds` is the one to alert on. It climbing steadily
means refreshes are failing and the copy is walking toward its horizon, at
which point you silently go back to querying the root servers.
