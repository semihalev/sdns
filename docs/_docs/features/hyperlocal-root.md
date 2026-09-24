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
that offer it, verifies it, and answers from the copy.

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

The copy refreshes on the zone's own SOA schedule. If it cannot be refreshed and
reaches SOA expire, it is withdrawn and resolution falls back to the real root
servers unchanged. There is no state in which a stale root keeps answering.

## Across restarts

Every verified copy is also written to `root.zone` in the state `directory`, and
the next start serves from it right away instead of waiting for a transfer. The
file gets no trust of its own. It passes the same ZONEMD check against the
trust anchors held at startup, and it keeps the age it had: its expire is
counted from when it was transferred, not from when it was read back. A copy
that expired while sdns was down, one that no longer verifies, or a file that
fails its checksum is set aside, and the first transfer happens as it would on
a fresh install.

Reading it back adds the time to parse and verify the zone to startup, well
under a second for the real root on ordinary hardware.

## Sources

`hyperlocal_root_sources` overrides the built-in transfer hosts. Give
`host:port` entries. You would set this to use an internal distribution point,
or to pin to specific root servers your network reaches well.

## Watching it

```
dns_localroot_answers_total     queries answered from the local copy
dns_localroot_serial            serial of the copy in use
dns_localroot_copy_age_seconds  age since last successful refresh
dns_localroot_transfers_total   transfer attempts, by outcome
dns_localroot_disk_total        saved copy loads and writes, by result
```

`dns_localroot_copy_age_seconds` is the one to alert on. It climbing steadily
means refreshes are failing and the copy is walking toward its expire, at which
point you silently go back to querying the root servers.
