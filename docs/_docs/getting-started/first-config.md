---
layout: doc
title: Your first configuration
category: Getting Started
order: 2
description: What the generated file contains and the few keys worth setting straight away.
---

Starting sdns without a configuration writes one next to the binary and uses
it. The generated file documents every setting in place, so it is worth
reading once rather than copying fragments from elsewhere.

## The keys that matter first

```toml
# Where to listen. ":53" is both 0.0.0.0:53 and [::]:53.
bind = ":53"

# Writable state: trust anchors, cached blocklists, the local root copy.
directory = "/var/lib/sdns"

# Who may query this resolver. The default allows everyone, which is
# almost never what you want on a public address.
accesslist = ["127.0.0.1/32", "::1/128", "192.168.0.0/16"]

# DNSSEC validation. Leave it on unless you have a specific reason.
dnssec = "on"
```

## Check before you start

```bash
sdns -t -c /etc/sdns.conf
```

The gate reads the file the way the server will: addresses are parsed, ports
are resolved through the same lookup a dial uses, CIDRs and enumerations are
checked, TLS files are opened, and policy zones are compiled with the loaders
the server runs. It reports **every** problem it finds, not just the first.

A key that no setting claims fails `-t` — a typo, or a setting an older sdns
understood. Startup only warns about those, so upgrading with a stale key in
the file does not turn into an outage.

## Next

- [Configuration reference]({{ '/docs/configuration/overview/' | relative_url }}) — every key, grouped by what it does
- [Running as a service]({{ '/docs/deployment/service/' | relative_url }}) — systemd, containers, file permissions
