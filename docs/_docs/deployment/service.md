---
layout: doc
title: Running as a service
category: Deployment
order: 1
description: systemd, the unprivileged user, file layout and binding to port 53.
---

The `.deb` and `.rpm` packages install the unit, the user and the configuration
for you. This page describes what they set up, which is also what you want if
you are installing from a tarball.

## The unit

```ini
[Unit]
Description=SDNS - Fast DNS Resolver
ConditionPathExists=/var/lib/sdns
Wants=network.target
After=network.target

[Service]
Type=simple
User=sdns
Group=sdns
LimitNOFILE=131072
Restart=on-failure
RestartSec=10
WorkingDirectory=/var/lib/sdns
ExecStart=/usr/bin/sdns --config=/etc/sdns.conf
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=syslog
StandardError=journal
SyslogIdentifier=sdns

[Install]
WantedBy=multi-user.target
```

Three lines carry most of the weight.

`AmbientCapabilities=CAP_NET_BIND_SERVICE` is what lets an unprivileged process
bind port 53. Do not run sdns as root to solve this.

`LimitNOFILE=131072` matters more than it looks: the TCP/DoT connection cap is
derived at startup partly from the file-descriptor limit, so a low limit
silently gives you a smaller connection cap than the machine could handle.

`ConditionPathExists=/var/lib/sdns` stops the unit rather than starting a
resolver with nowhere to write.

## Files

| Path | Contents |
|---|---|
| `/usr/bin/sdns` | The binary |
| `/etc/sdns.conf` | Configuration |
| `/var/lib/sdns` | Trust anchors, cached blocklists, the local root copy |

`/var/lib/sdns` must be writable by the `sdns` user. It holds real state — the
RFC 5011 trust anchor database in particular — so it belongs on persistent
storage, not in a tmpfs.

## Operating it

```bash
sudo systemctl enable --now sdns
sudo systemctl status sdns
sudo journalctl -u sdns -f
```

The listener bounds — worker pool, in-flight cap, TCP connection cap — are
logged as each listener starts, which is the quickest way to confirm what the
process actually derived from the machine.

## Restarting safely

```bash
sudo sdns -t -c /etc/sdns.conf && sudo systemctl restart sdns
```

Make the validation gate part of the restart, not a thing you remember to run.
It reports every problem in the file at once and exits nonzero on any of them,
so the `&&` is doing real work.

## Conflicting resolvers

On most distributions something already holds port 53 — `systemd-resolved`,
`dnsmasq`, or an existing recursor. Check before the first start:

```bash
sudo ss -lnup 'sport = :53'
```

For `systemd-resolved`, the usual approach is to turn off its stub listener
(`DNSStubListener=no` in `/etc/systemd/resolved.conf`) rather than disabling the
service, so `/etc/resolv.conf` handling stays intact.

## Debug environment variables

The unit ships both off:

```
SDNS_PPROF=false     # serve /debug/pprof on the API listener
SDNS_DEBUGNS=false   # serve the CHAOS-class nameserver debug view
```

`SDNS_PPROF=true` exposes Go's profiling endpoints on the API address. Leave it
off unless you are actively profiling, and never expose that listener publicly
while it is on.
