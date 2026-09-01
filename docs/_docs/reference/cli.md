---
layout: doc
title: Command line
category: Reference
order: 1
description: Flags, subcommands, environment variables and exit codes.
---

```
sdns [flags]
sdns version
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `sdns.conf` | Path to the configuration file. If it does not exist, one is generated there and used. |
| `-t`, `--test` | off | Validate the configuration and exit. |

## `sdns version`

Prints version information and exits. There is no `--version` flag; the
subcommand is the spelling.

```bash
$ sdns version
```

## Validating a configuration

```bash
sdns -t -c /etc/sdns.conf
```

Exit code `0` if the file is valid, `1` if it is not. Every problem found is
reported, not just the first — the gate is meant to be run once and fixed once,
rather than run in a loop.

What it checks: addresses parse; ports resolve through the same lookup a dial
uses; CIDRs are well-formed; enumerated values are ones the runtime accepts; TLS
certificate and key files open; policy zones compile with the loaders the server
runs; and every key in the file is one some setting claims.

That last check is stricter than startup, which only warns about an unknown key.
The asymmetry is deliberate: you want the strict answer while checking a change,
and you do not want a leftover key from an older version to turn an upgrade into
an outage.

## Environment variables

| Variable | Effect |
|---|---|
| `SDNS_PPROF` | Serves Go's `/debug/pprof` endpoints on the API listener |
| `SDNS_DEBUGNS` | Answers CHAOS HINFO with the delegation sdns holds, per-server RTT and health |

Both default off, and the shipped systemd unit sets both to `false` explicitly.
Each is parsed as a boolean, so `1`, `t` and `TRUE` work as well as `true`, and
each is read once at startup — changing either means a restart.

`bearertoken` does **not** cover the pprof routes. What each switch exposes, how
to read the HINFO output, and why that matters are on the
[diagnostics]({{ '/docs/deployment/diagnostics/' | relative_url }}) page.

## First run

Starting with no configuration file writes `sdns.conf` in the current working
directory and uses it:

```bash
./sdns
```

The generated file documents every setting in place. Read it once — it is the
authoritative description of the version you are running.

## Schema version

The `version` key at the top of the file is the schema version, not the sdns
version, and only changes when the schema does.

A file whose version does not match produces a warning and is then loaded
exactly as written. sdns does **not** rewrite it and does **not** keep a
backup.

Upgrading across a schema change is therefore manual: generate a fresh file —
pointing `-t` at a path that does not exist writes one — carry your settings
across, and use `sdns -t` to catch keys that have gone away.
