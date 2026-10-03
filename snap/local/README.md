# SDNS Snap Package

This directory contains the snap packaging files for SDNS.

## Installation

```bash
sudo snap install sdns
```

The stable channel is published by the Snap workflow whenever a release is
published on GitHub.

## Configuration

The install hook writes the standard generated configuration, the same file
`sdns` writes anywhere else, with `directory` pointed at the state directory
every snap revision shares. Edit it, check it, and restart:

```bash
sudo nano /var/snap/sdns/current/sdns.conf
sudo sdns.sdns-cli -t
sudo snap restart sdns
```

A configuration written by an older snap, in the legacy `[server]` layout, is
moved aside to `sdns.conf.legacy` on refresh and a fresh one is generated.
Carry your settings across by hand.

## File Locations

- Configuration: `/var/snap/sdns/current/sdns.conf`
- State (trust anchors, blocklists, cache snapshot): `/var/snap/sdns/common/db/`

## Service Management

```bash
# View service status
sudo snap services sdns

# View logs
sudo journalctl -u snap.sdns.sdns -f

# Restart service
sudo snap restart sdns

# Stop service
sudo snap stop sdns

# Start service
sudo snap start sdns
```

## Building the Snap

To build the snap locally:

```bash
# Install snapcraft
sudo snap install snapcraft --classic

# Build the snap
cd /path/to/sdns
snapcraft

# Install locally built snap
sudo snap install sdns_*.snap --dangerous
```

## Permissions

The snap uses the following interfaces:
- `network`: For network access
- `network-bind`: To bind to ports
- `network-observe`: For network statistics

These are automatically connected when the snap is installed from the store.
