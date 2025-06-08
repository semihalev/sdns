# SDNS Snap Package

This directory contains the snap packaging files for SDNS.

## Installation

```bash
sudo snap install sdns
```

## Configuration

SDNS can be configured using snap configuration options:

### Basic Configuration

```bash
# Change DNS port (default: 53)
sudo snap set sdns port=5353

# Change bind address (default: 0.0.0.0)
sudo snap set sdns bind="127.0.0.1"

# Enable/disable DNSSEC (default: true)
sudo snap set sdns dnssec=false
```

### Advanced Features

```bash
# Enable DNS-over-HTTPS
sudo snap set sdns doh=true

# Enable DNS-over-TLS
sudo snap set sdns dot=true

# Enable DNS-over-QUIC
sudo snap set sdns doq=true

# Set log level (debug, info, warn, error)
sudo snap set sdns log.level=debug

# Set cache size
sudo snap set sdns cache.size=50000

# Set rate limit (requests per second, 0 = unlimited)
sudo snap set sdns ratelimit=100
```

### TLS Configuration

For DoH/DoT/DoQ, you need to provide TLS certificates:

```bash
sudo snap set sdns tls.certificate=/path/to/cert.pem
sudo snap set sdns tls.key=/path/to/key.pem
```

## File Locations

- Configuration: `/var/snap/sdns/current/sdns.conf`
- Logs: `/var/snap/sdns/current/log/`
- Blocklists: `/var/snap/sdns/current/db/blocklists/`

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