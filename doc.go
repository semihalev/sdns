/*
Package main is the entry point for SDNS, a high-performance, privacy-focused
recursive DNS resolver with full DNSSEC validation.

# Overview

SDNS resolves queries iteratively from the root, validating DNSSEC along the
chain of trust, and caches aggressively. It can also run as a forwarding
resolver. Queries are served over plain DNS (UDP and TCP) as well as the
encrypted transports DNS-over-TLS (DoT), DNS-over-HTTPS (DoH, including
HTTP/3), and DNS-over-QUIC (DoQ). A separate HTTP API exposes Prometheus
metrics and operational endpoints (blocklist management, cache purge).

# Feature highlights

  - Iterative recursive resolution with DNSSEC validation, NSEC/NSEC3
    denial-of-existence proofs, and RFC 5011 automatic root trust-anchor
    maintenance.
  - QNAME minimization (RFC 7816) for query privacy.
  - High-performance caching: positive and negative caches, prefetch of
    popular entries, and EDNS Client Subnet (ECS, RFC 7871) aware keying.
  - Forwarding to upstream resolvers over UDP, TCP, DoT, and DoH.
  - Filtering and policy: blocklists with pattern matching, IP access
    lists, per-client views, and per-client/global rate limiting.
  - Amplification/reflection (spoofed-source) attack detection.
  - DNS64 (RFC 6147), AS112 (RFC 7534), CHAOS telemetry, local hosts-file
    answers, and optional Kubernetes service discovery.
  - Observability via Prometheus metrics and dnstap query logging.

# Architecture

SDNS processes every query through an ordered middleware chain. Each
middleware either answers the query, mutates the request/response, or passes
control to the next middleware via the chain. The order is significant and is
the single source of truth in gen.go's middlewareList; gen.go generates
registry.go, whose init registers each middleware with the middleware package.
Middlewares self-declare their dependencies through marker interfaces (e.g.
StoreProvider, QueryerSetter), so adding one means adding an entry to
middlewareList plus an implementation — no central wiring switch to edit.

The chain order is:

 1. recovery   - Panic recovery for the handler chain.
 2. metrics    - Prometheus metrics, with optional per-domain tracking.
 3. dnstap     - Binary DNS message logging in dnstap format.
 4. accesslist - IP-based access control for clients.
 5. ratelimit  - Per-client and global query rate limiting.
 6. reflex     - DNS amplification/reflection (spoofed-source) detection.
 7. edns       - EDNS0 processing: option/version handling, DO and CD bits,
    and UDP buffer-size negotiation.
 8. accesslog  - Per-query logging.
 9. chaos      - CHAOS-class version and telemetry responses.
 10. hostsfile - Answers served from a local hosts file.
 11. views     - Per-client static answers selected by source-IP CIDR.
 12. blocklist - Domain blocking with pattern matching.
 13. as112     - RFC 7534 handling for private-use reverse zones.
 14. kubernetes- Kubernetes service DNS (optional).
 15. dns64     - RFC 6147 AAAA synthesis for IPv6-only clients.
 16. cache     - Positive/negative caching with prefetch and ECS awareness.
 17. failover  - Fallback when the primary resolution path fails.
 18. resolver  - Iterative recursive resolution with DNSSEC validation.
 19. forwarder - Forwarding to upstream resolvers (UDP/TCP/DoT/DoH).

# Configuration

SDNS reads a TOML configuration file (default: sdns.conf). If the file does
not exist, a documented default is generated on first run. The file controls
listen addresses for each transport, TLS certificates, upstream and root
servers, cache sizing and TTL bounds, DNSSEC and privacy options, the HTTP
API, and per-middleware settings.

# Usage

	sdns [flags]
	sdns [command]

Commands:

	version   Print version and build information.
	help      Help about any command.

Flags:

	-c, --config string   Path to the config file; generated if absent
	                      (default "sdns.conf").
	-t, --test            Validate the config file and exit (0 valid, 1 invalid).
	-h, --help            Help for sdns.

Examples:

	# Start with the default config (generated if missing).
	sdns

	# Start with a specific config file.
	sdns -c /etc/sdns/sdns.conf

	# Validate a config without starting the server.
	sdns -t -c /etc/sdns/sdns.conf

	# Print version information.
	sdns version

Project home and documentation: https://github.com/semihalev/sdns
*/
package main // import "github.com/semihalev/sdns"
