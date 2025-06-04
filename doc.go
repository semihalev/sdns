/*
Package main implements SDNS - a high-performance, recursive DNS resolver server with DNSSEC support.

SDNS is a privacy-focused DNS server that provides:

  - High-performance recursive DNS resolution with aggressive caching
  - Full DNSSEC validation and verification support
  - DNS-over-HTTPS (DoH) and DNS-over-QUIC (DoQ) protocols
  - Privacy-preserving features including query minimization (RFC 7816)
  - Flexible middleware architecture for extending functionality
  - Built-in blocklist and allowlist support
  - Rate limiting and access control
  - Metrics and monitoring via Prometheus
  - Automatic root trust anchor updates (RFC 5011)

Architecture:

SDNS uses a middleware-based architecture where each component processes DNS queries
in a chain. The middleware order is important and defined as:

 1. Recovery - Panic recovery and error handling
 2. Loop - Detection and prevention of query loops
 3. Metrics - Prometheus metrics collection with optional per-domain tracking
 4. Dnstap - Binary DNS message logging (dnstap format)
 5. AccessList - IP-based access control
 6. RateLimit - Query rate limiting per client
 7. EDNS - EDNS0 support and processing
 8. AccessLog - Query logging
 9. Chaos - Chaos TXT query responses
 10. HostsFile - Local hosts file resolution
 11. BlockList - Domain blocking with pattern matching
 12. AS112 - RFC 7534 AS112 redirection
 13. Cache - High-performance query caching
 14. Failover - Upstream server failover
 15. Resolver - Recursive DNS resolution with DNSSEC
 16. Forwarder - Forward queries to upstream servers

Configuration:

SDNS uses a configuration file (default: sdns.conf) that supports:

  - Server binding addresses for DNS, DoH, and DoQ
  - TLS certificate configuration
  - Middleware-specific settings
  - Upstream resolver configuration
  - Cache size and TTL settings
  - Logging levels and output

Usage:

	sdns [flags]
	sdns [command]

Available Commands:

	help        Help about any command
	version     Print version information

Flags:

	-c, --config string   Location of config file (default "sdns.conf")
	-h, --help           Help for sdns

Example:

	# Start with default config
	sdns

	# Start with custom config
	sdns -c /etc/sdns/sdns.conf

	# Show version
	sdns version

For more information, visit https://sdns.dev
*/
package main // import "github.com/semihalev/sdns"
