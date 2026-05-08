package config

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

const configver = "1.6.6"

// Config type.
type Config struct {
	Version          string
	Directory        string
	BlockLists       []string
	BlockListDir     string
	RootServers      []string
	Root6Servers     []string
	DNSSEC           string
	RootKeys         []string
	FallbackServers  []string
	ForwarderServers []string
	AccessList       []string
	LogLevel         string
	AccessLog        string
	Bind             string
	BindTLS          string
	BindDOH          string
	BindDOQ          string
	TLSCertificate   string
	TLSPrivateKey    string
	API              string
	BearerToken      string //nolint:gosec // G117 - not a hardcoded credential, loaded from config file
	Nullroute        string
	Nullroutev6      string
	HostsFile        string
	OutboundIPs      []string
	OutboundIP6s     []string
	Timeout          Duration
	QueryTimeout     Duration
	Expire           uint32
	CacheSize        int
	Prefetch         uint32
	Maxdepth         int
	RateLimit        int
	ClientRateLimit  int
	NSID             string
	Blocklist        []string
	Whitelist        []string
	Chaos            bool
	QnameMinLevel    int `toml:"qname_min_level"`
	EmptyZones       []string

	// Views are per-client static answers, evaluated in order. A
	// query whose source IP falls in a view's Sources gets that
	// view's Records as the response; non-matching queries fall
	// through to the rest of the middleware chain (blocklist,
	// resolver, etc.).
	Views []ViewConfig

	// Dnstap configuration
	DnstapSocket        string
	DnstapIdentity      string
	DnstapVersion       string
	DnstapLogQueries    bool
	DnstapLogResponses  bool
	DnstapFlushInterval int

	// Domain metrics configuration
	DomainMetrics      bool
	DomainMetricsLimit int

	// Kubernetes middleware configuration as a section
	Kubernetes KubernetesConfig `toml:"kubernetes"`

	// DNS64 middleware configuration (RFC 6147). Translates A
	// records into AAAA records embedded in a configured IPv6
	// prefix, so an IPv6-only client can reach IPv4-only services.
	DNS64 DNS64Config `toml:"dns64"`

	Plugins map[string]Plugin

	CookieSecret string
	IPv6Access   bool `toml:"ipv6access"`

	// TCP connection pooling configuration
	TCPKeepalive      bool
	RootTCPTimeout    Duration // Timeout for root server TCP connections
	TLDTCPTimeout     Duration // Timeout for TLD server TCP connections
	TCPMaxConnections int      // Maximum number of TCP connections to pool

	// Resolver concurrency limits
	MaxConcurrentQueries int // Maximum concurrent DNS queries (default 10000)

	// Reflex: DNS amplification/reflection attack detection
	ReflexEnabled      bool    // Enable amplification attack detection
	ReflexBlockMode    bool    // If false, only log but don't block
	ReflexLearningMode bool    // If true, log detections but don't block
	ReflexThreshold    float64 // Suspicion threshold (0.0-1.0, default: 0.7)

	sVersion string
}

// ViewConfig describes a single per-client static-answer view.
// Zone is a free-form label that names the view in logs and
// errors. Networks are CIDR strings; a query is dispatched to
// this view if its source IP is contained in any of them. Answers
// are DNS resource records in standard zone-file format; wildcard
// owners (e.g. "*.example.lan.") match any name strictly more
// specific than the suffix per RFC 4592.
type ViewConfig struct {
	Zone     string
	Networks []string
	Answers  []string
}

// KubernetesConfig holds Kubernetes middleware configuration
type KubernetesConfig struct {
	Enabled       bool   `toml:"enabled"`
	ClusterDomain string `toml:"cluster_domain"`
	// KillerMode is deprecated and ignored. The kubernetes middleware
	// always uses the sharded registry; the field is retained so
	// older configs parse without error. Remove it from new configs.
	KillerMode bool   `toml:"killer_mode"`
	Kubeconfig string `toml:"kubeconfig"`
	// Demo populates the registry with synthetic services so the
	// middleware can be exercised without a real cluster
	// (development / tests). It is NEVER safe to enable in
	// production: the middleware will answer synthesised names
	// that look real. Independent from Enabled.
	Demo bool                `toml:"demo"`
	TTL  KubernetesTTLConfig `toml:"ttl"`
}

// KubernetesTTLConfig holds TTL settings for different record types
type KubernetesTTLConfig struct {
	Service uint32 `toml:"service"`
	Pod     uint32 `toml:"pod"`
	SRV     uint32 `toml:"srv"`
	PTR     uint32 `toml:"ptr"`
}

// DNS64Config holds DNS64 middleware configuration (RFC 6147).
//
// Prefixes lists Pref64::/n IPv6 prefixes used to embed IPv4
// addresses in synthesised AAAA records. Each prefix length must
// be one of /32, /40, /48, /56, /64, /96 per RFC 6052 §2.2. Per
// RFC 6147 §5.2 every configured prefix synthesises in parallel:
// each upstream A record produces one AAAA per prefix, so a
// client receives every reachable Pref64 path in a single reply.
// When DNS64 is enabled but no usable prefix is configured the
// well-known 64:ff9b::/96 is the runtime default.
//
// ClientNetworks restricts synthesis to clients whose source IP
// falls in one of the listed CIDRs. An empty list synthesises for
// every client; "::/0" plus "0.0.0.0/0" achieves the same and is
// the recommended explicit form.
//
// ExcludeZones is a list of fully-qualified domain names whose
// AAAA responses are never synthesised (their original NODATA /
// NXDOMAIN flows through unchanged). Useful for opting out
// specific zones when some other middleware is expected to handle
// IPv6.
//
// ExcludeANetworks is the RFC 6147 §5.1.4 / RFC 6052 §3.1
// "do not translate" set. IPv4 addresses inside any listed CIDR
// are dropped from synthesis when the well-known prefix
// 64:ff9b::/96 is in use. Operator-chosen network-specific
// prefixes ignore this list — they picked the prefix knowing the
// network's reachability. When the field is omitted entirely
// (nil) and the well-known prefix is active, a runtime default
// list mirroring the IANA Special-Purpose Address Registry is
// applied; declaring an explicit empty list opts out.
//
// ExcludeAAAANetworks lists IPv6 prefixes whose AAAA records in the
// upstream response must be filtered before deciding pass-through
// vs synthesis (RFC 6147 §5.1.4). The default ::ffff:0:0/96 (IPv4-
// mapped IPv6) keeps misconfigured upstreams from leaking
// non-routable addresses into the client. When every AAAA in the
// upstream answer is excluded, the response is treated as if no
// AAAA records were returned and synthesis proceeds. Declaring
// an explicit empty list opts out of filtering.
type DNS64Config struct {
	Enabled             bool     `toml:"enabled"`
	Prefixes            []string `toml:"prefixes"`
	ClientNetworks      []string `toml:"client_networks"`
	ExcludeZones        []string `toml:"exclude_zones"`
	ExcludeANetworks    []string `toml:"exclude_a_networks"`
	ExcludeAAAANetworks []string `toml:"exclude_aaaa_networks"`
}

// Plugin type.
type Plugin struct {
	Path   string
	Config map[string]any
}

// (*Config).ServerVersion serverVersion return current server version.
func (c *Config) ServerVersion() string {
	return c.sVersion
}

// Duration type.
type Duration struct {
	time.Duration
}

// (*Duration).UnmarshalText unmarshalText for duration type.
func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

var defaultConfig = `
# Configuration file version (not SDNS version)
version = "%s"

# ============================
# Basic Server Configuration
# ============================

# Working directory for SDNS database and cache files
# This directory must have write permissions for the SDNS user
directory = "db"

# DNS server bind address and port
bind = ":53"

# DNS-over-TLS (DoT) server bind address and port
# Requires TLS certificate and key to be configured
# bindtls = ":853"

# DNS-over-HTTPS (DoH) server bind address and port
# Requires TLS certificate and key to be configured
# binddoh = ":443"

# DNS-over-QUIC (DoQ) server bind address and port
# Requires TLS certificate and key to be configured
# binddoq = ":853"

# TLS certificate file path (PEM format)
# Required for DoT, DoH, and DoQ servers
# tlscertificate = "server.crt"

# TLS private key file path (PEM format)
# Required for DoT, DoH, and DoQ servers
# tlsprivatekey = "server.key"

# ============================
# Network Configuration
# ============================

# Outbound IPv4 addresses for DNS queries
# Multiple addresses enable random source IP selection per request
outboundips = [
]

# Outbound IPv6 addresses for DNS queries
# Multiple addresses enable random source IP selection per request
outboundip6s = [
]

# ============================
# Root DNS Servers
# ============================

# Root DNS servers (IPv4)
# These are the authoritative name servers for the DNS root zone
rootservers = [
    "198.41.0.4:53",      # a.root-servers.net
    "170.247.170.2:53",   # b.root-servers.net
    "192.33.4.12:53",     # c.root-servers.net
    "199.7.91.13:53",     # d.root-servers.net
    "192.203.230.10:53",  # e.root-servers.net
    "192.5.5.241:53",     # f.root-servers.net
    "192.112.36.4:53",    # g.root-servers.net
    "198.97.190.53:53",   # h.root-servers.net
    "192.36.148.17:53",   # i.root-servers.net
    "192.58.128.30:53",   # j.root-servers.net
    "193.0.14.129:53",    # k.root-servers.net
    "199.7.83.42:53",     # l.root-servers.net
    "202.12.27.33:53"     # m.root-servers.net
]

# Root DNS servers (IPv6)
# These are the authoritative name servers for the DNS root zone
root6servers = [
    "[2001:503:ba3e::2:30]:53",  # a.root-servers.net
    "[2801:1b8:10::b]:53",       # b.root-servers.net
    "[2001:500:2::c]:53",        # c.root-servers.net
    "[2001:500:2d::d]:53",       # d.root-servers.net
    "[2001:500:a8::e]:53",       # e.root-servers.net
    "[2001:500:2f::f]:53",       # f.root-servers.net
    "[2001:500:12::d0d]:53",     # g.root-servers.net
    "[2001:500:1::53]:53",       # h.root-servers.net
    "[2001:7fe::53]:53",         # i.root-servers.net
    "[2001:503:c27::2:30]:53",   # j.root-servers.net
    "[2001:7fd::1]:53",          # k.root-servers.net
    "[2001:500:9f::42]:53",      # l.root-servers.net
    "[2001:dc3::35]:53"          # m.root-servers.net
]

# ============================
# DNSSEC Configuration
# ============================

# DNSSEC validation mode
# "on" = validate DNSSEC for signed zones
# "off" = disable DNSSEC validation
dnssec = "on"

# DNSSEC root trust anchors
# These are the public keys used to verify the DNS root zone
rootkeys = [
	# Key ID 20326 - Active since 2017
	"""\
	. 172800 IN DNSKEY 257 3 8 ( \
	AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTO \
	iW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN \
	7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5 \
	LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8 \
	efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7 \
	pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLY \
	A4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws \
	9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= \
	) ; KSK; alg = RSASHA256 ; key id = 20326 \
	""",
	# Key ID 38696 - Active since 2024
	"""\
	. 172800 IN DNSKEY 257 3 8 ( \
	AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC \
	6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeH \
	spaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vr \
	hbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAx \
	m9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7 \
	CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+ \
	u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxP \
	vYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc= \
	) ; KSK; alg = RSASHA256 ; key id = 38696 \
	"""
]

# ============================
# Upstream Servers
# ============================

# Fallback DNS servers
# Used when root servers are unreachable or for specific failures
# Supports standard DNS (port 53)
fallbackservers = [
    # Examples:
    # "8.8.8.8:53",              # Google Public DNS
    # "[2001:4860:4860::8888]:53" # Google Public DNS IPv6
]

# Forwarder DNS servers
# When configured, SDNS acts as a forwarding resolver instead of recursive
# Supports DNS (port 53) and DNS-over-TLS (tls:// prefix)
forwarderservers = [
    # Examples:
    # "8.8.8.8:53",              # Standard DNS
    # "[2001:4860:4860::8888]:53", # Standard DNS IPv6
    # "tls://8.8.8.8:853" # DNS-over-TLS
]

# ============================
# API and Logging
# ============================

# HTTP API server configuration
# Provides REST API for statistics and management
# Set to empty string to disable
api = "127.0.0.1:8080"

# API authentication token
# When set, requests must include: Authorization: Bearer <token>
# bearertoken = ""

# Log verbosity level
# Options: crit, error, warn, info, debug
loglevel = "info"

# Query access log file path
# Uses Common Log Format (CLF)
# Leave empty to disable access logging
# accesslog = ""

# ============================
# Filtering and Blocking
# ============================

# Remote blocklist sources
# These URLs are periodically downloaded and updated
blocklists = [
    # Popular blocklist examples:
    # "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # "http://sysctl.org/cameleon/hosts",
    # "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    # "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"
]

# [DEPRECATED] Blocklist directory - automatically created under working directory
blocklistdir = ""

# Response IP for blocked A queries (IPv4)
nullroute = "0.0.0.0"

# Response IP for blocked AAAA queries (IPv6)
nullroutev6 = "::0"

# ============================
# Access Control
# ============================

# Client access control list (ACL)
# CIDR notation for allowed client IP ranges
accesslist = [
    "0.0.0.0/0",    # Allow all IPv4
    "::0/0"         # Allow all IPv6
]

# Local hosts file path
# Serves entries from hosts file (RFC 952/1123 format)
# Leave empty to disable
hostsfile = ""


# ============================
# Performance and Limits
# ============================

# Network timeout for upstream DNS queries
timeout = "2s"

# Maximum time to wait for any DNS query to complete
querytimeout = "10s"

# Cache TTL for error responses (seconds)
expire = 600

# Maximum number of cached DNS records
cachesize = 256000

# Prefetch threshold percentage (10-90)
# Refreshes popular cache entries before expiration
# Set to 0 to disable prefetching
prefetch = 10

# Maximum recursion depth for queries
# Prevents infinite loops in resolution
maxdepth = 30

# ============================
# Rate Limiting
# ============================

# Global query rate limit (queries per second)
# 0 = disabled
ratelimit = 0

# Per-client rate limit (queries per minute)
# 0 = disabled
clientratelimit = 0

# ============================
# Domain Metrics
# ============================

# Enable per-domain query metrics
# Tracks query counts for individual domains
domainmetrics = false

# Maximum number of domains to track in metrics
# 0 = unlimited (use with caution - may consume memory)
# Recommended: 10000-100000 for production
domainmetricslimit = 10000

# ============================
# Custom Lists
# ============================

# Manual domain blocklist
# Domains listed here will be blocked
blocklist = [
    # Examples:
    # "ads.example.com",
    # "tracker.example.net"
]

# Domain whitelist
# Domains listed here bypass all blocking
whitelist = [
    # Examples:
    # "important.example.com",
    # "trusted.example.net"
]

# ============================
# Advanced Features
# ============================

# DNS server identifier (RFC 5001)
# Useful for identifying specific servers in multi-server deployments
# Leave empty to disable
nsid = ""

# CHAOS query responses
# Responds to: version.bind, version.server, hostname.bind, id.server
chaos = true

# QNAME minimization level (RFC 7816)
# Higher values increase privacy but may impact performance
# 0 = disabled, 3 = recommended
qname_min_level = 3

# Empty zones (AS112 - RFC 7534)
# Prevents queries for private IP reverse zones from leaking
# Default list used if empty
emptyzones = [
    # Example: "10.in-addr.arpa."
]

# ============================
# TCP Connection Pooling
# ============================

# Enable TCP connection pooling for root and TLD servers
# Keeps TCP connections alive to improve performance
tcpkeepalive = false

# TCP idle timeout for root server connections
# Connections idle longer than this are closed
roottcptimeout = "5s"

# TCP idle timeout for TLD server connections (com, net, org, etc.)
# Connections idle longer than this are closed
tldtcptimeout = "10s"

# Maximum number of pooled TCP connections
# 0 = use default (100)
tcpmaxconnections = 100

# ============================
# DNS Amplification Attack Detection (Reflex)
# ============================

# Enable DNS amplification/reflection attack detection
# Tracks IP behavior to identify spoofed source IPs
reflexenabled = false

# Enable blocking mode (if false, only logs suspicious queries)
# Set to false for testing before enabling full blocking
reflexblockmode = true

# Enable learning mode (log detections but don't block)
# Useful for tuning detection thresholds
reflexlearningmode = false

# Suspicion threshold (0.0-1.0, default: 0.7)
# IPs exceeding this score are blocked/logged
# Lower values = more aggressive, higher values = fewer false positives
# reflexthreshold = 0.7

# ============================
# Dnstap Binary Logging
# ============================

# Dnstap socket path
# Unix domain socket for binary DNS logging
# Leave empty to disable
# dnstapsocket = "/var/run/sdns/dnstap.sock"

# Dnstap server identity
# Identifies this server in dnstap logs
# dnstapidentity = "sdns"

# Dnstap version string
# Version identifier for dnstap logs
# dnstapversion = "1.0"

# Log DNS queries via dnstap
# dnstaplogqueries = true

# Log DNS responses via dnstap
# dnstaplogresponses = true

# Dnstap buffer flush interval (seconds)
# dnstapflushinterval = 5

# ============================
# Per-client Views
# ============================

# Serve different DNS answers to different clients based on the
# client's source IP. Each view lists CIDR networks and zone-file
# answers; a query from a client whose IP is in one of the
# networks gets the view's matching answer, and any non-matching
# query falls through to normal resolution.
#
# Wildcards (*.example.lan.) are supported. Exact owners override
# a covering wildcard. Views are evaluated in declaration order.
#
# Examples:
# [[views]]
# zone = "lannet"
# networks = ["192.168.1.0/24"]
# answers = [
#     "*.example.lan. 60 IN A 192.168.1.3",
#     "*.example.lan. 60 IN AAAA fd00::3",
# ]
#
# [[views]]
# zone = "vpnnet"
# networks = ["100.64.0.0/24"]
# answers = [
#     "*.example.lan. 60 IN A 100.64.0.2",
# ]

# ============================
# Kubernetes Integration
# ============================

[kubernetes]
# Enable Kubernetes DNS middleware
# Provides DNS resolution for Kubernetes services and pods
enabled = false

# Kubernetes cluster domain suffix
# Default domain for Kubernetes DNS queries
cluster_domain = "cluster.local"

# Path to kubeconfig file
# Leave empty to use in-cluster config or ~/.kube/config
# kubeconfig = ""

# TTL configuration for different record types
[kubernetes.ttl]
# TTL for service A/AAAA records (seconds)
service = 30

# TTL for pod A/AAAA records (seconds)
pod = 30

# TTL for SRV records (seconds)
srv = 30

# TTL for PTR records (seconds)
ptr = 30

# ============================
# DNS64 (RFC 6147)
# ============================

# Synthesise AAAA records from A records for IPv6-only clients
# reaching IPv4-only services. When a client AAAA query returns
# NOERROR-NODATA (or any nonzero RCODE other than NXDOMAIN, e.g.
# SERVFAIL without a DNSSEC EDE), the resolver issues an A query
# for the same name and synthesises AAAA records by embedding
# each IPv4 inside one of the configured Pref64::/n prefixes
# (RFC 6052). NXDOMAIN passes through unchanged; SERVFAIL with a
# DNSSEC-failure Extended DNS Error also passes through so DNS64
# can never mask a validation failure (RFC 6147 §5.5). Clients
# that set RD=0 or CD=1 bypass DNS64 entirely.

[dns64]
# Enable DNS64 synthesis.
enabled = false

# IPv6 prefixes used to embed IPv4 addresses. Lengths must be one
# of /32, /40, /48, /56, /64, /96. List multiple prefixes to
# synthesise one AAAA per (A record, prefix) pair so the client
# sees every reachable Pref64 path in a single reply. The IANA-
# reserved Well-Known Prefix 64:ff9b::/96 is the typical choice
# for general-purpose DNS64; if the field is omitted entirely
# while DNS64 is enabled, that prefix is the runtime default
# (RFC 6147 §5.2).
prefixes = ["64:ff9b::/96"]

# CIDR ranges of clients eligible for synthesis. Empty list means
# all clients are eligible. Restrict to your IPv6-only subnets to
# keep dual-stack clients on their original answers.
client_networks = []

# Fully-qualified domain names whose AAAA responses must not be
# synthesised. Suffix match: "example.com." matches the zone and
# every name under it.
exclude_zones = []

# IPv6 prefixes whose AAAA records must be filtered out of the
# upstream response before deciding pass-through vs synthesis
# (RFC 6147 §5.1.4). The IPv4-mapped IPv6 range ::ffff:0:0/96 is
# the standard default; misconfigured upstreams that return
# IPv4-mapped AAAAs are treated as if they returned no AAAA, so
# DNS64 synthesises a routable address from the corresponding A.
exclude_aaaa_networks = ["::ffff:0:0/96"]

# IPv4 networks excluded from synthesis when the Well-Known Prefix
# 64:ff9b::/96 is the active prefix (RFC 6147 §5.1.4). Operator-
# chosen network-specific prefixes ignore this list. Defaults
# below mirror the IANA Special-Purpose Address Registry.
exclude_a_networks = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
]

# ============================
# Plugins
# ============================

# External plugin configuration
# Plugins extend SDNS functionality
# Load order affects processing sequence
# Example: https://github.com/semihalev/sdnsexampleplugin

# [plugins]
#     [plugins.example]
#     path = "exampleplugin.so"
#     config = {key_1 = "value_1", key_2 = 2, key_3 = true}
`

// Load loads the given config file.
func Load(cfgfile, version string) (*Config, error) {
	config := new(Config)

	if _, err := os.Stat(cfgfile); os.IsNotExist(err) {
		if path.Base(cfgfile) == "sdns.conf" {
			// compatibility for old default conf file
			if _, err := os.Stat("sdns.toml"); os.IsNotExist(err) {
				if err := generateConfig(cfgfile); err != nil {
					return nil, err
				}
			} else {
				cfgfile = "sdns.toml"
			}
		}
	}

	zlog.Info("Loading config file...", zlog.String("path", cfgfile))

	if _, err := toml.DecodeFile(cfgfile, config); err != nil {
		return nil, fmt.Errorf("could not load config: %s", err)
	}

	if config.Version != configver {
		zlog.Warn("Config file is out of version, you can generate new one and check the changes.")
	}

	if _, err := os.Stat(config.Directory); os.IsNotExist(err) {
		if err := os.Mkdir(config.Directory, 0750); err != nil {
			return nil, fmt.Errorf("error creating working directory: %s", err)
		}
	}

	zlog.Info("Working directory", zlog.String("path", config.Directory))

	config.sVersion = version

	if config.DNSSEC == "" || config.DNSSEC != "off" {
		config.DNSSEC = "on"
	}

	if config.CookieSecret == "" {
		var v uint64

		err := binary.Read(rand.Reader, binary.BigEndian, &v)
		if err != nil {
			return nil, err
		}

		config.CookieSecret = fmt.Sprintf("%16x", v)
	}

	if !config.IPv6Access {
		err := testIPv6Network()
		if err == nil {
			config.IPv6Access = true
		}
	}

	// Set TCP keepalive defaults
	if config.RootTCPTimeout.Duration == 0 {
		config.RootTCPTimeout.Duration = 5 * time.Second
	}
	if config.TLDTCPTimeout.Duration == 0 {
		config.TLDTCPTimeout.Duration = 10 * time.Second
	}
	if config.TCPMaxConnections == 0 {
		config.TCPMaxConnections = 100
	}
	if config.MaxConcurrentQueries == 0 {
		config.MaxConcurrentQueries = 10000
	}

	// Set Kubernetes TTL defaults
	if config.Kubernetes.TTL.Service == 0 {
		config.Kubernetes.TTL.Service = 30
	}
	if config.Kubernetes.TTL.Pod == 0 {
		config.Kubernetes.TTL.Pod = 30
	}
	if config.Kubernetes.TTL.SRV == 0 {
		config.Kubernetes.TTL.SRV = 30
	}
	if config.Kubernetes.TTL.PTR == 0 {
		config.Kubernetes.TTL.PTR = 30
	}

	return config, nil
}

func generateConfig(path string) error {
	output, err := os.Create(path) //nolint:gosec // G304 - path from command line flag, admin controlled
	if err != nil {
		return fmt.Errorf("could not generate config: %s", err)
	}

	defer func() {
		err := output.Close()
		if err != nil {
			zlog.Warn("Config generation failed while file closing", zlog.String("error", err.Error()))
		}
	}()

	r := strings.NewReader(fmt.Sprintf(defaultConfig, configver))
	if _, err := io.Copy(output, r); err != nil {
		return fmt.Errorf("could not copy default config: %s", err)
	}

	if abs, err := filepath.Abs(path); err == nil {
		zlog.Info("Default config file generated", "config", abs)
	}

	return nil
}

func testIPv6Network() error {
	client := &dns.Client{Net: "udp"}

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	// root server
	_, _, err := client.Exchange(req, net.JoinHostPort("2001:500:2::c", "53"))
	if err != nil {
		return err
	}

	return nil
}
