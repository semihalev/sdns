package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/zlog/v2"
)

const (
	configver               = "1.8.2"
	defaultServeStaleMaxTTL = 24 * time.Hour
)

// Config type.
type Config struct {
	Version      string
	Directory    string
	BlockLists   []string
	BlockListDir string
	RootServers  []string
	Root6Servers []string
	DNSSEC       string
	RFC8198      *bool `toml:"rfc8198"` // nil is default-on for backward compatibility
	RFC9520      *bool `toml:"rfc9520"` // nil is default-on; false is an emergency kill switch
	ServeStale   bool  `toml:"serve_stale"`
	// ServeStaleMaxTTL caps how long a positive answer may be reused after
	// its admitted TTL expires. Omission defaults to 24 hours. An explicit
	// zero leaves the delegation lease as the only bound; in forwarder mode,
	// where no delegation cut is learned, that means retention until eviction.
	// Serve-stale itself remains opt-in through ServeStale.
	ServeStaleMaxTTL Duration `toml:"serve_stale_max_ttl"`
	RootKeys         []string
	FallbackServers  []string
	ForwarderServers []string
	// ForwardZones route individual zones to their own upstreams. They are
	// consulted before ForwarderServers, which remains the whole-server
	// setting: a query matching no zone resolves normally.
	ForwardZones    []ForwardZoneConfig `toml:"forward_zone"`
	AccessList      []string
	LogLevel        string
	AccessLog       string
	Bind            string
	BindTLS         string
	BindDOH         string
	BindDOQ         string
	TLSCertificate  string
	TLSPrivateKey   string
	API             string
	BearerToken     string //nolint:gosec // G117 - not a hardcoded credential, loaded from config file
	Nullroute       string
	Nullroutev6     string
	HostsFile       string
	OutboundIPs     []string
	OutboundIP6s    []string
	Timeout         Duration
	QueryTimeout    Duration
	Expire          uint32
	CacheSize       int
	Prefetch        uint32
	Maxdepth        int
	RateLimit       int
	ClientRateLimit int
	NSID            string
	Blocklist       []string
	Whitelist       []string
	Chaos           bool
	// QnameMinLevel is deprecated and retained so older configs keep
	// parsing. It capped minimization by delegation depth rather than by
	// the queries a lookup spends, which is what RFC 9156 section 2.3
	// bounds. A non-zero value here is folded onto QnameMaxMinimizeCount
	// when that is unset. Remove it from new configs.
	QnameMinLevel int `toml:"qname_min_level"`
	// QnameMaxMinimizeCount is RFC 9156's MAX_MINIMISE_COUNT: the total
	// minimized queries one lookup may spend before the full name goes
	// out. 0 disables minimization entirely. A pointer because an explicit
	// zero and an absent key mean different things: written zero is the
	// operator switching minimization off, and it must win even when the
	// deprecated qname_min_level is still in the file; only an absent key
	// falls back to it.
	QnameMaxMinimizeCount *int `toml:"qname_max_minimize_count"`
	// QnameMinimizeOneLabel is RFC 9156's MINIMISE_ONE_LAB: how many of
	// those queries add a single label before the remaining labels are
	// grouped over the queries left. 0 selects the RFC's suggested 4;
	// grouping from the first query would expose a deep name almost at
	// once, so it is not an available setting.
	QnameMinimizeOneLabel int `toml:"qname_minimize_one_label"`

	// HyperlocalRoot serves the root zone from a local copy (RFC 8806):
	// transferred over AXFR from the root servers that publish it,
	// verified against the ZONEMD digest (RFC 8976) chained to the root
	// trust anchors, refreshed on the zone's own SOA schedule, and
	// withdrawn past its SOA expire — the resolver then walks to the real
	// root servers as if the copy never existed.
	HyperlocalRoot bool `toml:"hyperlocal_root"`
	// HyperlocalRootSources overrides the built-in transfer sources
	// (host:port). Empty selects the RFC 8806 appendix set.
	HyperlocalRootSources []string `toml:"hyperlocal_root_sources"`

	EmptyZones []string

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

	// ECS (EDNS Client Subnet, RFC 7871) policy. Default-disabled
	// per §11 privacy guidance: the resolver strips client ECS on
	// the way out unless the operator opts in via [ecs].enabled.
	// Stage 1 of the feature uses Enabled / ForwardV4Max /
	// ForwardV6Max / ClientNetworks for upstream forwarding; the
	// remaining fields ride along for the Stage 2 cache changes
	// so the on-disk schema only bumps once.
	ECS ECSConfig `toml:"ecs"`

	// RecursionFirewall bounds aggregate work across one recursive
	// request tree. Shadow mode records limit crossings without
	// changing responses; enforce mode terminates over-budget work.
	RecursionFirewall RecursionFirewallConfig `toml:"recursion_firewall"`

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

	// Server ingress bounds. These are deliberately separate from
	// MaxConcurrentQueries, which is the resolver's upstream fan-out
	// semaphore. Left at zero, each derives from the machine's resource
	// plan (memory, CPUs, descriptor limit); nothing is preallocated —
	// admission is capped, slabs are created on demand and parked in an
	// idle cache between requests.
	IngressWorkers  int // Fixed handler workers per listener (default: derived from CPUs and memory)
	IngressQueue    int // Ready-queue depth before a job is served on its own goroutine (default 64)
	IngressTCPConns int // Concurrent inbound TCP/DoT connection cap (default: derived from available memory)

	// MemoryTrim returns a burst's slab memory to the operating system
	// after a long idle. Off by default: the trim is one synchronous GC
	// over the whole process, which a busy or big-memory server never
	// needs and a single small core feels. Meant for memory-constrained
	// devices (containers on routers, small VPSes) where resident memory
	// after a traffic burst matters more than an idle-time pause.
	MemoryTrim bool

	// Reflex: DNS amplification/reflection attack detection
	ReflexEnabled      bool    // Enable amplification attack detection
	ReflexBlockMode    bool    // If false, only log but don't block
	ReflexLearningMode bool    // If true, log detections but don't block
	ReflexThreshold    float64 // Suspicion threshold (0.0-1.0, default: 0.7)

	sVersion string

	// undecodedKeys are the keys the config file carried that no field
	// claimed. See Load for why they warn rather than fail there.
	undecodedKeys []string
}

// UndecodedKeys returns the config keys that were present in the file and
// matched no setting — typos, or settings a previous version understood.
// They have no effect on this server.
func (c *Config) UndecodedKeys() []string { return c.undecodedKeys }

// RFC8198Enabled reports whether aggressive NSEC/NSEC3 denial synthesis is
// enabled. Omission is default-on; an explicit false is the operational kill
// switch. RFC 8020 NXDOMAIN subtree cuts are controlled independently.
func (c *Config) RFC8198Enabled() bool {
	return c == nil || c.RFC8198 == nil || *c.RFC8198
}

// RFC9520Enabled reports whether shared resolution-failure caching is
// enabled. Omission is default-on because RFC 9520 requires resolvers to
// cache failures; explicit false exists as an operational rollback switch
// for the shared question and authority-zone state.
func (c *Config) RFC9520Enabled() bool {
	return c == nil || c.RFC9520 == nil || *c.RFC9520
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

// ForwardZoneConfig sends one zone's queries to named recursive upstreams
// instead of resolving them from the root.
//
// This is forwarding in the RFC 8499 §6 sense — the query goes out with RD=1
// to a server that resolves on our behalf — not a stub zone, which points at
// a zone's own authoritative servers with RD=0.
//
// A forwarded zone is not validated here. Answers carry whatever the upstream
// asserted, exactly as in whole-server forwarder mode, so pointing a signed
// public zone at an upstream silently gives up local DNSSEC validation for it.
// The intended use is the opposite case: an internal zone the public namespace
// cannot resolve at all.
type ForwardZoneConfig struct {
	// Name is the zone apex. Queries at or below it are forwarded.
	Name string `toml:"name"`
	// Servers are the upstreams, in the same forms as forwarderservers:
	// "ip:port", "tls://ip:port", or an https:// URL.
	Servers []string `toml:"servers"`
}

// validateForwardZones refuses a forward zone the operator cannot have meant.
//
// An omitted name is the dangerous one: it canonicalizes to the root, and a
// root forward zone matches every question — so a block that named only its
// servers would silently turn the whole resolver into a forwarder and give up
// local recursion and DNSSEC for everything. Forwarding the root is a real
// choice, but it has to be written as one.
//
// A zone with no server is refused for the opposite reason: it would be
// skipped at match time, so its subtree would resolve publicly. For an
// internal zone that is not a harmless no-op, it is the leak the zone was
// configured to prevent. Better to fail at startup, where it is visible.
func (c *Config) validateForwardZones(add func(string, ...any)) {
	for i := range c.ForwardZones {
		zone := &c.ForwardZones[i]
		// The two name problems are alternatives, but a missing server list is
		// independent of both — reporting only the first would send the
		// operator back for a second run over the same entry.
		switch {
		case strings.TrimSpace(zone.Name) == "":
			add("forward_zone %d has no name; use name = \".\" to forward every query", i+1)
		case !validDomainName(zone.Name):
			add("forward_zone %q is not a valid domain name", zone.Name)
		}
		if len(zone.Servers) == 0 {
			add("forward_zone %q has no servers", zone.Name)
		}
	}
}

// validDomainName reports whether name is structurally a domain name. Its
// character set is deliberately not judged: RFC 2181 section 11 makes a label
// any binary string, so a name this package finds odd may still be legal.
func validDomainName(name string) bool {
	_, ok := dns.IsDomainName(name)
	return ok
}

// ForwardZoneFor returns the most specific configured forward zone covering
// qname, or nil when the query resolves normally. Most specific wins so a
// narrower zone can be pointed somewhere else than the one containing it.
//
// A zone carrying no servers at all is skipped, but only as a guard for a
// Config built in code: validateForwardZones refuses one at startup, because
// letting its subtree resolve publicly is the leak configuring the zone was
// meant to prevent. A zone whose servers are configured but turn out
// unusable still matches here, and the forwarder fails those queries rather
// than sending them to the public upstreams.
//
// The scan is linear because a forward-zone list is a handful of entries an
// operator wrote by hand; an index would cost more to keep honest than it
// saves.
func (c *Config) ForwardZoneFor(qname string) *ForwardZoneConfig {
	if c == nil || len(c.ForwardZones) == 0 || qname == "" {
		return nil
	}
	qname = dns.CanonicalName(qname)

	var (
		best     *ForwardZoneConfig
		bestApex string
	)
	for i := range c.ForwardZones {
		zone := &c.ForwardZones[i]
		if len(zone.Servers) == 0 {
			continue
		}
		apex := dns.CanonicalName(zone.Name)
		if !dns.IsSubDomain(apex, qname) {
			continue
		}
		if best == nil || dns.CountLabel(apex) > dns.CountLabel(bestApex) {
			best, bestApex = zone, apex
		}
	}
	return best
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

// ECSConfig holds the EDNS Client Subnet middleware configuration
// (RFC 7871). Strictly opt-in: when Enabled is false, the resolver
// strips every client-supplied ECS option before forwarding upstream,
// matching the §11 privacy stance and SDNS's historical behaviour.
//
// When Enabled is true, ForwardV4Max and ForwardV6Max cap the
// source-prefix length we'll forward — narrower (more specific)
// client prefixes get clamped down. Defaults are /24 and /56,
// matching common operator practice.
//
// ClientNetworks restricts forwarding to known clients (corporate
// networks, internal load balancers, CDN edges); empty means every
// eligible client.
//
// CacheLimitTTL, MinScopeV4, and MinScopeV6 control how scoped
// answers are stored (Stage 2). They live here so the on-disk
// schema only bumps once across the rollout, even though Stage 1
// doesn't consume them yet.
type ECSConfig struct {
	Enabled        bool     `toml:"enabled"`
	ForwardV4Max   uint8    `toml:"forward_v4"`
	ForwardV6Max   uint8    `toml:"forward_v6"`
	ClientNetworks []string `toml:"client_networks"`
	CacheLimitTTL  Duration `toml:"cache_limit_ttl"`
	MinScopeV4     uint8    `toml:"min_scope_v4"`
	MinScopeV6     uint8    `toml:"min_scope_v6"`
}

// RecursionFirewallMode controls whether request-tree work limits are
// disabled, observed, or enforced.
type RecursionFirewallMode string

const (
	RecursionFirewallModeOff     RecursionFirewallMode = "off"
	RecursionFirewallModeShadow  RecursionFirewallMode = "shadow"
	RecursionFirewallModeEnforce RecursionFirewallMode = "enforce"

	DefaultRecursionFirewallMaxOutboundQueries      uint32 = 128
	DefaultRecursionFirewallMaxInternalQueries      uint32 = 32
	DefaultRecursionFirewallMaxDNSKEYCandidates     uint32 = 4
	DefaultRecursionFirewallMaxRRsetSignatureChecks uint32 = 8
	DefaultRecursionFirewallMaxSignatureChecks      uint32 = 32
	DefaultRecursionFirewallMaxDSDigests            uint32 = 32
	DefaultRecursionFirewallMaxNSEC3Hashes          uint32 = 32
	DefaultRecursionFirewallMaxConcurrentCrypto     uint32 = 32
	DefaultRecursionFirewallFailureCacheSize        int    = 4096
	DefaultRecursionFirewallFailureCacheMinTTL             = 5 * time.Second
	DefaultRecursionFirewallFailureCacheMaxTTL             = 5 * time.Minute
)

// RecursionFirewallConfig controls aggregate and local recursive work limits.
//
// A zero limit means "use the default", not unlimited. Operators that
// need to disable accounting use Mode=off explicitly.
type RecursionFirewallConfig struct {
	Mode                    RecursionFirewallMode `toml:"mode"`
	MaxOutboundQueries      uint32                `toml:"max_outbound_queries"`
	MaxInternalQueries      uint32                `toml:"max_internal_queries"`
	MaxDNSKEYCandidates     uint32                `toml:"max_dnskey_candidates"`
	MaxRRsetSignatureChecks uint32                `toml:"max_rrset_signature_checks"`
	MaxSignatureChecks      uint32                `toml:"max_signature_checks"`
	MaxDSDigests            uint32                `toml:"max_ds_digests"`
	MaxNSEC3Hashes          uint32                `toml:"max_nsec3_hashes"`
	MaxConcurrentCrypto     uint32                `toml:"max_concurrent_crypto"`
	FailureCacheSize        int                   `toml:"failure_cache_size"`
	FailureCacheMinTTL      Duration              `toml:"failure_cache_min_ttl"`
	FailureCacheMaxTTL      Duration              `toml:"failure_cache_max_ttl"`
}

// Normalize applies omission-safe defaults. It deliberately does not
// silently repair an unknown mode; Validate reports that typo to the
// operator instead of selecting a security policy by accident.
func (c *RecursionFirewallConfig) Normalize() {
	if c.Mode == "" {
		c.Mode = RecursionFirewallModeShadow
	}
	if c.MaxOutboundQueries == 0 {
		c.MaxOutboundQueries = DefaultRecursionFirewallMaxOutboundQueries
	}
	if c.MaxInternalQueries == 0 {
		c.MaxInternalQueries = DefaultRecursionFirewallMaxInternalQueries
	}
	if c.MaxDNSKEYCandidates == 0 {
		c.MaxDNSKEYCandidates = DefaultRecursionFirewallMaxDNSKEYCandidates
	}
	if c.MaxRRsetSignatureChecks == 0 {
		c.MaxRRsetSignatureChecks = DefaultRecursionFirewallMaxRRsetSignatureChecks
	}
	if c.MaxSignatureChecks == 0 {
		c.MaxSignatureChecks = DefaultRecursionFirewallMaxSignatureChecks
	}
	if c.MaxDSDigests == 0 {
		c.MaxDSDigests = DefaultRecursionFirewallMaxDSDigests
	}
	if c.MaxNSEC3Hashes == 0 {
		c.MaxNSEC3Hashes = DefaultRecursionFirewallMaxNSEC3Hashes
	}
	if c.MaxConcurrentCrypto == 0 {
		c.MaxConcurrentCrypto = DefaultRecursionFirewallMaxConcurrentCrypto
	}
	if c.FailureCacheSize == 0 {
		c.FailureCacheSize = DefaultRecursionFirewallFailureCacheSize
	}
	if c.FailureCacheMinTTL.Duration == 0 {
		c.FailureCacheMinTTL.Duration = DefaultRecursionFirewallFailureCacheMinTTL
	}
	if c.FailureCacheMaxTTL.Duration == 0 {
		c.FailureCacheMaxTTL.Duration = DefaultRecursionFirewallFailureCacheMaxTTL
	}
}

// Validate verifies the normalized recursion-firewall policy.
func (c RecursionFirewallConfig) Validate() error {
	switch c.Mode {
	case RecursionFirewallModeOff, RecursionFirewallModeShadow, RecursionFirewallModeEnforce:
	default:
		return fmt.Errorf("mode %q must be one of %q, %q, or %q",
			c.Mode,
			RecursionFirewallModeOff,
			RecursionFirewallModeShadow,
			RecursionFirewallModeEnforce)
	}

	if c.MaxOutboundQueries == 0 {
		return fmt.Errorf("max_outbound_queries must be greater than zero")
	}
	if c.MaxInternalQueries == 0 {
		return fmt.Errorf("max_internal_queries must be greater than zero")
	}
	if c.MaxDNSKEYCandidates == 0 {
		return fmt.Errorf("max_dnskey_candidates must be greater than zero")
	}
	if c.MaxRRsetSignatureChecks == 0 {
		return fmt.Errorf("max_rrset_signature_checks must be greater than zero")
	}
	if c.MaxSignatureChecks == 0 {
		return fmt.Errorf("max_signature_checks must be greater than zero")
	}
	if c.MaxDSDigests == 0 {
		return fmt.Errorf("max_ds_digests must be greater than zero")
	}
	if c.MaxNSEC3Hashes == 0 {
		return fmt.Errorf("max_nsec3_hashes must be greater than zero")
	}
	if c.MaxConcurrentCrypto == 0 {
		return fmt.Errorf("max_concurrent_crypto must be greater than zero")
	}
	if c.FailureCacheSize <= 0 {
		return fmt.Errorf("failure_cache_size must be greater than zero")
	}
	if c.FailureCacheMinTTL.Duration < time.Second {
		return fmt.Errorf("failure_cache_min_ttl must be at least 1s")
	}
	if c.FailureCacheMaxTTL.Duration < c.FailureCacheMinTTL.Duration {
		return fmt.Errorf("failure_cache_max_ttl must be greater than or equal to failure_cache_min_ttl")
	}
	if c.FailureCacheMaxTTL.Duration > 5*time.Minute {
		return fmt.Errorf("failure_cache_max_ttl must not exceed 5m")
	}

	return nil
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

# Aggressively reuse locally validated NSEC/NSEC3 records to answer
# later negative queries without another authoritative lookup (RFC 8198).
# Set false as an operational kill switch. Exact negative caching and
# RFC 8020 NXDOMAIN subtree cuts remain active.
rfc8198 = true

# Cache recursive resolution failures and failed-authority state (RFC 9520).
# Set false only as an emergency rollback switch. This disables RFC 9520
# conformance: SERVFAIL responses and failed-authority state are not cached,
# which can increase upstream retry load. Per-server retry ceilings, request
# work limits, DNSSEC validation, and ordinary positive/NXDOMAIN caching remain
# active.
rfc9520 = true

# Serve an expired positive answer as a last resort when resolution ends in
# SERVFAIL (RFC 8767). A learned delegation lease remains a hard ceiling, so
# this cannot revive data after a known parent-granted cut expires. The
# optional duration is measured from the answer TTL's expiry. It defaults to
# 24 hours. An explicit zero leaves the delegation lease as the only upper
# bound; in forwarder mode, which has no learned delegation cut, zero permits
# retention until cache eviction.
serve_stale = false
serve_stale_max_ttl = "24h"

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
# Supports plain DNS (port 53), DNS-over-TLS (tls:// prefix), and
# DNS-over-HTTPS (https:// prefix, RFC 8484). DoH URLs accept either an
# IP literal or a hostname — hostnames are resolved once at startup
# through the system resolver and the resulting IPs are pinned for the
# process lifetime (no per-query DNS dependency).
forwarderservers = [
    # Examples:
    # "8.8.8.8:53",                          # Standard DNS
    # "[2001:4860:4860::8888]:53",           # Standard DNS IPv6
    # "tls://8.8.8.8:853",                   # DNS-over-TLS
    # "https://1.1.1.1/dns-query",           # DoH, IP literal
    # "https://cloudflare-dns.com/dns-query" # DoH, hostname (system-resolver bootstrap)
]

# Per-zone forwarding
# Sends one zone's queries to its own upstreams while everything else still
# resolves recursively. This is forwarding in the RFC 8499 sense — the query
# goes out with RD=1 to a resolver that answers on our behalf — so the
# upstreams must be recursive resolvers, not the zone's authoritative servers.
# The most specific matching zone wins. A zone must name itself and at least
# one server or startup fails — an omitted name would forward every query —
# and a zone whose upstreams all turn out unusable fails its queries rather
# than borrowing forwarderservers, which would send an internal zone's
# questions to public resolvers. Servers take the same forms as
# forwarderservers, so DoT and DoH work per zone too.
#
# A forwarded zone is NOT validated here: answers carry whatever the upstream
# asserted, exactly as in whole-server forwarder mode. Pointing a signed
# public zone at an upstream therefore gives up local DNSSEC validation for
# it. The intended use is the opposite case — an internal zone the public
# namespace cannot resolve at all.
#
# [[forward_zone]]
# name = "corp.example."
# servers = ["10.0.0.53:53", "tls://10.0.0.54:853"]

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
# Options: error, warn, info, debug
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

# Legacy error-cache ceiling retained for configuration compatibility.
# Recursive resolution failures use the RFC 9520 failure_cache_* settings
# below instead of DNS-message TTLs.
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
# Server Resources
# ============================

# The serving bounds — worker pool, in-flight query cap, TCP/DoT
# connection cap — are derived at startup from this machine's memory,
# CPUs and file-descriptor limit, and logged as each listener starts.
# The keys below override the derived defaults; leave them unset unless
# a measurement says otherwise.

# Fixed handler workers per listener
# ingressworkers = 256

# Ready-queue depth before a query is served on its own goroutine
# ingressqueue = 64

# Concurrent inbound TCP/DoT connection cap
# ingresstcpconns = 1024

# Return a traffic burst's memory to the operating system after a long
# idle (several minutes quiescent). The trim is one synchronous GC over
# the whole process, so it is meant for memory-constrained devices —
# containers on routers, small VPSes — not for busy servers.
# memorytrim = true

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
domainmetricslimit = 1000

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

# QNAME minimization (RFC 9156)
# Sends upstream servers only the labels the current delegation already
# justifies, instead of the whole query name. Past the budget the full name
# goes out, so every delegation below that point sees all of it.
#
# qname_max_minimize_count: minimized queries one lookup may spend.
#                           0 disables minimization. RFC recommends 10.
# qname_minimize_one_label: how many of those add a single label before the
#                           remaining labels are grouped over the queries
#                           left. 0 selects the RFC's suggested 4.
#
# Replaces qname_min_level, which counted delegation depth rather than
# queries; it is still read when qname_max_minimize_count is unset.
qname_max_minimize_count = 10
qname_minimize_one_label = 4

# Hyperlocal root (RFC 8806)
# Serve the root zone from a local copy: transferred over AXFR from the root
# servers that publish it, verified against the zone's ZONEMD digest
# (RFC 8976) chained to the root trust anchors, and refreshed on the zone's
# own SOA schedule. Root referrals, junk-TLD NXDOMAINs and questions asked
# at the root itself then cost no upstream query and leak nothing to the
# root servers. A copy that cannot be refreshed is withdrawn at its SOA
# expire and resolution falls back to the real root servers unchanged.
# hyperlocal_root_sources overrides the built-in transfer hosts (host:port).
hyperlocal_root = false
# hyperlocal_root_sources = ["b.root-servers.net:53", "k.root-servers.net:53"]

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
# EDNS Client Subnet (RFC 7871)
# ============================

# ECS lets a recursive resolver pass a slice of the client's IP to
# the authoritative server so geo-aware services (CDN, load
# balancers) can return locality-appropriate answers. SDNS strips
# ECS by default per RFC 7871 §11 privacy guidance; this section is
# strictly opt-in.
#
# Stage 1 of the feature (this release) ships upstream forwarding.
# Stage 2 (subsequent release) will partition the cache so a
# geo-tailored answer for one client subnet isn't served to a
# client in a different subnet (cache pollution). The cache_limit
# and min_scope knobs below already live in the schema so the
# Stage 2 upgrade doesn't bump configver again.
[ecs]

# Master switch. When false (default) every option below is ignored
# and SDNS strips client ECS before forwarding. Leave off unless
# downstream geo-routing actually benefits from per-subnet answers.
enabled = false

# Maximum source-prefix length forwarded upstream. Clients that
# send narrower (more specific) prefixes get clamped to this value
# so the resolver doesn't leak more locality than the operator
# intended. /24 for IPv4 and /56 for IPv6 match common practice.
forward_v4 = 24
forward_v6 = 56

# CIDRs eligible for ECS forwarding. Empty (the default) means
# every client whose query reaches this resolver. Populate to scope
# forwarding to known internal sources (load balancers, CDN edges,
# corporate networks) and strip ECS for the open internet.
client_networks = []

# Stage 2 (cache) knobs — declared here so the config schema only
# bumps once. They are no-ops in this release.

# Ceiling on the TTL of any scoped (per-subnet) cache entry. Geo
# answers tend to go stale faster than the resolver's general TTL
# would suggest; "5m" is a defensible default.
cache_limit_ttl = "5m"

# Refuse to key the cache on scopes narrower than these. Caps
# worst-case cardinality so a busy resolver with diverse clients
# can't blow up the cache budget on per-client entries. Defaults
# match the forwarding ceilings.
min_scope_v4 = 24
min_scope_v6 = 56

# ============================
# Recursion Firewall
# ============================

# Bounds aggregate resolver work across the complete request tree,
# including retries and nested resolver-generated queries.
[recursion_firewall]

# "off" disables accounting, "shadow" records would-be limit
# crossings without changing replies, and "enforce" terminates
# over-budget recursion with SERVFAIL. Shadow is the rollout-safe
# default for existing installations.
mode = "shadow"

# Maximum outbound transport attempts in one request tree. Retries
# and UDP-to-TCP fallbacks each consume another attempt.
# 0 uses the default (128); use mode = "off" to disable accounting.
max_outbound_queries = 128

# Maximum resolver-generated child queries in one request tree,
# including cache-missed DS/DNSKEY, NS-address, and alias lookups.
# 0 uses the default (32); use mode = "off" to disable accounting.
max_internal_queries = 32

# Maximum same-tag DNSKEY candidates tried for one signature or DS
# record, and signatures tried for one RRset.
max_dnskey_candidates = 4
max_rrset_signature_checks = 8

# Aggregate DNSSEC operations across the complete request tree.
# Keep shadow mode enabled first and calibrate these limits from the
# dnssec_work_per_request histogram (especially NSEC3 p99) before enforce.
max_signature_checks = 32
max_ds_digests = 32
max_nsec3_hashes = 32

# Maximum signature, DS-digest, or NSEC3-hash operations executing
# concurrently across request trees handled by this resolver.
max_concurrent_crypto = 32

# RFC 9520 resolution-failure cache. This cache is active independently
# of mode: mode controls work accounting, while failure caching and the
# per-server retry ceiling are resolver protocol requirements.
#
# The first failed resolution is held for 5s. Repeated failures back off
# exponentially up to 5m. RFC 9520 requires every active failure interval
# to stay between 1s and 5m.
failure_cache_size = 4096
failure_cache_min_ttl = "5s"
failure_cache_max_ttl = "5m"

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

// defaultQnameMinimizeOneLabel is RFC 9156 section 2.3's suggested
// MINIMISE_ONE_LAB. It stands in for an unset qname_minimize_one_label
// because the alternative reading of zero — group from the very first
// query — hands a deep name to the first server almost whole.
const defaultQnameMinimizeOneLabel = 4

// QnameMinimizeParams resolves the RFC 9156 minimization parameters: the
// deprecated qname_min_level is folded in when the current key is unset, and
// the pair is clamped into a shape the resolver can use. It is pure and
// idempotent, so a Config built in code — tests, embedders — reaches the same
// values Load produces.
func (c *Config) QnameMinimizeParams() (maxCount, oneLabel int) {
	if c.QnameMaxMinimizeCount != nil {
		// Written is written: an explicit zero switches minimization off
		// and must not fall back to a deprecated key still in the file.
		maxCount = *c.QnameMaxMinimizeCount
	} else {
		maxCount = c.QnameMinLevel
	}
	if maxCount < 0 {
		maxCount = 0
	}

	oneLabel = c.QnameMinimizeOneLabel
	if oneLabel <= 0 {
		oneLabel = defaultQnameMinimizeOneLabel
	}
	if oneLabel > maxCount {
		oneLabel = maxCount
	}

	return maxCount, oneLabel
}

// normalizeQnameMinimize settles the minimization parameters on the loaded
// config and says so once when a config is still on the deprecated key.
func (c *Config) normalizeQnameMinimize() {
	if c.QnameMaxMinimizeCount == nil && c.QnameMinLevel > 0 {
		zlog.Warn("Config qname_min_level is deprecated, use qname_max_minimize_count",
			zlog.Int("qname_min_level", c.QnameMinLevel))
	}

	maxCount, oneLabel := c.QnameMinimizeParams()
	c.QnameMaxMinimizeCount, c.QnameMinimizeOneLabel = &maxCount, oneLabel
}

// Load loads the given config file.
func Load(cfgfile, version string) (*Config, error) {
	config := new(Config)

	// A missing config is generated whatever it is called and wherever
	// it points: the -c flag promises exactly that. (An sdns.toml
	// fallback lived here once, for configs from the earliest releases;
	// it also made an explicit path load an unrelated file from the
	// working directory, and the releases it served are long gone.)
	if _, err := os.Stat(cfgfile); os.IsNotExist(err) {
		// An operator upgrading across the fallback's removal would
		// otherwise get a silent fresh default while their old file sits
		// ignored. The location the removed fallback actually loaded was
		// the literal "sdns.toml" in the process working directory,
		// whenever the requested basename was sdns.conf — so that is the
		// path that must be probed; the sibling of an explicit -c path is
		// checked as a courtesy on top.
		legacies := []string{filepath.Join(filepath.Dir(cfgfile), "sdns.toml")}
		if filepath.Base(cfgfile) == "sdns.conf" && filepath.Clean(legacies[0]) != "sdns.toml" {
			legacies = append(legacies, "sdns.toml")
		}
		for _, legacy := range legacies {
			if _, err := os.Stat(legacy); err == nil {
				zlog.Warn("Found a legacy sdns.toml, but it is no longer loaded; generating a new config instead. Migrate your settings manually.",
					zlog.String("legacy", legacy), zlog.String("path", cfgfile))
				break
			}
		}
		if err := generateConfig(cfgfile); err != nil {
			return nil, err
		}
	}

	zlog.Info("Loading config file...", zlog.String("path", cfgfile))

	metadata, err := toml.DecodeFile(cfgfile, config)
	if err != nil {
		return nil, fmt.Errorf("could not load config: %s", err)
	}
	if !metadata.IsDefined("serve_stale_max_ttl") {
		config.ServeStaleMaxTTL.Duration = defaultServeStaleMaxTTL
	}

	if config.Version != configver {
		zlog.Warn("Config file is out of version, you can generate new one and check the changes.")
	}

	// Before the gate, like the DNSSEC default below, because the checks read
	// the settled value: outboundip6s is only judged when v6 is in use, and
	// root6servers only count as roots then too.
	if !config.IPv6Access {
		if err := ipv6Probe(); err == nil {
			config.IPv6Access = true
		}
	}

	// Before the gate, because omitting the key means validation is on: the
	// coercion below used to run after it, so a file naming neither dnssec
	// nor a trust anchor passed the anchor check as if validation were off
	// and then ran with it on and nothing to anchor to.
	if config.DNSSEC == "" {
		config.DNSSEC = "on"
	}

	config.RecursionFirewall.Normalize()

	// Keys the file carries that no field claims: a typo, or a setting an
	// older SDNS understood and this one no longer does. Either way the
	// operator wrote something that will not take effect, so it is recorded
	// and logged. Startup only warns — refusing to run over a stale key
	// would turn an upgrade into an outage — while `sdns -t`, whose whole
	// job is to answer "is this file right", treats it as a failure.
	for _, key := range metadata.Undecoded() {
		config.undecodedKeys = append(config.undecodedKeys, key.String())
		zlog.Warn("Unknown config key, ignored", "key", key.String(), "path", cfgfile)
	}

	// One gate, so a file with several mistakes is fixed in one pass rather
	// than one error per run. When the file is failing anyway, the unknown
	// keys join the report — they still never cause a failure on their own,
	// but omitting them here would send the operator back for a second run.
	if err := config.validateLoaded(); err != nil {
		if len(config.undecodedKeys) > 0 {
			return nil, fmt.Errorf("%w\n  - unknown keys (a typo, or settings this version no longer has): %s",
				err, strings.Join(config.undecodedKeys, ", "))
		}
		return nil, err
	}

	// After the gate, not before: normalizing folds a negative minimization
	// count to zero and a negative one-label count to the default, so running
	// it first would hand Validate the settled value and hide what the file
	// actually said.
	config.normalizeQnameMinimize()

	if _, err := os.Stat(config.Directory); os.IsNotExist(err) {
		if err := os.Mkdir(config.Directory, 0750); err != nil {
			return nil, fmt.Errorf("error creating working directory: %s", err)
		}
	}

	zlog.Info("Working directory", zlog.String("path", config.Directory))

	config.sVersion = version

	if config.CookieSecret == "" {
		// 16 random bytes (128-bit) hex-encoded to a 32-char secret.
		// The previous fmt.Sprintf("%16x", uint64) was *space*-padded,
		// not zero-padded, so small random values produced low-entropy
		// secrets like "              2a" — weakening DNS Cookie
		// (RFC 7873) anti-spoofing.
		secret := make([]byte, 16)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		config.CookieSecret = hex.EncodeToString(secret)
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

// ipv6Probe answers whether this host can reach the IPv6 internet. Loading a
// configuration that does not already declare IPv6 access asks it, and the
// answer costs a round trip to a root server — so it is a variable, letting
// tests settle the question without going near the network.
var ipv6Probe = testIPv6Network

// ipv6ProbeServer is the address the probe asks. A variable so a test can
// point it at a server it controls and cover the probe itself rather than
// stubbing past it.
var ipv6ProbeServer = net.JoinHostPort("2001:500:2::c", "53") // a root server

func testIPv6Network() error {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client := dnsclient.Client{Proto: "udp", Timeout: 2 * time.Second}
	_, _, err := client.Exchange(ctx, req, ipv6ProbeServer)
	return err
}
