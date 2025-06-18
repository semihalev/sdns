// Package kubernetes - Common constants for Kubernetes middleware
package kubernetes

import "time"

// Cache configuration constants
const (
	// Cache sizes and limits
	CacheMaxEntries      = 10000 // Maximum number of entries in zero-alloc cache
	CacheIndexSize       = 16384 // Must be power of 2 for fast modulo
	CacheLockStripes     = 256   // Number of lock stripes for sharding
	CacheMaxWireSize     = 4096  // Maximum wire format DNS message size (EDNS0 support)
	CacheLinearProbeSize = 16    // Maximum linear probe attempts for collision handling

	// Cache cleanup and expiry
	CacheCleanupInterval = 10 * time.Second
	CacheDefaultTTL      = 30 // Default TTL in seconds
)

// Sharding constants for registry
const (
	RegistryServiceShards = 256 // Number of shards for services
	RegistryPodShards     = 256 // Number of shards for pods
)

// Predictor constants
const (
	PredictorBufferSize     = 1024 // Size of circular buffer for recent queries
	PredictorMaxPredictions = 10   // Maximum predictions in pool
	PredictorMaxResults     = 5    // Maximum predictions to return
	PredictorThresholdDiv   = 10   // Threshold divisor (>10% probability)
	PredictorTrainInterval  = 30 * time.Second
)

// Network constants
const (
	IPv4AddressSize = 4  // Size of IPv4 address in bytes
	IPv6AddressSize = 16 // Size of IPv6 address in bytes
)

// Performance monitoring constants
const (
	StatsLogInterval = 30 * time.Second // Interval for logging statistics
)

// Service population constants (for demo/test data)
const (
	DemoServiceCount = 10 // Number of demo services to create
)

// Client timeout constants
const (
	ClientStopTimeout = 5 * time.Second // Timeout for client stop operation
)

// DNS query type constants (for ML predictor)
const (
	DNSTypeA    = 1  // A record type
	DNSTypeAAAA = 28 // AAAA record type
)

// Hash constants
const (
	FNVOffsetBasis = 14695981039346656037 // FNV-1a offset basis
	FNVPrime       = 1099511628211        // FNV-1a prime
	HashMultiplier = 31                   // Simple hash multiplier
)

// Registry statistics percentage calculation
const (
	PercentageMultiplier = 100
)

// SRV record constants
const (
	SRVPriority = 0   // Default SRV priority
	SRVWeight   = 100 // Default SRV weight for single entry
	SRVWeight1  = 1   // Alternative SRV weight
)

// IP byte positions
const (
	IPv4LastOctetIndex = 3  // Index of last octet in IPv4 address
	IPv6LastByteIndex  = 15 // Index of last byte in IPv6 address
)

// Wire format constants
const (
	WireMessageIDOffset = 0 // Offset of message ID in DNS wire format
	WireMessageIDSize   = 2 // Size of message ID in bytes
)

// Benchmark and test constants
const (
	BenchmarkServiceStart = 1      // Starting index for benchmark services
	NetworkOctet10        = 10     // First octet for test IPs (10.x.x.x)
	NetworkOctet96        = 96     // Second octet for test IPs (10.96.x.x)
	NetworkOctet244       = 244    // Third octet for test pod IPs (10.244.x.x)
	IPv6TestPrefix        = 0xfe80 // IPv6 test prefix (fe80::)
)

// Port numbers for test services
const (
	PortHTTPS = 443 // HTTPS port
	PortDNS   = 53  // DNS port
)
