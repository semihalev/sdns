package kubernetes

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// ShardedRegistry - Lock-free sharded registry for massive concurrency
type ShardedRegistry struct {
	// Service shards - distributed by hash
	serviceShards [256]*serviceShard

	// Pod shards - distributed by IP
	podShards [256]*podShard

	// Stats
	queries uint64
	hits    uint64

	// TTL configuration
	ttlService uint32
	ttlPod     uint32
	ttlSRV     uint32
	ttlPTR     uint32
}

// serviceShard holds services for one shard
type serviceShard struct {
	mu       sync.RWMutex
	services map[string]*Service // namespace/name -> service
}

// podShard holds pods for one shard
type podShard struct {
	mu   sync.RWMutex
	pods map[string]*Pod // ip -> pod
}

// NewShardedRegistry creates the beast
func NewShardedRegistry() *ShardedRegistry {
	r := &ShardedRegistry{
		// Default TTLs
		ttlService: DefaultServiceTTL,
		ttlPod:     DefaultPodTTL,
		ttlSRV:     DefaultSRVTTL,
		ttlPTR:     DefaultPTRTTL,
	}

	// Initialize all shards
	for i := 0; i < 256; i++ {
		r.serviceShards[i] = &serviceShard{
			services: make(map[string]*Service),
		}
		r.podShards[i] = &podShard{
			pods: make(map[string]*Pod),
		}
	}

	return r
}

// SetTTLs sets custom TTL values
func (r *ShardedRegistry) SetTTLs(service, pod, srv, ptr uint32) {
	// Use defaults if 0 is provided
	if service > 0 {
		r.ttlService = service
	}
	if pod > 0 {
		r.ttlPod = pod
	}
	if srv > 0 {
		r.ttlSRV = srv
	}
	if ptr > 0 {
		r.ttlPTR = ptr
	}
}

// ResolveQuery resolves DNS query with minimal locking
func (r *ShardedRegistry) ResolveQuery(qname string, qtype uint16) ([]dns.RR, bool) {
	atomic.AddUint64(&r.queries, 1)

	// Fast path: parse query type
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) < 3 {
		return nil, false
	}

	// Check query pattern
	switch {
	case strings.HasSuffix(qname, ".svc.cluster.local."):
		return r.resolveService(labels, qtype)

	case strings.HasSuffix(qname, ".pod.cluster.local."):
		return r.resolvePod(labels, qtype)

	case strings.HasSuffix(qname, ".in-addr.arpa."), strings.HasSuffix(qname, ".ip6.arpa."):
		return r.resolveReverse(labels)
	}

	return nil, false
}

// resolveService handles service queries
func (r *ShardedRegistry) resolveService(labels []string, qtype uint16) ([]dns.RR, bool) {
	if len(labels) < 5 {
		return nil, false
	}

	// Check if this is a StatefulSet pod query (pod.service.namespace.svc.cluster.local)
	if len(labels) >= 6 {
		// This might be a StatefulSet pod
		podName := labels[0]
		serviceName := labels[1]
		namespace := labels[2]

		// Try to find the pod - check most likely shards first
		// StatefulSet pods are often numbered, so hash based on name
		hash := uint32(0)
		for i := 0; i < len(podName); i++ {
			hash = hash*31 + uint32(podName[i])
		}
		startShard := int(hash % 256)

		var foundPod *Pod
		// Check likely shard first
		if foundPod = r.findPodInShard(startShard, podName, namespace, serviceName); foundPod == nil {
			// Fall back to checking all shards
			for i := 0; i < 256; i++ {
				if i == startShard {
					continue // Already checked
				}
				if foundPod = r.findPodInShard(i, podName, namespace, serviceName); foundPod != nil {
					break
				}
			}
		}

		if foundPod != nil {
			qname := strings.Join(labels, ".") + "."
			var answers []dns.RR

			if qtype == dns.TypeA || qtype == dns.TypeANY {
				if ipv4Str := foundPod.GetIPv4(); ipv4Str != "" {
					if ip := net.ParseIP(ipv4Str); ip != nil {
						answers = append(answers, &dns.A{
							Hdr: dns.RR_Header{
								Name:   qname,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    r.ttlPod,
							},
							A: ip.To4(),
						})
					}
				}
			}

			if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
				if ipv6Str := foundPod.GetIPv6(); ipv6Str != "" {
					if ip := net.ParseIP(ipv6Str); ip != nil {
						answers = append(answers, &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   qname,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    r.ttlPod,
							},
							AAAA: ip,
						})
					}
				}
			}

			return answers, len(answers) > 0
		}
	}

	// Parse service.namespace.svc.cluster.local
	service := labels[0]
	namespace := labels[1]

	// Handle SRV queries
	if strings.HasPrefix(service, "_") && len(labels) >= 6 {
		// _port._protocol.service.namespace.svc.cluster.local
		return r.resolveSRV(labels)
	}

	// Get shard
	key := namespace + "/" + service
	shard := r.getServiceShard(key)

	shard.mu.RLock()
	svc, ok := shard.services[key]
	shard.mu.RUnlock()

	if !ok {
		return nil, false
	}

	atomic.AddUint64(&r.hits, 1)

	// Build response based on service type
	qname := strings.Join(labels, ".") + "."
	var answers []dns.RR

	// For headless services, return true even with no answers
	if svc.Headless {
		// TODO: Should resolve to endpoint IPs
		return answers, true
	}

	switch qtype {
	case dns.TypeA:
		if ipv4 := svc.GetIPv4(); ipv4 != nil {
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    r.ttlService,
				},
				A: net.IP(ipv4),
			})
		}

	case dns.TypeAAAA:
		if ipv6 := svc.GetIPv6(); ipv6 != nil {
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    r.ttlService,
				},
				AAAA: net.IP(ipv6),
			})
		}

	case dns.TypeCNAME:
		if svc.ExternalName != "" {
			answers = append(answers, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    r.ttlPod,
				},
				Target: svc.ExternalName,
			})
		}
	}

	return answers, len(answers) > 0
}

// resolvePod handles pod queries
func (r *ShardedRegistry) resolvePod(labels []string, qtype uint16) ([]dns.RR, bool) {
	if len(labels) < 5 {
		return nil, false
	}

	// Parse pod IP (supports both IPv4 and IPv6)
	podIP := ParsePodIP(labels[0])
	if podIP == nil {
		return nil, false
	}
	podIPStr := podIP.String()

	// Get shard by IP
	shard := r.getPodShardByIP(podIPStr)

	shard.mu.RLock()
	pod, ok := shard.pods[podIPStr]
	shard.mu.RUnlock()

	if !ok {
		return nil, false
	}

	atomic.AddUint64(&r.hits, 1)

	qname := strings.Join(labels, ".") + "."
	var answers []dns.RR

	switch qtype {
	case dns.TypeA:
		if ipv4Str := pod.GetIPv4(); ipv4Str != "" {
			if ip := net.ParseIP(ipv4Str); ip != nil {
				answers = append(answers, &dns.A{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPod,
					},
					A: ip.To4(),
				})
			}
		}

	case dns.TypeAAAA:
		if ipv6Str := pod.GetIPv6(); ipv6Str != "" {
			if ip := net.ParseIP(ipv6Str); ip != nil {
				answers = append(answers, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPod,
					},
					AAAA: ip,
				})
			}
		}
	}

	return answers, len(answers) > 0
}

// resolveSRV handles SRV queries
func (r *ShardedRegistry) resolveSRV(labels []string) ([]dns.RR, bool) {
	// _port._protocol.service.namespace.svc.cluster.local
	if len(labels) < 6 {
		return nil, false
	}

	port := strings.TrimPrefix(labels[0], "_")
	protocol := strings.TrimPrefix(labels[1], "_")
	service := labels[2]
	namespace := labels[3]

	key := namespace + "/" + service
	shard := r.getServiceShard(key)

	shard.mu.RLock()
	svc, ok := shard.services[key]
	shard.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Find matching port
	for _, p := range svc.Ports {
		if p.Name == port && strings.EqualFold(p.Protocol, protocol) {
			qname := strings.Join(labels, ".") + "."
			target := service + "." + namespace + ".svc.cluster.local."

			return []dns.RR{
				&dns.SRV{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPod,
					},
					Priority: 0,
					Weight:   100,
					Port:     uint16(p.Port),
					Target:   target,
				},
			}, true
		}
	}

	return nil, false
}

// resolveReverse handles PTR queries for both IPv4 and IPv6
func (r *ShardedRegistry) resolveReverse(labels []string) ([]dns.RR, bool) {
	// Parse reverse IP (handles both IPv4 and IPv6)
	ip, ok := ParseReverseIP(labels)
	if !ok || ip == nil {
		return nil, false
	}

	// Check pods first
	shard := r.getPodShardByIP(ip.String())
	shard.mu.RLock()
	pod, ok := shard.pods[ip.String()]
	shard.mu.RUnlock()

	if ok {
		qname := strings.Join(labels, ".") + "."
		// Format pod IP for DNS (handles both IPv4 and IPv6)
		target := FormatPodIP(ip) + "." + pod.Namespace + ".pod.cluster.local."

		return []dns.RR{
			&dns.PTR{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    r.ttlPod,
				},
				Ptr: target,
			},
		}, true
	}

	// Search through all service shards for matching IP
	for i := 0; i < 256; i++ {
		r.serviceShards[i].mu.RLock()
		for _, svc := range r.serviceShards[i].services {
			for _, clusterIP := range svc.ClusterIPs {
				if net.IP(clusterIP).Equal(ip) {
					r.serviceShards[i].mu.RUnlock()
					qname := strings.Join(labels, ".") + "."
					target := svc.Name + "." + svc.Namespace + ".svc.cluster.local."

					return []dns.RR{
						&dns.PTR{
							Hdr: dns.RR_Header{
								Name:   qname,
								Rrtype: dns.TypePTR,
								Class:  dns.ClassINET,
								Ttl:    r.ttlPod,
							},
							Ptr: target,
						},
					}, true
				}
			}
		}
		r.serviceShards[i].mu.RUnlock()
	}

	return nil, false
}

// AddService adds or updates a service
func (r *ShardedRegistry) AddService(svc *Service) {
	key := svc.Namespace + "/" + svc.Name
	shard := r.getServiceShard(key)

	shard.mu.Lock()
	shard.services[key] = svc
	shard.mu.Unlock()
}

// AddPod adds or updates a pod
func (r *ShardedRegistry) AddPod(pod *Pod) {
	// Add pod by all its IPs
	for _, ip := range pod.IPs {
		if ip == "" {
			continue
		}

		key := ip
		shard := r.getPodShardByIP(key)

		shard.mu.Lock()
		shard.pods[key] = pod
		shard.mu.Unlock()
	}
}

// getServiceShard returns shard for service
func (r *ShardedRegistry) getServiceShard(key string) *serviceShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = hash*31 + uint32(key[i])
	}
	return r.serviceShards[hash%256]
}

// getPodShardByIP returns shard for pod IP (supports both IPv4 and IPv6)
func (r *ShardedRegistry) getPodShardByIP(ip string) *podShard {
	// Parse IP to determine type
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return r.podShards[0]
	}

	// IPv4: use last octet
	if ip4 := parsedIP.To4(); ip4 != nil {
		return r.podShards[ip4[3]]
	}

	// IPv6: use last byte
	if ip6 := parsedIP.To16(); ip6 != nil {
		return r.podShards[ip6[15]]
	}

	return r.podShards[0]
}

// findPodInShard looks for a pod in a specific shard
func (r *ShardedRegistry) findPodInShard(shardIdx int, podName, namespace, serviceName string) *Pod {
	shard := r.podShards[shardIdx]
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	for _, pod := range shard.pods {
		if pod.Name == podName && pod.Namespace == namespace && pod.Subdomain == serviceName {
			return pod
		}
	}
	return nil
}

// GetStats returns registry statistics
func (r *ShardedRegistry) GetStats() map[string]int64 {
	services := int64(0)
	pods := int64(0)

	// Count across all shards
	for i := 0; i < 256; i++ {
		r.serviceShards[i].mu.RLock()
		services += int64(len(r.serviceShards[i].services))
		r.serviceShards[i].mu.RUnlock()

		r.podShards[i].mu.RLock()
		pods += int64(len(r.podShards[i].pods))
		r.podShards[i].mu.RUnlock()
	}

	queries := atomic.LoadUint64(&r.queries)
	hits := atomic.LoadUint64(&r.hits)

	return map[string]int64{
		"services":     services,
		"pods":         pods,
		"queries":      int64(queries),
		"hits":         int64(hits),
		"shards":       256,
		"hit_rate_pct": int64(float64(hits) / float64(queries) * 100),
	}
}
