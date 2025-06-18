package kubernetes

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ExtendedService adds IPv6 support to Service
type ExtendedService struct {
	*Service
	ClusterIPv6 []byte // IPv6 address as bytes
}

// ExtendedPod adds IPv6 support to Pod
type ExtendedPod struct {
	*Pod
	IPv6 string // Pod IPv6 address
}

// ExtendedEndpoint adds IPv6 support to Endpoint
type ExtendedEndpoint struct {
	*Endpoint
	IPv6Address string // IPv6 address
}

// ResolveIPv6 handles IPv6 queries properly
func ResolveIPv6(svc *Service, qname string, qtype uint16) []dns.RR {
	var answers []dns.RR

	// For full IPv6 support, we'd need:
	// 1. Dual-stack ClusterIPs
	// 2. IPv6 endpoints
	// 3. IPv6 pod IPs

	if qtype == dns.TypeAAAA {
		if ipv6 := svc.GetIPv6(); ipv6 != nil {
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				AAAA: net.IP(ipv6),
			})
		}
	}

	return answers
}

// ParseIPv6PodQuery parses IPv6 pod queries
// Format: 2001-db8--1.namespace.pod.cluster.local
func ParseIPv6PodQuery(query string) (net.IP, bool) {
	// Extract first part before namespace
	parts := strings.Split(query, ".")
	if len(parts) < 5 {
		return nil, false
	}

	ipPart := parts[0]

	// Convert pod format to IPv6
	// Replace -- with ::
	ipStr := strings.ReplaceAll(ipPart, "--", "::")
	ipStr = strings.ReplaceAll(ipStr, "-", ":")

	ip := net.ParseIP(ipStr)
	return ip, ip != nil && ip.To4() == nil // Must be IPv6
}

// HandleIPv6PTR handles IPv6 reverse DNS
// Format: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
func HandleIPv6PTR(labels []string) (net.IP, bool) {
	if len(labels) < 34 || !strings.HasSuffix(strings.Join(labels, "."), "ip6.arpa") {
		return nil, false
	}

	// Reverse the nibbles
	var nibbles []string
	for i := len(labels) - 3; i >= 0; i-- { // Skip "ip6.arpa"
		nibbles = append(nibbles, labels[i])
	}

	// Group into IPv6 format
	var groups []string
	for i := 0; i < len(nibbles); i += 4 {
		if i+3 < len(nibbles) {
			group := nibbles[i] + nibbles[i+1] + nibbles[i+2] + nibbles[i+3]
			groups = append(groups, group)
		}
	}

	ipStr := strings.Join(groups, ":")
	ip := net.ParseIP(ipStr)

	return ip, ip != nil
}

// DualStackResponse creates both A and AAAA responses
func DualStackResponse(qname string, ipv4, ipv6 net.IP) []dns.RR {
	var answers []dns.RR

	if ipv4 != nil && ipv4.To4() != nil {
		answers = append(answers, &dns.A{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: ipv4.To4(),
		})
	}

	if ipv6 != nil && ipv6.To4() == nil {
		answers = append(answers, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			AAAA: ipv6,
		})
	}

	return answers
}

// Full IPv6 Support Requirements:
// 1. Kubernetes 1.16+ with IPv6 enabled
// 2. Dual-stack cluster configuration
// 3. Service.spec.ipFamilies: ["IPv4", "IPv6"]
// 4. Service.spec.ipFamilyPolicy: "PreferDualStack"
// 5. CNI plugin with IPv6 support

// What we're missing for 100% IPv6:
// - [ ] Dual ClusterIPs (IPv4 + IPv6) per service
// - [ ] IPv6 addresses in Endpoints
// - [ ] IPv6 pod IPs with proper formatting
// - [ ] Full ip6.arpa reverse DNS
// - [ ] IPv6 node addresses
// - [ ] IPv6-only cluster support
