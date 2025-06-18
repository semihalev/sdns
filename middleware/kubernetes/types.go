// Package kubernetes - DNS types
package kubernetes

import (
	"net"

	"github.com/miekg/dns"
)

// Service represents a Kubernetes service
type Service struct {
	Name         string
	Namespace    string
	Type         string   // ClusterIP, NodePort, LoadBalancer, ExternalName
	ClusterIPs   [][]byte // Dual-stack: [IPv4, IPv6] addresses
	IPFamilies   []string // ["IPv4", "IPv6"] or ["IPv6", "IPv4"]
	ExternalName string   // For ExternalName type
	Headless     bool     // True if ClusterIP is None
	Ports        []Port
}

// Port represents a service port
type Port struct {
	Name     string
	Port     int
	Protocol string // TCP, UDP
}

// Endpoint represents a service endpoint
type Endpoint struct {
	Addresses []string   // Dual-stack: [IPv4, IPv6] addresses
	Hostname  string     // Optional hostname
	Ready     bool       // Is endpoint ready
	TargetRef *ObjectRef // Reference to pod
}

// Pod represents a Kubernetes pod
type Pod struct {
	Name      string
	Namespace string
	IPs       []string // Dual-stack: [IPv4, IPv6] addresses
	Hostname  string   // Pod hostname
	Subdomain string   // For StatefulSet DNS
}

// ObjectRef references another object
type ObjectRef struct {
	Kind      string
	Name      string
	Namespace string
}

// Response holds DNS query results
type Response struct {
	Answer []dns.RR
	Extra  []dns.RR
	Rcode  int
}

// GetIPv4 returns the IPv4 address if available
func (s *Service) GetIPv4() []byte {
	if len(s.ClusterIPs) > 0 {
		// If IPFamilies is set, use it
		if len(s.IPFamilies) > 0 {
			for i, family := range s.IPFamilies {
				if family == "IPv4" && i < len(s.ClusterIPs) {
					return s.ClusterIPs[i]
				}
			}
		} else {
			// No IPFamilies, check by IP size
			for _, ip := range s.ClusterIPs {
				if len(ip) == 4 {
					return ip
				}
			}
		}
	}
	return nil
}

// GetIPv6 returns the IPv6 address if available
func (s *Service) GetIPv6() []byte {
	if len(s.ClusterIPs) > 0 {
		// If IPFamilies is set, use it
		if len(s.IPFamilies) > 0 {
			for i, family := range s.IPFamilies {
				if family == "IPv6" && i < len(s.ClusterIPs) {
					return s.ClusterIPs[i]
				}
			}
		} else {
			// No IPFamilies, check by IP size
			for _, ip := range s.ClusterIPs {
				if len(ip) == 16 {
					return ip
				}
			}
		}
	}
	return nil
}

// GetIPv4 returns the IPv4 address from pod IPs
func (p *Pod) GetIPv4() string {
	for _, ip := range p.IPs {
		if pip := net.ParseIP(ip); pip != nil && pip.To4() != nil {
			return ip
		}
	}
	return ""
}

// GetIPv6 returns the IPv6 address from pod IPs
func (p *Pod) GetIPv6() string {
	for _, ip := range p.IPs {
		if pip := net.ParseIP(ip); pip != nil && pip.To4() == nil {
			return ip
		}
	}
	return ""
}

// GetIPv4 returns IPv4 address from endpoint addresses
func (e *Endpoint) GetIPv4() string {
	for _, addr := range e.Addresses {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			return addr
		}
	}
	return ""
}

// GetIPv6 returns IPv6 address from endpoint addresses
func (e *Endpoint) GetIPv6() string {
	for _, addr := range e.Addresses {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
			return addr
		}
	}
	return ""
}
