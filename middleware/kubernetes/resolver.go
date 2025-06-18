// Package kubernetes - DNS resolver
package kubernetes

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Resolver handles DNS resolution for Kubernetes resources
type Resolver struct {
	clusterDomain string
	registry      *Registry
	cache         *Cache
}

// NewResolver creates a new resolver
func NewResolver(clusterDomain string, cache *Cache) *Resolver {
	return &Resolver{
		clusterDomain: clusterDomain,
		registry:      NewRegistry(),
		cache:         cache,
	}
}

// Resolve handles a DNS query
func (r *Resolver) Resolve(qname string, qtype uint16) (*Response, bool) {
	qname = strings.ToLower(qname)

	// Check if it's a cluster query
	if !r.isClusterQuery(qname) {
		return nil, false
	}

	// Parse the query
	parts := r.parseQuery(qname)
	if parts == nil {
		return nil, false
	}

	switch parts.queryType {
	case qtypeService:
		return r.resolveService(parts, qname, qtype), true
	case qtypePod:
		return r.resolvePod(parts, qname, qtype), true
	case qtypeSRV:
		return r.resolveSRV(parts, qname, qtype), true
	case qtypePTR:
		return r.resolvePTR(parts, qname, qtype), true
	default:
		return &Response{Rcode: dns.RcodeNameError}, true
	}
}

// Query types
const (
	qtypeUnknown = iota
	qtypeService
	qtypePod
	qtypeSRV
	qtypePTR
)

// queryParts holds parsed query information
type queryParts struct {
	queryType int
	service   string
	namespace string
	pod       string
	port      string
	protocol  string
	ip        net.IP
}

// isClusterQuery checks if query is for cluster domain
func (r *Resolver) isClusterQuery(qname string) bool {
	return strings.HasSuffix(qname, "."+r.clusterDomain+".") ||
		strings.HasSuffix(qname, ".in-addr.arpa.") ||
		strings.HasSuffix(qname, ".ip6.arpa.")
}

// parseQuery parses a DNS query
func (r *Resolver) parseQuery(qname string) *queryParts {
	// Handle PTR queries (both IPv4 and IPv6)
	if strings.HasSuffix(qname, ".in-addr.arpa.") || strings.HasSuffix(qname, ".ip6.arpa.") {
		return r.parsePTR(qname)
	}

	// Remove cluster domain
	name := strings.TrimSuffix(qname, ".")
	name = strings.TrimSuffix(name, "."+r.clusterDomain)

	labels := strings.Split(name, ".")

	// Service: name.namespace.svc
	if len(labels) >= 3 && labels[len(labels)-1] == "svc" {
		// Check for SRV: _port._protocol.name.namespace.svc
		if len(labels) >= 5 && strings.HasPrefix(labels[0], "_") {
			return &queryParts{
				queryType: qtypeSRV,
				port:      strings.TrimPrefix(labels[0], "_"),
				protocol:  strings.TrimPrefix(labels[1], "_"),
				service:   strings.Join(labels[2:len(labels)-2], "."),
				namespace: labels[len(labels)-2],
			}
		}

		return &queryParts{
			queryType: qtypeService,
			service:   strings.Join(labels[0:len(labels)-2], "."),
			namespace: labels[len(labels)-2],
		}
	}

	// Pod: pod-ip.namespace.pod (supports both IPv4 and IPv6)
	if len(labels) >= 3 && labels[len(labels)-1] == "pod" {
		if ip := ParsePodIP(labels[0]); ip != nil {
			return &queryParts{
				queryType: qtypePod,
				namespace: labels[len(labels)-2],
				ip:        ip,
			}
		}
	}

	// StatefulSet pod: pod-name.service.namespace.svc.cluster.local
	if len(labels) >= 6 && labels[len(labels)-3] == "svc" &&
		labels[len(labels)-2] == "cluster" && labels[len(labels)-1] == "local" {
		return &queryParts{
			queryType: qtypePod,
			pod:       labels[0],
			service:   strings.Join(labels[1:len(labels)-4], "."),
			namespace: labels[len(labels)-4],
		}
	}

	return nil
}

// parsePTR parses PTR query for both IPv4 and IPv6
func (r *Resolver) parsePTR(qname string) *queryParts {
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")

	// Use our utility to parse both IPv4 and IPv6 reverse queries
	if ip, ok := ParseReverseIP(labels); ok && ip != nil {
		return &queryParts{
			queryType: qtypePTR,
			ip:        ip,
		}
	}

	return nil
}

// resolveService handles service queries
func (r *Resolver) resolveService(parts *queryParts, qname string, qtype uint16) *Response {
	svc := r.registry.GetService(parts.service, parts.namespace)
	if svc == nil {
		return &Response{Rcode: dns.RcodeNameError}
	}

	resp := &Response{Rcode: dns.RcodeSuccess}

	// Handle ExternalName
	if svc.Type == "ExternalName" && svc.ExternalName != "" {
		if qtype == dns.TypeCNAME || qtype == dns.TypeANY {
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				Target: dns.Fqdn(svc.ExternalName),
			})
		}
		return resp
	}

	// Handle A/AAAA queries
	if qtype == dns.TypeA || qtype == dns.TypeAAAA || qtype == dns.TypeANY {
		if svc.Headless {
			// Return endpoint IPs
			endpoints := r.registry.GetEndpoints(parts.service, parts.namespace)
			for _, ep := range endpoints {
				if !ep.Ready {
					continue
				}

				// Handle IPv4
				if qtype == dns.TypeA || qtype == dns.TypeANY {
					if ipv4 := ep.GetIPv4(); ipv4 != "" {
						if ip := net.ParseIP(ipv4); ip != nil {
							resp.Answer = append(resp.Answer, &dns.A{
								Hdr: dns.RR_Header{
									Name:   qname,
									Rrtype: dns.TypeA,
									Class:  dns.ClassINET,
									Ttl:    30,
								},
								A: ip.To4(),
							})
						}
					}
				}

				// Handle IPv6
				if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
					if ipv6 := ep.GetIPv6(); ipv6 != "" {
						if ip := net.ParseIP(ipv6); ip != nil {
							resp.Answer = append(resp.Answer, &dns.AAAA{
								Hdr: dns.RR_Header{
									Name:   qname,
									Rrtype: dns.TypeAAAA,
									Class:  dns.ClassINET,
									Ttl:    30,
								},
								AAAA: ip,
							})
						}
					}
				}
			}
		} else {
			// Return ClusterIP(s)
			if qtype == dns.TypeA || qtype == dns.TypeANY {
				if ipv4 := svc.GetIPv4(); ipv4 != nil {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: net.IP(ipv4),
					})
				}
			}

			if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
				if ipv6 := svc.GetIPv6(); ipv6 != nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{
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
		}
	}

	return resp
}

// resolvePod handles pod queries
func (r *Resolver) resolvePod(parts *queryParts, qname string, qtype uint16) *Response {
	resp := &Response{Rcode: dns.RcodeSuccess}

	// Pod by IP
	if parts.ip != nil {
		pod := r.registry.GetPodByIP(parts.ip.String())
		if pod == nil || pod.Namespace != parts.namespace {
			return &Response{Rcode: dns.RcodeNameError}
		}

		if qtype == dns.TypeA || qtype == dns.TypeANY {
			if ipv4 := pod.GetIPv4(); ipv4 != "" {
				if ip := net.ParseIP(ipv4); ip != nil {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: ip.To4(),
					})
				}
			}
		}

		if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
			if ipv6 := pod.GetIPv6(); ipv6 != "" {
				if ip := net.ParseIP(ipv6); ip != nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						AAAA: ip,
					})
				}
			}
		}
		return resp
	}

	// StatefulSet pod
	if parts.pod != "" && parts.service != "" {
		// Check if this is a StatefulSet endpoint
		endpoints := r.registry.GetEndpoints(parts.service, parts.namespace)
		for _, ep := range endpoints {
			if ep.Hostname == parts.pod && ep.Ready {
				// Found matching endpoint
				if qtype == dns.TypeA || qtype == dns.TypeANY {
					ipv4 := ep.GetIPv4()
					if ipv4 != "" {
						if ip := net.ParseIP(ipv4); ip != nil {
							resp.Answer = append(resp.Answer, &dns.A{
								Hdr: dns.RR_Header{
									Name:   qname,
									Rrtype: dns.TypeA,
									Class:  dns.ClassINET,
									Ttl:    30,
								},
								A: ip.To4(),
							})
						}
					}
				}

				if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
					if ipv6 := ep.GetIPv6(); ipv6 != "" {
						if ip := net.ParseIP(ipv6); ip != nil {
							resp.Answer = append(resp.Answer, &dns.AAAA{
								Hdr: dns.RR_Header{
									Name:   qname,
									Rrtype: dns.TypeAAAA,
									Class:  dns.ClassINET,
									Ttl:    30,
								},
								AAAA: ip,
							})
						}
					}
				}
				return resp
			}
		}

		// Fallback to pod lookup
		pod := r.registry.GetPodByName(parts.pod, parts.namespace)
		if pod == nil || pod.Subdomain != parts.service {
			return &Response{Rcode: dns.RcodeNameError}
		}

		if qtype == dns.TypeA || qtype == dns.TypeANY {
			if ipv4 := pod.GetIPv4(); ipv4 != "" {
				if ip := net.ParseIP(ipv4); ip != nil {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: ip.To4(),
					})
				}
			}
		}

		if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
			if ipv6 := pod.GetIPv6(); ipv6 != "" {
				if ip := net.ParseIP(ipv6); ip != nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						AAAA: ip,
					})
				}
			}
		}
	}

	return resp
}

// resolveSRV handles SRV queries
func (r *Resolver) resolveSRV(parts *queryParts, qname string, qtype uint16) *Response {
	if qtype != dns.TypeSRV && qtype != dns.TypeANY {
		return &Response{Rcode: dns.RcodeSuccess}
	}

	svc := r.registry.GetService(parts.service, parts.namespace)
	if svc == nil {
		return &Response{Rcode: dns.RcodeNameError}
	}

	resp := &Response{Rcode: dns.RcodeSuccess}

	// Find matching port
	var port *Port
	for i := range svc.Ports {
		p := &svc.Ports[i]
		if (p.Name == parts.port || strconv.Itoa(p.Port) == parts.port) &&
			strings.EqualFold(p.Protocol, parts.protocol) {
			port = p
			break
		}
	}

	if port == nil {
		return &Response{Rcode: dns.RcodeNameError}
	}

	target := fmt.Sprintf("%s.%s.svc.%s.",
		parts.service, parts.namespace, r.clusterDomain)

	resp.Answer = append(resp.Answer, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    30,
		},
		Priority: 0,
		Weight:   1,
		Port:     uint16(port.Port),
		Target:   target,
	})

	// Add additional A record
	if !svc.Headless {
		if ipv4 := svc.GetIPv4(); ipv4 != nil {
			resp.Extra = append(resp.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   target,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: net.IP(ipv4),
			})
		}
	}

	return resp
}

// resolvePTR handles PTR queries
func (r *Resolver) resolvePTR(parts *queryParts, qname string, qtype uint16) *Response {
	if qtype != dns.TypePTR && qtype != dns.TypeANY {
		return &Response{Rcode: dns.RcodeSuccess}
	}

	resp := &Response{Rcode: dns.RcodeSuccess}

	// Check pods first
	pod := r.registry.GetPodByIP(parts.ip.String())
	if pod != nil {
		ipStr := strings.ReplaceAll(parts.ip.String(), ".", "-")
		target := fmt.Sprintf("%s.%s.pod.%s.",
			ipStr, pod.Namespace, r.clusterDomain)

		resp.Answer = append(resp.Answer, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			Ptr: target,
		})
		return resp
	}

	// Check services
	svc := r.registry.GetServiceByIP(parts.ip)
	if svc != nil {
		target := fmt.Sprintf("%s.%s.svc.%s.",
			svc.Name, svc.Namespace, r.clusterDomain)

		resp.Answer = append(resp.Answer, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			Ptr: target,
		})
		return resp
	}

	return &Response{Rcode: dns.RcodeNameError}
}
