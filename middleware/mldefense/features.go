package mldefense

import (
	"github.com/miekg/dns"
	"time"
)

// QueryFeatures represents extracted features from a DNS query
type QueryFeatures struct {
	// Basic query information
	QueryType          uint16
	QueryClass         uint16
	QueryName          string
	RequestSize        int
	EDNSBufferSize     uint16
	HasEDNS            bool
	IsDNSSEC           bool

	// Amplification-related features
	AmplificationPotential float64 // Estimated response size / request size
	IsHighRiskType         bool    // ANY, TXT, DNSKEY, etc.

	// Behavioral features
	Timestamp          time.Time
	Protocol           string // udp, tcp, doh, doq
}

// AmplificationFactors maps query types to their typical amplification factors
// Based on research: https://www.us-cert.gov/ncas/alerts/TA13-088A
var AmplificationFactors = map[uint16]float64{
	dns.TypeANY:    179.0, // Highest amplification
	dns.TypeDNSKEY: 120.0,
	dns.TypeRRSIG:  90.0,
	dns.TypeTXT:    73.0,
	dns.TypeMX:     51.0,
	dns.TypeSOA:    47.0,
	dns.TypeNS:     37.0,
	dns.TypeSRV:    30.0,
	dns.TypeAAAA:   23.0,
	dns.TypeA:      8.0,
	dns.TypePTR:    10.0,
	dns.TypeCNAME:  8.0,
}

// HighRiskQueryTypes are query types commonly used in amplification attacks
var HighRiskQueryTypes = map[uint16]bool{
	dns.TypeANY:    true,
	dns.TypeDNSKEY: true,
	dns.TypeRRSIG:  true,
	dns.TypeTXT:    true,
	dns.TypeMX:     true,
	dns.TypeSOA:    true,
}

// ExtractFeatures extracts relevant features from a DNS query
func ExtractFeatures(req *dns.Msg, protocol string) *QueryFeatures {
	if req == nil || len(req.Question) == 0 {
		return nil
	}

	question := req.Question[0]
	features := &QueryFeatures{
		QueryType:   question.Qtype,
		QueryClass:  question.Qclass,
		QueryName:   question.Name,
		RequestSize: req.Len(),
		Protocol:    protocol,
		Timestamp:   time.Now(),
	}

	// Extract EDNS information
	if opt := req.IsEdns0(); opt != nil {
		features.HasEDNS = true
		features.EDNSBufferSize = opt.UDPSize()
		features.IsDNSSEC = opt.Do()
	}

	// Calculate amplification potential
	if factor, exists := AmplificationFactors[question.Qtype]; exists {
		features.AmplificationPotential = factor
	} else {
		features.AmplificationPotential = 5.0 // Default conservative estimate
	}

	// Check if high-risk query type
	features.IsHighRiskType = HighRiskQueryTypes[question.Qtype]

	return features
}

// CalculateAnomalyScore calculates an anomaly score based on features
// Higher score indicates more suspicious behavior
func (f *QueryFeatures) CalculateAnomalyScore() float64 {
	if f == nil {
		return 0.0
	}

	score := 0.0

	// High amplification potential increases score
	if f.AmplificationPotential > 50.0 {
		score += 40.0
	} else if f.AmplificationPotential > 20.0 {
		score += 20.0
	} else if f.AmplificationPotential > 10.0 {
		score += 10.0
	}

	// High-risk query types
	if f.IsHighRiskType {
		score += 25.0
	}

	// Large EDNS buffer size (attackers often set this high)
	if f.HasEDNS {
		if f.EDNSBufferSize > 4096 {
			score += 15.0
		} else if f.EDNSBufferSize > 2048 {
			score += 5.0
		}
	}

	// UDP queries have higher abuse potential than TCP
	if f.Protocol == "udp" {
		score += 10.0
	}

	return score
}
