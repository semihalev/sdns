package mldefense

import (
	"testing"

	"github.com/miekg/dns"
)

func TestExtractFeatures(t *testing.T) {
	tests := []struct {
		name            string
		qname           string
		qtype           uint16
		protocol        string
		ednsBufferSize  uint16
		wantHighRisk    bool
		minAmpFactor    float64
	}{
		{
			name:         "A record query",
			qname:        "example.com.",
			qtype:        dns.TypeA,
			protocol:     "udp",
			wantHighRisk: false,
			minAmpFactor: 5.0,
		},
		{
			name:         "ANY query - high risk",
			qname:        "example.com.",
			qtype:        dns.TypeANY,
			protocol:     "udp",
			wantHighRisk: true,
			minAmpFactor: 100.0,
		},
		{
			name:         "TXT query - high risk",
			qname:        "example.com.",
			qtype:        dns.TypeTXT,
			protocol:     "udp",
			wantHighRisk: true,
			minAmpFactor: 50.0,
		},
		{
			name:         "DNSKEY query - high risk",
			qname:        "example.com.",
			qtype:        dns.TypeDNSKEY,
			protocol:     "udp",
			wantHighRisk: true,
			minAmpFactor: 100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion(tt.qname, tt.qtype)

			if tt.ednsBufferSize > 0 {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(tt.ednsBufferSize)
				msg.Extra = append(msg.Extra, opt)
			}

			features := ExtractFeatures(msg, tt.protocol)

			if features == nil {
				t.Fatal("ExtractFeatures returned nil")
			}

			if features.QueryType != tt.qtype {
				t.Errorf("QueryType = %v, want %v", features.QueryType, tt.qtype)
			}

			if features.IsHighRiskType != tt.wantHighRisk {
				t.Errorf("IsHighRiskType = %v, want %v", features.IsHighRiskType, tt.wantHighRisk)
			}

			if features.AmplificationPotential < tt.minAmpFactor {
				t.Errorf("AmplificationPotential = %v, want >= %v", features.AmplificationPotential, tt.minAmpFactor)
			}

			if features.Protocol != tt.protocol {
				t.Errorf("Protocol = %v, want %v", features.Protocol, tt.protocol)
			}
		})
	}
}

func TestCalculateAnomalyScore(t *testing.T) {
	tests := []struct {
		name       string
		features   *QueryFeatures
		minScore   float64
		maxScore   float64
	}{
		{
			name: "Normal A query - low score",
			features: &QueryFeatures{
				QueryType:              dns.TypeA,
				AmplificationPotential: 8.0,
				IsHighRiskType:         false,
				Protocol:               "tcp",
				HasEDNS:                false,
			},
			minScore: 0,
			maxScore: 20,
		},
		{
			name: "ANY query over UDP with large EDNS - high score",
			features: &QueryFeatures{
				QueryType:              dns.TypeANY,
				AmplificationPotential: 179.0,
				IsHighRiskType:         true,
				Protocol:               "udp",
				HasEDNS:                true,
				EDNSBufferSize:         4096,
			},
			minScore: 80,
			maxScore: 100,
		},
		{
			name: "TXT query over UDP - medium-high score",
			features: &QueryFeatures{
				QueryType:              dns.TypeTXT,
				AmplificationPotential: 73.0,
				IsHighRiskType:         true,
				Protocol:               "udp",
				HasEDNS:                true,
				EDNSBufferSize:         2048,
			},
			minScore: 60,
			maxScore: 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.features.CalculateAnomalyScore()

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("CalculateAnomalyScore() = %v, want between %v and %v",
					score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestExtractFeaturesNilOrEmpty(t *testing.T) {
	// Test nil message
	features := ExtractFeatures(nil, "udp")
	if features != nil {
		t.Error("Expected nil for nil message")
	}

	// Test empty question section
	msg := new(dns.Msg)
	features = ExtractFeatures(msg, "udp")
	if features != nil {
		t.Error("Expected nil for message with no questions")
	}
}

func TestAmplificationFactors(t *testing.T) {
	// Verify that high-risk types have high amplification factors
	highRiskTypes := []uint16{dns.TypeANY, dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeTXT}

	for _, qtype := range highRiskTypes {
		factor, exists := AmplificationFactors[qtype]
		if !exists {
			t.Errorf("Missing amplification factor for high-risk type %v", qtype)
			continue
		}

		if factor < 50.0 {
			t.Errorf("Amplification factor for %v is %v, expected >= 50", qtype, factor)
		}

		if !HighRiskQueryTypes[qtype] {
			t.Errorf("Type %v not marked as high risk", qtype)
		}
	}
}
