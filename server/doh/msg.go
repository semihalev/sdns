package doh

import (
	"strings"

	"github.com/miekg/dns"
)

// Question struct
type Question struct {
	Name   string `json:"name"`
	Qtype  uint16 `json:"type"`
	Qclass uint16 `json:"-"`
}

// RR struct
type RR struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// Msg struct
type Msg struct {
	Status    int
	TC        bool
	RD        bool
	RA        bool
	AD        bool
	CD        bool
	Question  []Question
	Answer    []RR `json:",omitempty"`
	Authority []RR `json:",omitempty"`
}

// NewMsg function
func NewMsg(m *dns.Msg) *Msg {
	if m == nil {
		return nil
	}

	msg := &Msg{
		Status:    m.Rcode,
		TC:        m.Truncated,
		RD:        m.RecursionDesired,
		RA:        m.RecursionAvailable,
		AD:        m.AuthenticatedData,
		CD:        m.CheckingDisabled,
		Question:  make([]Question, len(m.Question)),
		Answer:    make([]RR, len(m.Answer)),
		Authority: make([]RR, len(m.Ns)),
	}

	for i, q := range m.Question {
		msg.Question[i] = Question(q)
	}

	for i, a := range m.Answer {
		msg.Answer[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	for i, a := range m.Ns {
		msg.Authority[i] = RR{
			Name: a.Header().Name,
			Type: a.Header().Rrtype,
			TTL:  a.Header().Ttl,
			Data: strings.TrimPrefix(a.String(), a.Header().String()),
		}
	}

	return msg
}
