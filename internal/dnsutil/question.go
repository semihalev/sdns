package dnsutil

import (
	"strings"

	"github.com/miekg/dns"
)

// FormatQuestion renders a question for log lines: the lowercased qname,
// class, and type, space-separated ("example.com. IN A"). Every middleware
// used to carry its own copy of this; they all funnel here now.
func FormatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}
