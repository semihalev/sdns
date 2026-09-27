package dnsutil

import (
	"strings"

	"github.com/miekg/dns"
)

// DeclinedQtype reports whether qtype is one this server answers by its own
// policy, never by resolving it: ANY (NOTIMP), a zone transfer (REFUSED),
// and NXNAME, a meta-type RFC 9824 §3.5 says must not be forwarded or
// resolved (FORMERR).
func DeclinedQtype(qtype uint16) bool {
	switch qtype {
	case dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeNXNAME:
		return true
	}
	return false
}

// DeclinedClass reports whether qclass is one this server does not resolve:
// every class but IN. CHAOS names this server answers for itself are the
// chaos middleware's, answered before any resolution.
func DeclinedClass(qclass uint16) bool {
	return qclass != dns.ClassINET
}

// FormatQuestion renders a question for log lines: the lowercased qname,
// class, and type, space-separated ("example.com. IN A"). Every middleware
// used to carry its own copy of this; they all funnel here now.
func FormatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}
