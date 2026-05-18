package dnsutil

import (
	"strings"

	"github.com/miekg/dns"
)

// ExtractRRSet returns every RR in `in` whose owner equals `name`
// (case-insensitive; pass "" to skip the name match) and whose Rrtype
// is one of `t`. The returned slice is a fresh copy and shares no
// storage with the input.
func ExtractRRSet(in []dns.RR, name string, t ...uint16) []dns.RR {
	if len(in) == 0 {
		return nil
	}

	// Pre-allocate with reasonable capacity
	out := make([]dns.RR, 0, min(len(in)/2, 10))

	// Optimize for common single-type queries
	if len(t) == 1 {
		targetType := t[0]
		for _, r := range in {
			if r.Header().Rrtype == targetType {
				if name != "" && !strings.EqualFold(name, r.Header().Name) {
					continue
				}
				out = append(out, r)
			}
		}
		return out
	}

	// For multiple types, use map
	template := make(map[uint16]struct{}, len(t))
	for _, typ := range t {
		template[typ] = struct{}{}
	}
	for _, r := range in {
		if _, ok := template[r.Header().Rrtype]; ok {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

// FilterRRsToZone returns the subset of rrs whose owner is in zone.
// For NSEC records the NextDomain field is also checked: a legitimate
// NSEC's NextDomain is always another owner in the same zone (the last
// NSEC wraps back to the zone apex), so an in-zone owner paired with an
// out-of-zone NextDomain is either a broken zone or an attacker-crafted
// record and must be discarded. Without this the structural coverage
// helpers would accept a forged NSEC whose NextDomain is picked to
// canonically straddle the qname.
func FilterRRsToZone(rrs []dns.RR, zone string) []dns.RR {
	z := strings.ToLower(dns.Fqdn(zone))
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		name := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if !NameInZone(name, z) {
			continue
		}
		if nsec, ok := rr.(*dns.NSEC); ok {
			next := strings.ToLower(dns.Fqdn(nsec.NextDomain))
			if !NameInZone(next, z) {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}

// NameInZone reports whether name is the zone apex or a descendant of
// zone. Both arguments are expected to be lowercase FQDNs.
func NameInZone(name, zone string) bool {
	if zone == "." || zone == "" {
		return true
	}
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}

// DnameTarget returns the synthesized CNAME target for the question
// given a DNAME in msg.Answer, or "" if no redirect applies. Per RFC
// 6672 §2.3 the DNAME owner itself is *not* redirected, and only names
// strictly below the owner are substituted.
//
// dns.CompareDomainName counts matching trailing labels regardless of
// whether one name is actually an ancestor of the other, so a DNAME at
// sub.example.com. and a query for other.example.com. both share the
// two-label suffix example.com. — but sub.example.com. is a *sibling*
// of other.example.com., not an ancestor, and must not rewrite the
// query. Require the shared count to exactly equal the DNAME owner's
// label count (i.e. owner is a proper suffix sequence of qname), and
// that qname has strictly more labels (rules out exact match), before
// synthesizing.
func DnameTarget(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]

	for _, r := range msg.Answer {
		dname, ok := r.(*dns.DNAME)
		if !ok {
			continue
		}
		ownerLabels := dns.CountLabel(dname.Header().Name)
		qLabels := dns.CountLabel(q.Name)
		if ownerLabels == 0 || qLabels <= ownerLabels {
			// Exact-owner (per RFC 6672 §2.3) or the owner has more
			// labels than qname — neither can apply.
			return ""
		}
		if dns.CompareDomainName(dname.Header().Name, q.Name) != ownerLabels {
			// Shared trailing-label count is less than the DNAME
			// owner's full name, meaning the owner is a cousin or
			// unrelated sibling, not an ancestor of qname.
			return ""
		}
		prev, _ := dns.PrevLabel(q.Name, ownerLabels)
		return q.Name[:prev] + dname.Target
	}

	return ""
}
