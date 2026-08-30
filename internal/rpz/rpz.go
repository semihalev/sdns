// Package rpz is the policy engine for DNS Response Policy Zones
// (draft-vixie-dnsop-dns-rpz): parsing policy zones into an immutable
// compiled store, and matching query names against it under the draft's
// precedence rules.
//
// The package deliberately knows nothing about middleware, config, or
// serving: the middleware imports it for matching, and the config
// validator imports it so `sdns -t` judges a policy file with exactly the
// parser the runtime uses. Design and invariants: docs/rpz-design.md.
package rpz

import (
	"github.com/miekg/dns"
)

// Action is what a matched rule asks for. The zero value means "no rule".
type Action uint8

// The policy actions of the draft, in no particular order. LocalData
// carries records on the rule; the others are codes.
const (
	ActionNone Action = iota
	ActionNXDOMAIN
	ActionNODATA
	ActionPassthru
	ActionDrop
	ActionTCPOnly
	ActionLocalData
)

// String returns the metric/log label for the action.
func (a Action) String() string {
	switch a {
	case ActionNXDOMAIN:
		return "nxdomain"
	case ActionNODATA:
		return "nodata"
	case ActionPassthru:
		return "passthru"
	case ActionDrop:
		return "drop"
	case ActionTCPOnly:
		return "tcp-only"
	case ActionLocalData:
		return "local-data"
	}
	return "none"
}

// Override is a zone-wide replacement for whatever the zone's rules say,
// set by the operator in the config rather than by the feed.
type Override uint8

// The override values of the draft's §6 that phase 1 carries. Given uses
// the rule's own action; Disabled observes without consuming the match.
const (
	OverrideGiven Override = iota
	OverridePassthru
	OverrideNXDOMAIN
	OverrideNODATA
	OverrideDrop
	OverrideTCPOnly
	OverrideCNAME
	OverrideDisabled
)

// ParseOverride maps the config spelling to an Override. ok is false for a
// spelling the config validator should have refused.
func ParseOverride(s string) (Override, bool) {
	switch s {
	case "", "given":
		return OverrideGiven, true
	case "passthru":
		return OverridePassthru, true
	case "nxdomain":
		return OverrideNXDOMAIN, true
	case "nodata":
		return OverrideNODATA, true
	case "drop":
		return OverrideDrop, true
	case "tcp-only":
		return OverrideTCPOnly, true
	case "cname":
		return OverrideCNAME, true
	case "disabled":
		return OverrideDisabled, true
	}
	return OverrideGiven, false
}

// Rule is one compiled policy rule. Local holds the rule's records only
// for ActionLocalData; their owner names are as parsed and are rewritten
// to the client's qname at synthesis (the trigger owner never reaches a
// response).
type Rule struct {
	Action Action
	Local  []dns.RR
}

// Zone is one compiled policy zone. The maps are keyed in canonical form —
// dns.CanonicalName's spelling, lowercase with the trailing dot — which is
// the same spelling dnsname.AppendCanonicalLabels builds on the stack at
// query time, so lookups index the maps without constructing a string.
type Zone struct {
	// Name labels the zone in metrics, logs, and the EDE text.
	Name string
	// Origin is the policy zone's apex, canonical.
	Origin string
	// SOA is the apex SOA, served in the additional section of every
	// rewritten answer to identify the policy source (draft §6).
	SOA *dns.SOA
	// Policy is the operator's zone-wide override.
	Policy Override
	// CNAMETarget is the OverrideCNAME target, canonical FQDN.
	CNAMETarget string

	exact map[string]*Rule // canonical qname -> rule
	wild  map[string]*Rule // canonical suffix (from "*.suffix") -> rule
	// matchAll is the rule of a bare "*" owner: any qname, subdomain
	// walk included. Rare, so it is a field rather than a map probe.
	matchAll *Rule

	// Rules counts the compiled rules; Skipped counts what the load
	// stepped over, by reason — both feed the load-time gauges and the
	// `sdns -t` report.
	Rules   int
	Skipped map[string]int
}

// Disabled reports whether the zone observes without consuming a match.
func (z *Zone) Disabled() bool { return z.Policy == OverrideDisabled }

// Store is an immutable compiled policy generation: every reload builds a
// new Store and swaps it in whole. Zones are in configuration order, which
// is evaluation order (precedence rule 1).
type Store struct {
	Zones []*Zone
}

// Empty reports whether no zone carries any rule — the whole engine is
// then skipped per query at the cost of one nil/len check.
func (s *Store) Empty() bool {
	if s == nil {
		return true
	}
	for _, z := range s.Zones {
		if z.Rules > 0 {
			return false
		}
	}
	return true
}
