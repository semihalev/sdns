package rpz

import "net/netip"

// Trigger labels for metrics and logs.
const (
	TriggerQNAME      = "qname"
	TriggerClientIP   = "client-ip"
	TriggerResponseIP = "ip"
)

// triggerRank orders trigger types within one zone (precedence rule 2):
// CLIENT-IP > QNAME > IP.
func triggerRank(trigger string) int {
	switch trigger {
	case TriggerClientIP:
		return 3
	case TriggerQNAME:
		return 2
	case TriggerResponseIP:
		return 1
	}
	return 0
}

// ZoneMatch is one zone's best match for a query. Trigger and PrefixBits
// carry the rank information a later merge (or a log line) needs.
type ZoneMatch struct {
	ZoneIdx    int
	Zone       *Zone
	Rule       *Rule
	Trigger    string
	Wildcard   bool
	PrefixBits int
}

// HasClientIP reports whether any zone carries CLIENT-IP rules, so a
// caller can skip canonicalizing the client address entirely on a
// qname-only configuration.
func (s *Store) HasClientIP() bool {
	if s == nil {
		return false
	}
	for _, z := range s.Zones {
		if z.clientIP4 != nil || z.clientIP6 != nil {
			return true
		}
	}
	return false
}

// Match walks the zones in configuration order and returns the first
// enabled zone's match as the winner, together with the matches of any
// disabled zones met on the way there. Zones past the winner are never
// probed: precedence rule 1 says they cannot win, and the winner-bounded
// counting semantic (design §5.5) says they are not counted either, so
// not probing them is both correct and the cheap path.
//
// Within a zone, CLIENT-IP outranks QNAME (rule 2), and among CLIENT-IP
// prefixes the longest wins (rule 4), equal-length distinct prefixes
// cannot both contain one address, so the client-side tie-break is
// vacuous by construction. client is the query's source address in
// canonical 128-bit form (CanonicalClient), or the zero Addr when no
// zone carries CLIENT-IP rules.
//
// canon and offs are the query name in the canonical-labels form
// dnsname.AppendCanonicalLabels produces: canon is the lowercase
// presentation with the trailing dot, offs[i] the start of label i, n the
// label count. Both live on the caller's stack; every probe here indexes a
// map as m[string(bytes)], which Go performs without constructing the
// string, with the prefix masking being value math, the reason a
// non-matching query allocates nothing.
//
// Within a zone the draft's rule 3 falls out of the walk order: the exact
// probe first, then wildcard suffixes from the longest down (stripping one
// leading label per step), so the first wildcard hit is the one with the
// most labels. A wildcard matches proper subdomains only, the walk starts
// at offs[1], so a name never probes its own spelling as a suffix.
//
// observed is nil unless a disabled zone matched, which keeps the miss
// path and the ordinary single-zone hit allocation-free.
func (s *Store) Match(canon []byte, offs []int, n int, client netip.Addr) (winner ZoneMatch, observed []ZoneMatch) {
	if s == nil {
		return
	}
	for idx, z := range s.Zones {
		m := z.match(canon, offs, n, client)
		if m.Rule == nil {
			continue
		}
		m.ZoneIdx, m.Zone = idx, z
		if z.Disabled() {
			observed = append(observed, m)
			continue
		}
		winner = m
		return
	}
	return
}

// match applies the within-zone trigger precedence: CLIENT-IP first. The
// client's family selects its table, the other family's rules do not
// exist for it.
func (z *Zone) match(canon []byte, offs []int, n int, client netip.Addr) ZoneMatch {
	if client.IsValid() {
		table := z.clientIP6
		if client.Is4() {
			table = z.clientIP4
		}
		if rule, bits := table.lookup(client); rule != nil {
			return ZoneMatch{Rule: rule, Trigger: TriggerClientIP, PrefixBits: bits}
		}
	}
	if rule, wild := z.matchQNAME(canon, offs, n); rule != nil {
		return ZoneMatch{Rule: rule, Trigger: TriggerQNAME, Wildcard: wild}
	}
	return ZoneMatch{}
}

func (z *Zone) matchQNAME(canon []byte, offs []int, n int) (rule *Rule, wildcard bool) {
	if len(z.exact) > 0 {
		if r, ok := z.exact[string(canon)]; ok {
			return r, false
		}
	}
	if len(z.wild) > 0 {
		for i := 1; i < n; i++ {
			if r, ok := z.wild[string(canon[offs[i]:])]; ok {
				return r, true
			}
		}
	}
	if z.matchAll != nil {
		return z.matchAll, true
	}
	return nil, false
}

// Effective resolves the zone's override against the rule's own action:
// the action the zone would take on this match. OverrideCNAME reports
// ActionLocalData, the synthesis layer reads Zone.CNAMETarget for the
// record. OverrideDisabled keeps the rule's action, because a disabled
// zone's log line reports what would otherwise have happened.
func (m ZoneMatch) Effective() Action {
	switch m.Zone.Policy {
	case OverridePassthru:
		return ActionPassthru
	case OverrideNXDOMAIN:
		return ActionNXDOMAIN
	case OverrideNODATA:
		return ActionNODATA
	case OverrideDrop:
		return ActionDrop
	case OverrideTCPOnly:
		return ActionTCPOnly
	case OverrideCNAME:
		return ActionLocalData
	}
	return m.Rule.Action
}
