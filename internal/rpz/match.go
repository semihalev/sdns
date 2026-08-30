package rpz

// ZoneMatch is one zone's best QNAME match for a query.
type ZoneMatch struct {
	ZoneIdx  int
	Zone     *Zone
	Rule     *Rule
	Wildcard bool
}

// MatchQNAME walks the zones in configuration order and returns the first
// enabled zone's match as the winner, together with the matches of any
// disabled zones met on the way there. Zones past the winner are never
// probed: precedence rule 1 says they cannot win, and the winner-bounded
// counting semantic (design §5.5) says they are not counted either — so
// not probing them is both correct and the cheap path.
//
// canon and offs are the query name in the canonical-labels form
// dnsname.AppendCanonicalLabels produces: canon is the lowercase
// presentation with the trailing dot, offs[i] the start of label i, n the
// label count. Both live on the caller's stack; every probe here indexes a
// map as m[string(bytes)], which Go performs without constructing the
// string — the reason a non-matching query allocates nothing.
//
// Within a zone the draft's rule 3 falls out of the walk order: the exact
// probe first, then wildcard suffixes from the longest down (stripping one
// leading label per step), so the first wildcard hit is the one with the
// most labels. A wildcard matches proper subdomains only — the walk starts
// at offs[1], so a name never probes its own spelling as a suffix.
//
// observed is nil unless a disabled zone matched, which keeps the miss
// path and the ordinary single-zone hit allocation-free.
func (s *Store) MatchQNAME(canon []byte, offs []int, n int) (winner ZoneMatch, observed []ZoneMatch) {
	if s == nil {
		return
	}
	for idx, z := range s.Zones {
		rule, wild := z.matchQNAME(canon, offs, n)
		if rule == nil {
			continue
		}
		m := ZoneMatch{ZoneIdx: idx, Zone: z, Rule: rule, Wildcard: wild}
		if z.Disabled() {
			observed = append(observed, m)
			continue
		}
		winner = m
		return
	}
	return
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
// ActionLocalData — the synthesis layer reads Zone.CNAMETarget for the
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
