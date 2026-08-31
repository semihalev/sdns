package rpz

import (
	"net/netip"

	"github.com/miekg/dns"
)

// HasResponseIP reports whether any zone carries IP (response) trigger
// rules — the switch that turns the whole sidecar machinery on.
func (s *Store) HasResponseIP() bool {
	if s == nil {
		return false
	}
	for _, z := range s.Zones {
		if z.hasResponseTriggers() {
			return true
		}
	}
	return false
}

// ResponseTriggerBefore reports whether any zone ahead of idx carries
// response triggers — §5.4's hold decision: a query-time match in zone
// idx is final immediately iff this is false. A same-zone response
// trigger never displaces a query-time match (rule 2: CLIENT-IP > QNAME
// > IP), which is why the scan is strictly before idx.
func (s *Store) ResponseTriggerBefore(idx int) bool {
	if s == nil {
		return false
	}
	for i := 0; i < idx && i < len(s.Zones); i++ {
		if s.Zones[i].hasResponseTriggers() {
			return true
		}
	}
	return false
}

// ResponseMatch is one zone's best IP-trigger match over a response's
// answer addresses, carried value-only: zone index, action, rank key
// (prefix length and matched address, both canonical 128-bit — IPv4
// mapped, +96), and — for Local Data — deep copies of the rule's
// records. Nothing here points into the policy store: a stamped
// candidate must not pin the generation it was computed under (§5.6).
type ResponseMatch struct {
	ZoneIdx    int
	Action     Action
	PrefixBits int
	Addr       netip.Addr
	Local      []dns.RR
}

// betterThan is precedence rule 4: the longer prefix wins; on equal
// length, the numerically smaller 128-bit address.
func (m ResponseMatch) betterThan(o ResponseMatch) bool {
	if m.PrefixBits != o.PrefixBits {
		return m.PrefixBits > o.PrefixBits
	}
	return m.Addr.Compare(o.Addr) < 0
}

// ResponseMatches is the entry-local evaluation result the sidecar
// carries: the generation it was computed under and one best match per
// matching zone, ascending zone index, over ALL zones uniformly —
// enabled, disabled, and shadow alike. An empty List is the explicit
// "evaluated, nothing matched"; the winner is a property of the query
// and is computed at the serve-time merge, never here (§5.6 item 2).
type ResponseMatches struct {
	Gen  uint64
	List []ResponseMatch
}

// EvaluateResponseList computes the per-zone best IP-trigger matches
// over a response's answer records, ascending by zone index. nil means
// nothing matched (or no zone carries response triggers — callers that
// need the distinction ask HasResponseIP), and nothing was allocated to
// say so. Local Data records are deep-copied at this boundary: a
// slice-header copy would keep the old generation's allocations
// reachable through every stamped entry.
func (s *Store) EvaluateResponseList(answers []dns.RR) []ResponseMatch {
	var list []ResponseMatch
	for idx, z := range s.Zones {
		if !z.hasResponseTriggers() {
			continue
		}
		best, found := z.matchResponse(answers)
		if !found {
			continue
		}
		best.ZoneIdx = idx
		list = append(list, best)
	}
	return list
}

// EvaluateResponse is EvaluateResponseList boxed with the generation:
// nil when no zone carries response triggers, an empty non-nil result
// for the explicit none.
func (s *Store) EvaluateResponse(answers []dns.RR) *ResponseMatches {
	if !s.HasResponseIP() {
		return nil
	}
	return &ResponseMatches{Gen: s.Gen, List: s.EvaluateResponseList(answers)}
}

// matchResponse probes every answer address against the zone's family
// tables and keeps the rule-4 best. The record's own type picks the
// family: an A record is judged by the v4 table only, an AAAA by the v6
// table only.
func (z *Zone) matchResponse(answers []dns.RR) (ResponseMatch, bool) {
	var best ResponseMatch
	found := false
	for _, rr := range answers {
		var addr netip.Addr
		var table *ipLPM
		switch a := rr.(type) {
		case *dns.A:
			ip, ok := netip.AddrFromSlice(a.A)
			if !ok {
				continue
			}
			addr, table = ip.Unmap(), z.responseIP4
		case *dns.AAAA:
			ip, ok := netip.AddrFromSlice(a.AAAA)
			if !ok {
				continue
			}
			addr, table = ip, z.responseIP6
		default:
			continue
		}
		rule, bits := table.lookup(addr)
		if rule == nil {
			continue
		}
		m := ResponseMatch{
			Action:     rule.Action,
			PrefixBits: canonicalBits(addr, bits),
			Addr:       canonicalAddr(addr),
		}
		if found && !m.betterThan(best) {
			continue
		}
		if rule.Action == ActionLocalData {
			m.Local = copyRecords(rule.Local)
		}
		best, found = m, true
	}
	return best, found
}

// canonicalBits maps a v4 prefix length into the shared 128-bit space
// (+96), so rule 4 compares v4 and v6 matches on one scale.
func canonicalBits(addr netip.Addr, bits int) int {
	if addr.Is4() {
		return bits + 96
	}
	return bits
}

// canonicalAddr is the matched address as a 128-bit value (v4 mapped).
func canonicalAddr(addr netip.Addr) netip.Addr {
	return netip.AddrFrom16(addr.As16())
}

// copyRecords clones each record into fresh backing (dns.Copy): the
// candidate owns its data outright and the old policy store stays
// collectible after a reload (§5.6's deep-copy clause).
func copyRecords(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = dns.Copy(rr)
	}
	return out
}

// FoldResponseLists merges the per-segment match lists of one composed
// chase, deduplicating per zone by the rank key: two segments matching
// the same zone collapse to that zone's single rule-4 best, so one query
// counts a zone exactly once (§5.6 item 4). Inputs and output are
// ascending by zone index.
func FoldResponseLists(lists ...[]ResponseMatch) []ResponseMatch {
	var out []ResponseMatch
	for _, list := range lists {
		for _, m := range list {
			pos := -1
			for i := range out {
				if out[i].ZoneIdx == m.ZoneIdx {
					pos = i
					break
				}
			}
			if pos == -1 {
				out = append(out, m)
				continue
			}
			if m.betterThan(out[pos]) {
				out[pos] = m
			}
		}
	}
	sortResponseMatches(out)
	return out
}

func sortResponseMatches(list []ResponseMatch) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].ZoneIdx < list[j-1].ZoneIdx; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// asZoneMatch lifts a response candidate into the ZoneMatch shape the
// action and counting layers already speak. The synthetic Rule carries
// the candidate's own copied data, never a pointer into any store.
func (m ResponseMatch) asZoneMatch(s *Store) ZoneMatch {
	return ZoneMatch{
		ZoneIdx:    m.ZoneIdx,
		Zone:       s.Zones[m.ZoneIdx],
		Rule:       &Rule{Action: m.Action, Local: m.Local},
		Trigger:    TriggerResponseIP,
		PrefixBits: m.PrefixBits,
	}
}

// Merge is the serve-time selection (§5.4/§5.6 item 3): the held
// query-time candidates meet the response-trigger candidates, and the
// ordinary precedence rules pick one decision per zone (rule 2), then
// the first enabled zone with a decision wins (rule 1, over enabled
// zones only — a disabled zone observes without consuming, §5.5).
//
// held is the enabled-zone query match Match returned (zero when none);
// heldObserved the disabled-zone query matches it collected; resp the
// sidecar's (or a fresh evaluation's) uniform per-zone response list.
// observed carries every matched zone before the winner — and every
// matched zone at all when no enabled zone decides — each with the
// decision it would have taken; winner-bounded counting reads it
// directly.
func (s *Store) Merge(held ZoneMatch, heldObserved []ZoneMatch, resp []ResponseMatch) (winner ZoneMatch, observed []ZoneMatch) {
	// One decision per zone: index the query-time candidates, then walk
	// zones ascending and let rule 2 pick between a zone's query match
	// and its response match.
	ri := 0
	for idx, z := range s.Zones {
		var decision ZoneMatch
		if held.Zone != nil && held.ZoneIdx == idx {
			decision = held
		}
		for _, o := range heldObserved {
			if o.ZoneIdx == idx {
				decision = o
			}
		}
		for ri < len(resp) && resp[ri].ZoneIdx < idx {
			ri++
		}
		if ri < len(resp) && resp[ri].ZoneIdx == idx {
			if decision.Zone == nil || triggerRank(TriggerResponseIP) > triggerRank(decision.Trigger) {
				decision = resp[ri].asZoneMatch(s)
			}
		}
		if decision.Zone == nil {
			continue
		}
		if z.Disabled() {
			observed = append(observed, decision)
			continue
		}
		winner = decision
		return
	}
	return
}
