package rpz

import (
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const responseIPZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
; response-ip rules: a broad block and a narrow exception-shaped rule
24.0.2.0.192.rpz-ip.rpz.test.   IN CNAME .
32.9.2.0.192.rpz-ip.rpz.test.   IN CNAME *.
48.zz.db8.2001.rpz-ip.rpz.test. IN CNAME rpz-drop.
; local data on a response trigger
32.7.2.0.192.rpz-ip.rpz.test.   IN A 203.0.113.53
`

func loadResponseIPZone(t *testing.T) *Zone {
	t.Helper()
	z, err := LoadZone("rip", strings.NewReader(responseIPZone), "rip.zone", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	if z.RulesResponseIP != 4 {
		t.Fatalf("RulesResponseIP = %d, want 4 (skips: %v)", z.RulesResponseIP, z.Skipped)
	}
	return z
}

func answerA(ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: "x.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   netip.MustParseAddr(ip).AsSlice(),
	}
}

func answerAAAA(ip string) dns.RR {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "x.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: netip.MustParseAddr(ip).AsSlice(),
	}
}

// TestEvaluateResponseBasics pins the evaluation shell: nil without any
// response rules, explicit none with them, matches carried with their
// canonical rank keys and the store's generation.
func TestEvaluateResponseBasics(t *testing.T) {
	empty := &Store{Zones: []*Zone{{Name: "plain"}}, Gen: 7}
	if empty.EvaluateResponse([]dns.RR{answerA("192.0.2.9")}) != nil {
		t.Fatal("a store without response rules evaluated something")
	}

	s := &Store{Zones: []*Zone{loadResponseIPZone(t)}, Gen: 9}
	none := s.EvaluateResponse([]dns.RR{answerA("198.51.100.1")})
	if none == nil || len(none.List) != 0 || none.Gen != 9 {
		t.Fatalf("explicit none broken: %+v", none)
	}

	rm := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")})
	if len(rm.List) != 1 || rm.Gen != 9 {
		t.Fatalf("match list: %+v", rm)
	}
	m := rm.List[0]
	if m.Action != ActionNXDOMAIN || m.PrefixBits != 24+96 {
		t.Fatalf("match: %+v", m)
	}
}

// TestEvaluateResponseRule4 pins precedence rule 4 across the answer's
// addresses: the longest prefix wins whatever record order says, and on
// equal length the numerically smaller 128-bit address does.
func TestEvaluateResponseRule4(t *testing.T) {
	s := &Store{Zones: []*Zone{loadResponseIPZone(t)}}

	// /32 outranks /24 even listed second.
	rm := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1"), answerA("192.0.2.9")})
	if len(rm.List) != 1 || rm.List[0].Action != ActionNODATA || rm.List[0].PrefixBits != 32+96 {
		t.Fatalf("longest prefix lost: %+v", rm.List)
	}

	// Two /32 matches: 192.0.2.7 (local data) < 192.0.2.9 numerically.
	rm = s.EvaluateResponse([]dns.RR{answerA("192.0.2.9"), answerA("192.0.2.7")})
	if len(rm.List) != 1 || rm.List[0].Action != ActionLocalData {
		t.Fatalf("smaller address lost the tie: %+v", rm.List)
	}
}

// TestEvaluateResponseFamiliesStaySeparate pins the family split on the
// response side: an A record is never judged by a v6 rule.
func TestEvaluateResponseFamiliesStaySeparate(t *testing.T) {
	z, err := LoadZone("fam", strings.NewReader(`
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
0.zz.rpz-ip.rpz.test. IN CNAME .
`), "fam.zone", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Zones: []*Zone{z}}

	if rm := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")}); len(rm.List) != 0 {
		t.Fatal("a v6 ::/0 rule judged an A record")
	}
	if rm := s.EvaluateResponse([]dns.RR{answerAAAA("2001:db8::1")}); len(rm.List) != 1 {
		t.Fatal("the v6 rule missed an AAAA record")
	}
}

// TestEvaluateResponseListsEveryZoneUniformly pins §5.6 item 2: the list
// carries every matching zone — disabled included — because the winner
// is the query's property, not the entry's.
func TestEvaluateResponseListsEveryZoneUniformly(t *testing.T) {
	disabled := loadResponseIPZone(t)
	disabled.Policy = OverrideDisabled
	enabled := loadResponseIPZone(t)
	s := &Store{Zones: []*Zone{disabled, enabled}}

	rm := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")})
	if len(rm.List) != 2 || rm.List[0].ZoneIdx != 0 || rm.List[1].ZoneIdx != 1 {
		t.Fatalf("uniform list broken: %+v", rm.List)
	}
}

// TestEvaluateResponseDeepCopiesLocalData pins the §5.6 deep-copy
// clause: mutating a candidate's record must not reach the store's rule
// — a header copy would satisfy the type and pin the old generation.
func TestEvaluateResponseDeepCopiesLocalData(t *testing.T) {
	z := loadResponseIPZone(t)
	s := &Store{Zones: []*Zone{z}}

	rm := s.EvaluateResponse([]dns.RR{answerA("192.0.2.7")})
	if len(rm.List) != 1 || rm.List[0].Action != ActionLocalData || len(rm.List[0].Local) != 1 {
		t.Fatalf("local-data match: %+v", rm.List)
	}
	rm.List[0].Local[0].(*dns.A).A[0] = 99

	again := s.EvaluateResponse([]dns.RR{answerA("192.0.2.7")})
	if got := again.List[0].Local[0].(*dns.A).A[0]; got == 99 {
		t.Fatal("a candidate mutation reached the store: the copy is shallow")
	}
}

// mergeFixtureStore builds two zones for the merge tests: zone 0 with
// response rules, zone 1 qname-only.
func mergeFixtureStore(t *testing.T) *Store {
	t.Helper()
	z0 := loadResponseIPZone(t)
	z1, err := LoadZone("names", strings.NewReader(`
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
victim.example.com.rpz.test. IN CNAME *.
`), "names.zone", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	return &Store{Zones: []*Zone{z0, z1}}
}

// TestMergeZoneOrderOutranksTriggerType is the review's P0 shape in
// reverse: a held QNAME match in zone 1 loses to zone 0's response
// match, because rule 1 outranks everything.
func TestMergeZoneOrderOutranksTriggerType(t *testing.T) {
	s := mergeFixtureStore(t)
	held := ZoneMatch{ZoneIdx: 1, Zone: s.Zones[1], Rule: &Rule{Action: ActionNODATA}, Trigger: TriggerQNAME}
	resp := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")})

	winner, observed := s.Merge(held, nil, resp.List)
	if winner.ZoneIdx != 0 || winner.Trigger != TriggerResponseIP || winner.Rule.Action != ActionNXDOMAIN {
		t.Fatalf("zone order lost: %+v", winner)
	}
	if len(observed) != 0 {
		t.Fatalf("nothing stood before the winner: %+v", observed)
	}
}

// TestMergeHeldCandidateSurvivesANoneSidecar is the P0 scenario itself:
// zone 0's response rules do NOT match, zone 1's held QNAME does — the
// merge must answer with the held action, never the stored truth.
func TestMergeHeldCandidateSurvivesANoneSidecar(t *testing.T) {
	s := mergeFixtureStore(t)
	held := ZoneMatch{ZoneIdx: 1, Zone: s.Zones[1], Rule: &Rule{Action: ActionNODATA}, Trigger: TriggerQNAME}

	winner, _ := s.Merge(held, nil, nil)
	if winner.ZoneIdx != 1 || winner.Trigger != TriggerQNAME {
		t.Fatalf("the held candidate was dropped over a none sidecar: %+v", winner)
	}
}

// TestMergeSameZoneTriggerPrecedence pins rule 2 inside the merge: a
// query-time match and a response match in the same zone resolve to the
// query trigger.
func TestMergeSameZoneTriggerPrecedence(t *testing.T) {
	s := mergeFixtureStore(t)
	held := ZoneMatch{ZoneIdx: 0, Zone: s.Zones[0], Rule: &Rule{Action: ActionPassthru}, Trigger: TriggerQNAME}
	resp := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")})

	winner, _ := s.Merge(held, nil, resp.List)
	if winner.Trigger != TriggerQNAME || winner.Rule.Action != ActionPassthru {
		t.Fatalf("rule 2 lost inside a zone: %+v", winner)
	}
}

// TestMergeDisabledObservesWithoutConsuming pins §5.5 in the merge: a
// disabled zone's response match is observed and the next enabled zone
// still wins; with no enabled zone at all, everything matched is
// observed.
func TestMergeDisabledObservesWithoutConsuming(t *testing.T) {
	s := mergeFixtureStore(t)
	s.Zones[0].Policy = OverrideDisabled
	held := ZoneMatch{ZoneIdx: 1, Zone: s.Zones[1], Rule: &Rule{Action: ActionNODATA}, Trigger: TriggerQNAME}
	resp := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")})

	winner, observed := s.Merge(held, nil, resp.List)
	if winner.ZoneIdx != 1 {
		t.Fatalf("a disabled zone consumed the query: %+v", winner)
	}
	if len(observed) != 1 || observed[0].ZoneIdx != 0 || observed[0].Trigger != TriggerResponseIP {
		t.Fatalf("the disabled match was not observed: %+v", observed)
	}

	s.Zones[1].Policy = OverrideDisabled
	winner, observed = s.Merge(held, []ZoneMatch{held}, resp.List)
	if winner.Zone != nil || len(observed) != 2 {
		t.Fatalf("no-enabled-winner case: winner=%+v observed=%+v", winner, observed)
	}
}

// TestMergeIsWinnerBounded pins the counting cut: a zone matching AFTER
// the winner appears in neither the winner nor the observed list.
func TestMergeIsWinnerBounded(t *testing.T) {
	s := mergeFixtureStore(t)
	// Zone 0 wins by response match; zone 1 also "matched" via a held
	// candidate — but zone 1 is past the winner.
	held := ZoneMatch{ZoneIdx: 1, Zone: s.Zones[1], Rule: &Rule{Action: ActionNODATA}, Trigger: TriggerQNAME}
	resp := s.EvaluateResponse([]dns.RR{answerA("192.0.2.1")})

	winner, observed := s.Merge(held, nil, resp.List)
	if winner.ZoneIdx != 0 {
		t.Fatalf("winner: %+v", winner)
	}
	if len(observed) != 0 {
		t.Fatalf("a zone past the winner was counted: %+v", observed)
	}
}

// TestOldGenerationIsCollectible pins §5.6's retention clause with the
// garbage collector as the judge: after a reload drops the old store, a
// live Local Data candidate must not keep the old rules reachable — the
// finalizer on the store's own record only runs if the candidate's copy
// is truly deep.
func TestOldGenerationIsCollectible(t *testing.T) {
	z := loadResponseIPZone(t)
	rule := z.responseIP4.lookupExact(netip.MustParsePrefix("192.0.2.7/32"))
	if rule == nil || len(rule.Local) != 1 {
		t.Fatal("fixture rule missing")
	}
	collected := make(chan struct{})
	runtime.SetFinalizer(rule.Local[0].(*dns.A), func(*dns.A) { close(collected) })

	s := &Store{Zones: []*Zone{z}}
	rm := s.EvaluateResponse([]dns.RR{answerA("192.0.2.7")})
	if len(rm.List) != 1 || len(rm.List[0].Local) != 1 {
		t.Fatal("no local-data candidate")
	}

	// The reload: every reference to the old generation is dropped while
	// the stamped candidate lives on.
	z, s, rule = nil, nil, nil
	_ = z
	_ = s
	_ = rule
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		select {
		case <-collected:
			// The candidate still serves its own copy.
			if rm.List[0].Local[0].(*dns.A).A == nil {
				t.Fatal("candidate lost its record")
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the old generation is pinned: a live candidate keeps the store's records reachable")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
