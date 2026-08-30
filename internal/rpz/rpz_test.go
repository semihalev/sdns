package rpz

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
)

// fixtureZone carries one of everything §5.1/§5.2 classify, so the parse
// counts below are load-bearing: a classification change moves a record
// between Rules and a Skipped reason and a test goes red.
const fixtureZone = `
$TTL 300
rpz.test.	3600	IN	SOA	ns.rpz.test. admin.rpz.test. 2026083001 3600 900 604800 300
rpz.test.	3600	IN	NS	ns.rpz.test.

; the six actions as QNAME rules
nx.example.com.rpz.test.        IN CNAME .
nodata.example.com.rpz.test.    IN CNAME *.
pass.example.com.rpz.test.      IN CNAME rpz-passthru.
drop.example.com.rpz.test.      IN CNAME rpz-drop.
tcp.example.com.rpz.test.       IN CNAME rpz-tcp-only.
walled.example.com.rpz.test.    IN A 192.0.2.1
walled.example.com.rpz.test.    IN A 192.0.2.2
walled.example.com.rpz.test.    IN TXT "walled garden"
alias.example.com.rpz.test.     IN CNAME garden.example.net.
wildtarget.example.com.rpz.test. IN CNAME *.garden.example.net.

; wildcards, incl. competing lengths with different actions
*.evil.example.com.rpz.test.    IN CNAME .
*.sub.evil.example.com.rpz.test. IN CNAME rpz-passthru.

; skipped: unsupported triggers (later phases)
24.0.2.0.192.rpz-client-ip.rpz.test. IN CNAME .
32.1.2.0.192.rpz-ip.rpz.test.        IN CNAME .
ns.evil.example.rpz-nsdname.rpz.test. IN CNAME .

; skipped: unknown action code
future.example.com.rpz.test.    IN CNAME rpz-shiny-new-action.

; skipped: not action data
signed.example.com.rpz.test.    IN NS ns.evil.example.
dnssec.example.com.rpz.test.    IN DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE1FF783F3E15E63FB6D9A8E4F

; skipped: out of zone / apex data / conflict
stray.other.zone.               IN A 192.0.2.9
rpz.test.                       IN TXT "apex junk"
nx.example.com.rpz.test.        IN A 192.0.2.3
`

func loadFixture(t *testing.T, policy Override, cname string) *Zone {
	t.Helper()
	z, err := LoadZone("fixture", strings.NewReader(fixtureZone), "fixture.zone", policy, cname)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestLoadZoneClassifiesEverything(t *testing.T) {
	z := loadFixture(t, OverrideGiven, "")

	if z.Origin != "rpz.test." {
		t.Fatalf("origin = %q", z.Origin)
	}
	if z.SOA == nil || z.SOA.Serial != 2026083001 {
		t.Fatal("apex SOA not captured")
	}
	// 6 action rules + local-data alias + wildcard-target alias +
	// 2 wildcards + (since phase 2) the client-ip rule.
	if z.Rules != 11 {
		t.Fatalf("Rules = %d, want 11 (skips: %v)", z.Rules, z.Skipped)
	}
	if z.RulesClientIP != 1 {
		t.Fatalf("RulesClientIP = %d, want 1", z.RulesClientIP)
	}

	want := map[string]int{
		SkipTrigger:       2, // rpz-ip + rpz-nsdname wait for their phases
		SkipUnknownAction: 1,
		SkipNotActionData: 3, // apex NS + in-zone NS + DS
		SkipOutOfZone:     1,
		SkipApexData:      1,
		SkipConflict:      1,
	}
	for reason, n := range want {
		if z.Skipped[reason] != n {
			t.Errorf("Skipped[%s] = %d, want %d", reason, z.Skipped[reason], n)
		}
	}

	// The walled garden merged its three records into one rule.
	rule := z.exact["walled.example.com."]
	if rule == nil || rule.Action != ActionLocalData || len(rule.Local) != 3 {
		t.Fatalf("walled rule = %+v", rule)
	}
	// The conflicting A at nx.example.com did not displace NXDOMAIN.
	if r := z.exact["nx.example.com."]; r == nil || r.Action != ActionNXDOMAIN {
		t.Fatalf("nx rule = %+v", r)
	}
}

// canonFor builds the query-side key exactly as the middleware does: wire
// form through AppendCanonicalLabels on stack buffers.
func canonFor(t testing.TB, name string) (canon []byte, offs [dnsname.MaxLabels]int, n int) {
	t.Helper()
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	canon, n, ok := dnsname.AppendCanonicalLabels(make([]byte, 0, dnsname.MaxPresentationLength), buf[:off], offs[:])
	if !ok {
		t.Fatalf("canonical labels refused %q", name)
	}
	return canon, offs, n
}

func storeOf(zones ...*Zone) *Store { return &Store{Zones: zones} }

func TestMatchQNAMEPrecedenceWithinZone(t *testing.T) {
	z := loadFixture(t, OverrideGiven, "")
	s := storeOf(z)

	for _, tc := range []struct {
		name   string
		action Action
		wild   bool
	}{
		// Exact rules.
		{"nx.example.com.", ActionNXDOMAIN, false},
		{"NoData.Example.COM.", ActionNODATA, false}, // case-folded
		{"pass.example.com.", ActionPassthru, false},
		{"drop.example.com.", ActionDrop, false},
		{"tcp.example.com.", ActionTCPOnly, false},
		{"walled.example.com.", ActionLocalData, false},
		// Rule 3: among wildcards the most labels wins; the two rules
		// prescribe different actions, so a precedence swap changes the
		// observable outcome.
		{"x.evil.example.com.", ActionNXDOMAIN, true},
		{"x.sub.evil.example.com.", ActionPassthru, true},
	} {
		canon, offs, n := canonFor(t, tc.name)
		winner, observed := s.Match(canon, offs[:], n, netip.Addr{})
		if winner.Zone == nil {
			t.Fatalf("%s: no match", tc.name)
		}
		if got := winner.Effective(); got != tc.action {
			t.Errorf("%s: action %v, want %v", tc.name, got, tc.action)
		}
		if winner.Wildcard != tc.wild {
			t.Errorf("%s: wildcard = %v, want %v", tc.name, winner.Wildcard, tc.wild)
		}
		if observed != nil {
			t.Errorf("%s: unexpected observations %v", tc.name, observed)
		}
	}
}

func TestWildcardMatchesSubdomainsOnly(t *testing.T) {
	z := loadFixture(t, OverrideGiven, "")
	s := storeOf(z)

	// evil.example.com. itself has no exact rule and must not match its
	// own wildcard.
	canon, offs, n := canonFor(t, "evil.example.com.")
	if winner, _ := s.Match(canon, offs[:], n, netip.Addr{}); winner.Zone != nil {
		t.Fatalf("apex of a wildcard matched: %+v", winner)
	}
}

func TestMatchQNAMEZoneOrderWins(t *testing.T) {
	// Rule 1: the earlier zone wins, and the two zones prescribe
	// different actions for the same name.
	first, err := LoadZone("first", strings.NewReader(`
z1.test. IN SOA ns. admin. 1 3600 900 604800 300
victim.example.com.z1.test. IN CNAME rpz-passthru.
`), "z1", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadZone("second", strings.NewReader(`
z2.test. IN SOA ns. admin. 1 3600 900 604800 300
victim.example.com.z2.test. IN CNAME .
`), "z2", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}

	canon, offs, n := canonFor(t, "victim.example.com.")
	winner, _ := storeOf(first, second).Match(canon, offs[:], n, netip.Addr{})
	if winner.Zone == nil || winner.Zone.Name != "first" || winner.Effective() != ActionPassthru {
		t.Fatalf("winner = %+v, want first/passthru", winner)
	}

	// Reversed order, reversed outcome — the assertion that pins rule 1.
	winner, _ = storeOf(second, first).Match(canon, offs[:], n, netip.Addr{})
	if winner.Zone == nil || winner.Zone.Name != "second" || winner.Effective() != ActionNXDOMAIN {
		t.Fatalf("winner = %+v, want second/nxdomain", winner)
	}
}

func TestDisabledZoneObservesWithoutConsuming(t *testing.T) {
	disabled := loadFixture(t, OverrideDisabled, "")
	disabled.Name = "watching"
	enforcing, err := LoadZone("acting", strings.NewReader(`
z2.test. IN SOA ns. admin. 1 3600 900 604800 300
nx.example.com.z2.test. IN CNAME rpz-drop.
`), "z2", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}

	canon, offs, n := canonFor(t, "nx.example.com.")
	winner, observed := storeOf(disabled, enforcing).Match(canon, offs[:], n, netip.Addr{})

	// The disabled zone matched first and must not consume: the later
	// enforcing zone's different action is the winner.
	if winner.Zone == nil || winner.Zone.Name != "acting" || winner.Effective() != ActionDrop {
		t.Fatalf("winner = %+v, want acting/drop", winner)
	}
	// And the disabled match is observed with what it would have done.
	if len(observed) != 1 || observed[0].Zone.Name != "watching" || observed[0].Effective() != ActionNXDOMAIN {
		t.Fatalf("observed = %+v", observed)
	}
}

func TestOverridesReplaceTheRuleAction(t *testing.T) {
	for _, tc := range []struct {
		policy Override
		want   Action
	}{
		{OverridePassthru, ActionPassthru},
		{OverrideNXDOMAIN, ActionNXDOMAIN},
		{OverrideNODATA, ActionNODATA},
		{OverrideDrop, ActionDrop},
		{OverrideTCPOnly, ActionTCPOnly},
		{OverrideCNAME, ActionLocalData},
	} {
		z := loadFixture(t, tc.policy, "garden.example.net.")
		canon, offs, n := canonFor(t, "drop.example.com.")
		winner, _ := storeOf(z).Match(canon, offs[:], n, netip.Addr{})
		if winner.Zone == nil {
			t.Fatalf("policy %v: no match", tc.policy)
		}
		if got := winner.Effective(); got != tc.want {
			t.Errorf("policy %v: action %v, want %v", tc.policy, got, tc.want)
		}
	}
}

func TestBareStarMatchesEverything(t *testing.T) {
	z, err := LoadZone("all", strings.NewReader(`
z.test. IN SOA ns. admin. 1 3600 900 604800 300
*.z.test. IN CNAME .
`), "z", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	canon, offs, n := canonFor(t, "anything.at.all.example.")
	if winner, _ := storeOf(z).Match(canon, offs[:], n, netip.Addr{}); winner.Zone == nil || winner.Effective() != ActionNXDOMAIN {
		t.Fatalf("bare * did not match: %+v", winner)
	}
}

// TestMatchQNAMEMissAllocatesNothing is the §5.11 contract for the engine:
// the non-matching query — the product's steady state — pays map probes
// off the caller's stack buffer and nothing else.
func TestMatchQNAMEMissAllocatesNothing(t *testing.T) {
	z := loadFixture(t, OverrideGiven, "")
	s := storeOf(z, z, z) // several zones, all probed on a miss

	buf := make([]byte, 64)
	off, err := dns.PackDomainName("miss.example.org.", buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wire := buf[:off]

	if allocs := testing.AllocsPerRun(200, func() {
		var keyBuf [dnsname.MaxPresentationLength]byte
		var offs [dnsname.MaxLabels]int
		canon, n, ok := dnsname.AppendCanonicalLabels(keyBuf[:0], wire, offs[:])
		if !ok {
			t.Fatal("refused")
		}
		winner, observed := s.Match(canon, offs[:], n, netip.Addr{})
		if winner.Zone != nil || observed != nil {
			t.Fatal("unexpected match")
		}
	}); allocs != 0 {
		t.Fatalf("a miss cost %.0f allocations, want 0", allocs)
	}
}
