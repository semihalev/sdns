package rpz

import (
	"net/netip"
	"strings"
	"testing"
)

// TestParseClientIPOwner pins the draft's §4.1.1 encoding, the zz
// last-run subtlety included: the fixture 2001:db8:0:0:1:0:0:1 has two
// equal zero runs, and zz stands for the LAST one.
func TestParseClientIPOwner(t *testing.T) {
	for _, tc := range []struct {
		enc  string
		want string
	}{
		// IPv4: prefix, then reversed octets, family kept.
		{"24.0.2.0.192", "192.0.2.0/24"},
		{"32.9.2.0.192", "192.0.2.9/32"},
		{"8.0.0.0.10", "10.0.0.0/8"},
		// IPv6, no compression: eight reversed hextets.
		{"128.1.0.0.0.0.0.db8.2001", "2001:db8::1/128"},
		// zz covering one run.
		{"128.1.zz.db8.2001", "2001:db8::1/128"},
		{"48.zz.db8.2001", "2001:db8::/48"},
		// The draft's compressed-LAST rule: for 2001:db8:0:0:1:0:0:1 the
		// zz is the run at fields six and seven, so the owner keeps the
		// first run spelled out.
		{"128.1.zz.1.0.0.db8.2001", "2001:db8:0:0:1::1/128"},
		// Host bits under the prefix are masked, not refused.
		{"24.99.2.0.192", "192.0.2.0/24"},
	} {
		p, ok := parseClientIPOwner(tc.enc)
		if !ok {
			t.Errorf("%q: refused", tc.enc)
			continue
		}
		want := netip.MustParsePrefix(tc.want).Masked()
		if p.Masked() != want {
			t.Errorf("%q: got %v, want %v", tc.enc, p.Masked(), want)
		}
	}
}

func TestParseClientIPOwnerRefusesMalformed(t *testing.T) {
	for _, enc := range []string{
		"",                           // nothing
		"24",                         // prefix alone
		"33.0.2.0.192",               // v4 prefix too long
		"129.zz",                     // v6 prefix too long
		"128.zz.zz",                  // two zz
		"128.1.2.3.4.5.6.7.8.9",      // nine fields
		"128.xyz.zz",                 // not hex
		"128.1.0.0.0.0.0.0.db8.2001", // nine labels
		"abc.0.2.0.192",              // prefix not a number
	} {
		if _, ok := parseClientIPOwner(enc); ok {
			t.Errorf("%q: accepted, want refusal", enc)
		}
	}
}

const clientIPZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
; client-ip rules with different actions per prefix length
24.0.2.0.192.rpz-client-ip.rpz.test.  IN CNAME rpz-drop.
32.9.2.0.192.rpz-client-ip.rpz.test.  IN CNAME rpz-passthru.
48.zz.db8.2001.rpz-client-ip.rpz.test. IN CNAME .
; a qname rule in the SAME zone, different action again: rule 2's fixture
victim.example.com.rpz.test.          IN CNAME *.
; local data on a client-ip trigger: the encoded owner must never leak
16.0.0.0.10.rpz-client-ip.rpz.test.   IN A 192.0.2.99
`

func loadClientIPZone(t *testing.T) *Zone {
	t.Helper()
	z, err := LoadZone("cip", strings.NewReader(clientIPZone), "cip.zone", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// TestClientIPBeatsQNAMEWithinZone pins precedence rule 2 with competing
// rules prescribing different actions: swapping the trigger order changes
// the observable outcome and this goes red.
func TestClientIPBeatsQNAMEWithinZone(t *testing.T) {
	z := loadClientIPZone(t)
	s := storeOf(z)
	canon, offs, n := canonFor(t, "victim.example.com.")

	// A client inside 192.0.2.0/24: CLIENT-IP (drop) must beat the
	// QNAME rule (nodata).
	client := CanonicalClient(netip.MustParseAddr("192.0.2.55"))
	winner, _ := s.Match(canon, offs[:], n, client)
	if winner.Zone == nil || winner.Trigger != TriggerClientIP || winner.Effective() != ActionDrop {
		t.Fatalf("winner = %+v, want client-ip/drop", winner)
	}

	// A client outside every prefix: the QNAME rule stands.
	outside := CanonicalClient(netip.MustParseAddr("198.51.100.1"))
	winner, _ = s.Match(canon, offs[:], n, outside)
	if winner.Zone == nil || winner.Trigger != TriggerQNAME || winner.Effective() != ActionNODATA {
		t.Fatalf("winner = %+v, want qname/nodata", winner)
	}
}

// TestClientIPLongestPrefixWins pins rule 4: /32 passthru inside the /24
// drop, the more specific rule prescribes the opposite action.
func TestClientIPLongestPrefixWins(t *testing.T) {
	z := loadClientIPZone(t)
	s := storeOf(z)
	canon, offs, n := canonFor(t, "victim.example.com.")

	exempt := CanonicalClient(netip.MustParseAddr("192.0.2.9"))
	winner, _ := s.Match(canon, offs[:], n, exempt)
	if winner.Effective() != ActionPassthru || winner.PrefixBits != 32 {
		t.Fatalf("winner = %+v, want passthru at /32", winner)
	}

	neighbor := CanonicalClient(netip.MustParseAddr("192.0.2.10"))
	winner, _ = s.Match(canon, offs[:], n, neighbor)
	if winner.Effective() != ActionDrop || winner.PrefixBits != 24 {
		t.Fatalf("winner = %+v, want drop at /24", winner)
	}
}

func TestClientIPv6Match(t *testing.T) {
	z := loadClientIPZone(t)
	s := storeOf(z)
	canon, offs, n := canonFor(t, "anything.example.org.")

	v6 := CanonicalClient(netip.MustParseAddr("2001:db8:0:2::3"))
	winner, _ := s.Match(canon, offs[:], n, v6)
	if winner.Zone == nil || winner.Effective() != ActionNXDOMAIN {
		t.Fatalf("winner = %+v, want nxdomain from the /48", winner)
	}
	// And the third hextet flipping out of the /48 loses the match.
	out := CanonicalClient(netip.MustParseAddr("2001:db8:1:2::3"))
	if w2, _ := s.Match(canon, offs[:], n, out); w2.Zone != nil {
		t.Fatalf("outside the /48 still matched: %+v", w2)
	}
}

// TestClientIPMissAllocatesNothing extends the §5.11 pin: prefixes across
// several lengths probed for a non-matching client and name, zero heap.
func TestClientIPMissAllocatesNothing(t *testing.T) {
	z := loadClientIPZone(t)
	s := storeOf(z, z)
	canon, offs, n := canonFor(t, "innocent.example.org.")
	client := CanonicalClient(netip.MustParseAddr("203.0.113.7"))

	if allocs := testing.AllocsPerRun(200, func() {
		winner, observed := s.Match(canon, offs[:], n, client)
		if winner.Zone != nil || observed != nil {
			t.Fatal("unexpected match")
		}
	}); allocs != 0 {
		t.Fatalf("a client-ip miss cost %.0f allocations, want 0", allocs)
	}
}

// BenchmarkClientIPAdversarialAllLengths is the §5.3/§6 exit criterion:
// a hostile feed carrying every prefix length /1../128, probed by a
// non-matching client. The stated budget is 2µs per zone walk, well
// under 6% of the per-query budget at the bench-box scoreboard rate,
// and the length-map walk must come in under it or be replaced by a
// radix before merge.
func BenchmarkClientIPAdversarialAllLengths(b *testing.B) {
	z := &Zone{Name: "adversarial", Skipped: map[string]int{}}
	base := netip.MustParseAddr("2001:db8::")
	for bits := 1; bits <= 128; bits++ {
		z.insertClientIP(netip.PrefixFrom(base, bits), ActionNXDOMAIN, nil)
	}
	if z.RulesClientIP != 128 {
		b.Fatalf("fixture built %d lengths", z.RulesClientIP)
	}
	// A client sharing no bits with the rules: every length probes and
	// misses.
	client := CanonicalClient(netip.MustParseAddr("fd00::1"))

	b.ReportAllocs()
	for b.Loop() {
		if r, _ := z.clientIP6.lookup(client); r != nil {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkClientIPRealisticLengths is the same walk at a commercial
// feed's shape: a handful of distinct lengths.
func BenchmarkClientIPRealisticLengths(b *testing.B) {
	z := &Zone{Name: "realistic", Skipped: map[string]int{}}
	for i, bits := range []int{120, 124, 128, 48, 64} {
		addr := netip.MustParseAddr("2001:db8::").As16()
		addr[6] = byte(i)
		z.insertClientIP(netip.PrefixFrom(netip.AddrFrom16(addr), bits), ActionDrop, nil)
	}
	// A v6 client for the v6 table: after the family split, a lookup is
	// always family-consistent, the router picks the table.
	client := CanonicalClient(netip.MustParseAddr("fd00::7"))

	b.ReportAllocs()
	for b.Loop() {
		if r, _ := z.clientIP6.lookup(client); r != nil {
			b.Fatal("unexpected match")
		}
	}
}

// TestClientIPFamiliesStaySeparate pins the review's merge blocker: an
// IPv6 rule must never match an IPv4 client and the reverse, folding
// IPv4 into the ::ffff/96 corner of one key space let ::/0 swallow every
// v4 client and collided ::ffff:0:0/96 with 0.0.0.0/0.
func TestClientIPFamiliesStaySeparate(t *testing.T) {
	z, err := LoadZone("families", strings.NewReader(`
rpz.test. IN SOA ns. admin. 1 3600 900 604800 300
; the v6 catch-all and the two colliding-slot rules, different actions
0.zz.rpz-client-ip.rpz.test.        IN CNAME .
96.zz.ffff.0.rpz-client-ip.rpz.test. IN CNAME rpz-drop.
0.0.0.0.0.rpz-client-ip.rpz.test.   IN CNAME rpz-tcp-only.
`), "fam.zone", OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	// All three compiled: the v6 ::ffff:0:0/96 and the v4 0.0.0.0/0 are
	// different rules in different tables, not a conflict.
	if z.RulesClientIP != 3 || z.Skipped[SkipConflict] != 0 {
		t.Fatalf("rules=%d conflicts=%d, want 3/0", z.RulesClientIP, z.Skipped[SkipConflict])
	}

	s := storeOf(z)
	canon, offs, n := canonFor(t, "x.example.")

	// A v4 client meets only the v4 catch-all, tcp-only, never the v6
	// ::/0 nxdomain or the ::ffff drop.
	v4 := CanonicalClient(netip.MustParseAddr("198.51.100.7"))
	if w, _ := s.Match(canon, offs[:], n, v4); w.Effective() != ActionTCPOnly {
		t.Fatalf("v4 client got %v, want the v4 table's tcp-only", w.Effective())
	}
	// The same client arriving in mapped spelling is still a v4 client.
	mapped := CanonicalClient(netip.MustParseAddr("::ffff:198.51.100.7"))
	if w, _ := s.Match(canon, offs[:], n, mapped); w.Effective() != ActionTCPOnly {
		t.Fatalf("mapped v4 client got %v, want the v4 table's tcp-only", w.Effective())
	}
	// An address spelled inside ::ffff:0:0/96 IS an IPv4 client, that is
	// what mapped means, and CanonicalClient's Unmap enforces it, so it
	// meets the v4 table, never the feed's v6 ::ffff rule. That rule
	// stays compiled and distinct (asserted above) but no client can
	// reach it, which is the correct fate for a v6 spelling of v4 space.
	spelled := CanonicalClient(netip.MustParseAddr("::ffff:0:1"))
	if !spelled.Is4() {
		t.Fatal("Unmap did not classify a mapped spelling as v4")
	}
	if w, _ := s.Match(canon, offs[:], n, spelled); w.Effective() != ActionTCPOnly {
		t.Fatalf("mapped-range client got %v, want the v4 table's tcp-only", w.Effective())
	}
	// A plain v6 client gets the v6 catch-all.
	v6 := CanonicalClient(netip.MustParseAddr("2001:db8::1"))
	if w, _ := s.Match(canon, offs[:], n, v6); w.Effective() != ActionNXDOMAIN {
		t.Fatalf("v6 client got %v, want the v6 ::/0 nxdomain", w.Effective())
	}
}
