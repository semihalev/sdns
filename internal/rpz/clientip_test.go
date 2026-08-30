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
		// IPv4: prefix, then reversed octets, lifted to +96.
		{"24.0.2.0.192", "::ffff:192.0.2.0/120"},
		{"32.9.2.0.192", "::ffff:192.0.2.9/128"},
		{"8.0.0.0.10", "::ffff:10.0.0.0/104"},
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
		{"24.99.2.0.192", "::ffff:192.0.2.0/120"},
	} {
		p, ok := parseClientIPOwner(tc.enc)
		if !ok {
			t.Errorf("%q: refused", tc.enc)
			continue
		}
		want := netip.MustParsePrefix(tc.want)
		wantCanon := netip.PrefixFrom(canonical16(want.Masked().Addr()), prefixBitsIn128(want))
		got := netip.PrefixFrom(canonical16(p.Masked().Addr()), p.Bits())
		if got != wantCanon {
			t.Errorf("%q: got %v, want %v", tc.enc, got, wantCanon)
		}
	}
}

// prefixBitsIn128 lifts a v4 prefix's length into the shared space the
// engine stores everything in.
func prefixBitsIn128(p netip.Prefix) int {
	if p.Addr().Is4() {
		return p.Bits() + 96
	}
	return p.Bits()
}

func TestParseClientIPOwnerRefusesMalformed(t *testing.T) {
	for _, enc := range []string{
		"",                           // nothing
		"24",                         // prefix alone
		"33.0.2.0.192",               // v4 prefix too long
		"129.zz",                     // v6 prefix too long
		"24.0.2.0.999",               // octet out of range... falls to v6 hex? 999 is not hex-only... 999 parses as hex! guard below
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
// drop — the more specific rule prescribes the opposite action.
func TestClientIPLongestPrefixWins(t *testing.T) {
	z := loadClientIPZone(t)
	s := storeOf(z)
	canon, offs, n := canonFor(t, "victim.example.com.")

	exempt := CanonicalClient(netip.MustParseAddr("192.0.2.9"))
	winner, _ := s.Match(canon, offs[:], n, exempt)
	if winner.Effective() != ActionPassthru || winner.PrefixBits != 128 {
		t.Fatalf("winner = %+v, want passthru at /128", winner)
	}

	neighbor := CanonicalClient(netip.MustParseAddr("192.0.2.10"))
	winner, _ = s.Match(canon, offs[:], n, neighbor)
	if winner.Effective() != ActionDrop || winner.PrefixBits != 120 {
		t.Fatalf("winner = %+v, want drop at /120", winner)
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
// non-matching client. The stated budget is 2µs per zone walk — well
// under 6% of the per-query budget at the bench-box scoreboard rate —
// and the length-map walk must come in under it or be replaced by a
// radix before merge.
func BenchmarkClientIPAdversarialAllLengths(b *testing.B) {
	z := &Zone{Name: "adversarial", Skipped: map[string]int{}}
	base := netip.MustParseAddr("2001:db8::")
	for bits := 1; bits <= 128; bits++ {
		z.insertClientIP(netip.PrefixFrom(canonical16(base), bits), ActionNXDOMAIN, nil)
	}
	if z.RulesClientIP != 128 {
		b.Fatalf("fixture built %d lengths", z.RulesClientIP)
	}
	// A client sharing no bits with the rules: every length probes and
	// misses.
	client := CanonicalClient(netip.MustParseAddr("fd00::1"))

	b.ReportAllocs()
	for b.Loop() {
		if r, _ := z.clientIP.lookup(client); r != nil {
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
	client := CanonicalClient(netip.MustParseAddr("203.0.113.7"))

	b.ReportAllocs()
	for b.Loop() {
		if r, _ := z.clientIP.lookup(client); r != nil {
			b.Fatal("unexpected match")
		}
	}
}
