package localroot

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	root := buildTestRoot(t)
	snap, err := buildSnapshot(root.rrs, time.Now())
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return snap
}

func TestSnapshotReferral(t *testing.T) {
	snap := testSnapshot(t)

	ref, ok := snap.Referral("com.")
	if !ok {
		t.Fatal("com. delegation missing")
	}
	if len(ref.NS) != 1 || len(ref.DS) != 1 {
		t.Fatalf("com. referral NS=%d DS=%d, want 1/1", len(ref.NS), len(ref.DS))
	}
	glue := ref.Glue["ns.com."]
	if len(glue) != 2 {
		t.Fatalf("ns.com. glue = %d records, want A+AAAA", len(glue))
	}

	if ref, ok := snap.Referral("org."); !ok || len(ref.DS) != 0 {
		t.Fatalf("org. must be an unsigned delegation; ok=%v DS=%d", ok, len(ref.DS))
	}
	if _, ok := snap.Referral("nope."); ok {
		t.Fatal("a delegation the zone does not hold was returned")
	}
	// Glue owners are not delegations: a hostile query for a glue name's
	// "TLD" must not fabricate a referral.
	if _, ok := snap.Referral("ns.com."); ok {
		t.Fatal("a glue owner masqueraded as a delegation")
	}
}

func TestSnapshotDSAnswer(t *testing.T) {
	snap := testSnapshot(t)

	ds, dsSig, _, _, ok := snap.DSAnswer("com.")
	if !ok || len(ds) != 1 || len(dsSig) != 1 {
		t.Fatalf("com. DS answer = ds:%d sig:%d ok:%v, want signed DS", len(ds), len(dsSig), ok)
	}

	ds, _, nsec, nsecSig, ok := snap.DSAnswer("org.")
	if !ok || len(ds) != 0 || len(nsec) != 1 || len(nsecSig) != 1 {
		t.Fatalf("org. DS answer must be the NSEC NODATA proof; ds:%d nsec:%d sig:%d ok:%v",
			len(ds), len(nsec), len(nsecSig), ok)
	}

	if _, _, _, _, ok := snap.DSAnswer("nope."); ok {
		t.Fatal("a DS answer for an absent TLD")
	}
}

func TestSnapshotDenial(t *testing.T) {
	snap := testSnapshot(t)

	// dev. sorts between com. and org.: covered by com.'s NSEC, with the
	// apex NSEC riding along as the wildcard proof.
	proof, ok := snap.Denial("dev.")
	if !ok {
		t.Fatal("dev. denial not covered")
	}
	var owners []string
	nsecs := 0
	for _, rr := range proof {
		if rr.Header().Rrtype == dns.TypeNSEC {
			nsecs++
			owners = append(owners, rr.Header().Name)
		}
	}
	if nsecs != 2 {
		t.Fatalf("dev. denial carries %d NSECs (%v), want covering + apex", nsecs, owners)
	}

	// zzz. sorts past org., whose NSEC wraps to the apex: covered.
	if _, ok := snap.Denial("zzz."); !ok {
		t.Fatal("zzz. denial not covered by the wrapping NSEC")
	}

	// A name that exists is not deniable.
	if _, ok := snap.Denial("com."); ok {
		t.Fatal("an existing TLD was denied")
	}
}

func TestSnapshotExpiry(t *testing.T) {
	root := buildTestRoot(t)
	now := time.Now()
	snap, err := buildSnapshot(root.rrs, now)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	// The test zone signs with a one-hour window against a seven-day SOA
	// expire; the horizon must follow the signatures, the nearer bound.
	// Past that instant every proof the copy could serve carries a dead
	// signature.
	if snap.Expired(now.Add(50 * time.Minute)) {
		t.Fatal("expired inside the signature validity window")
	}
	if !snap.Expired(now.Add(61 * time.Minute)) {
		t.Fatal("not expired past the signature window — the SOA expire must not extend dead signatures")
	}
	if !snap.ValidUntil().Before(now.Add(2 * time.Hour)) {
		t.Fatalf("ValidUntil = %v, not bounded by the signature window", snap.ValidUntil())
	}
}

func TestSnapshotApexAnswerRefusesZONEMD(t *testing.T) {
	snap := testSnapshot(t)

	// Assert the zone actually holds the type: without this the refusal
	// below would come from the NODATA branch and prove nothing.
	if len(snap.owners["."][dns.TypeZONEMD]) == 0 {
		t.Fatal("test zone has no apex ZONEMD, so its refusal cannot be tested here")
	}
	if _, _, _, _, ok := snap.ApexAnswer(dns.TypeZONEMD); ok {
		t.Fatal("ZONEMD served from the copy: RFC 8976 leaves its signatures outside the digest, " +
			"so serving the set would put unauthenticated records behind AD=1")
	}
}

// TestLoadIgnoresDuplicateRRs drives the whole load path, because that is
// where normalization sits: a doubled record must not survive into the index,
// must not be digested twice, and must not read as a second ZONEMD tuple.
func TestLoadIgnoresDuplicateRRs(t *testing.T) {
	root := buildTestRoot(t)

	// RFC 5936 §2.2: a source that double-sends a record must not put it in
	// an answer twice. The NS twin differs only in TTL, which is outside the
	// RFC 8976 §3.3.1.1 identity the rule is written against; the ZONEMD
	// twin is exact, the case that used to read as a repeated tuple and
	// refuse the whole zone.
	doubled := make([]dns.RR, 0, len(root.rrs)+2)
	var twinnedNS, twinnedZONEMD bool
	for _, rr := range root.rrs {
		doubled = append(doubled, rr)
		switch record := rr.(type) {
		case *dns.NS:
			if dns.CanonicalName(record.Hdr.Name) == "com." {
				twin := dns.Copy(record)
				twin.Header().Ttl += 60
				doubled = append(doubled, twin)
				twinnedNS = true
			}
		case *dns.ZONEMD:
			doubled = append(doubled, dns.Copy(record))
			twinnedZONEMD = true
		}
	}
	if !twinnedNS || !twinnedZONEMD {
		t.Fatalf("test zone lacks records to duplicate: ns=%v zonemd=%v", twinnedNS, twinnedZONEMD)
	}

	m := New(nil, func() []dns.RR { return root.anchors })
	if err := m.Load(doubled); err != nil {
		t.Fatalf("a zone with duplicate records was refused: %v", err)
	}
	snap := m.Active()
	if snap == nil {
		t.Fatal("no active copy after load")
	}
	ref, ok := snap.Referral("com.")
	if !ok {
		t.Fatal("com. delegation missing")
	}
	if len(ref.NS) != 1 {
		t.Fatalf("com. NS set = %d records, want the duplicate ignored", len(ref.NS))
	}
}

func TestSnapshotDSAnswerRefusesUnsignedDS(t *testing.T) {
	root := buildTestRoot(t)

	// A DS set the copy cannot evidence must not be served: stripping its
	// signatures leaves a delegation whose secure status is unproven, and
	// asserting it under AD=1 is the downgrade the proof requirement exists
	// to prevent.
	stripped := make([]dns.RR, 0, len(root.rrs))
	for _, rr := range root.rrs {
		if sig, ok := rr.(*dns.RRSIG); ok &&
			sig.TypeCovered == dns.TypeDS && dns.CanonicalName(sig.Hdr.Name) == "com." {
			continue
		}
		stripped = append(stripped, rr)
	}
	if len(stripped) == len(root.rrs) {
		t.Fatal("test zone has no RRSIG(DS) at com. to strip")
	}

	snap, err := buildSnapshot(stripped, time.Now())
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if _, _, _, _, ok := snap.DSAnswer("com."); ok {
		t.Fatal("an unsigned DS set was served from the copy")
	}
}

func TestTLDOf(t *testing.T) {
	for name, want := range map[string]string{
		".":                "",
		"com.":             "com.",
		"www.example.com.": "com.",
		`a\.com.`:          `a\.com.`,
	} {
		if got := TLDOf(name); got != want {
			t.Fatalf("TLDOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSnapshotApexGlue(t *testing.T) {
	snap := testSnapshot(t)

	glue := snap.ApexGlue()
	if len(glue) == 0 {
		t.Fatal("the root's own NS targets have no glue in the copy")
	}
	named := make(map[string]bool)
	for _, rr := range snap.owners["."][dns.TypeNS] {
		named[dns.CanonicalName(rr.(*dns.NS).Ns)] = true
	}
	for _, rr := range glue {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
		default:
			t.Fatalf("apex glue carries a %s record", dns.TypeToString[rr.Header().Rrtype])
		}
		if owner := dns.CanonicalName(rr.Header().Name); !named[owner] {
			t.Fatalf("apex glue carries an address for %s, which the root's NS set does not name", owner)
		}
	}
}

// TestSnapshotProofsRequireTheirSignatures pins the rule the DS set and the
// apex NODATA branch already follow: the copy may hold a record the digest
// authenticated, but a denial served to a client under AD=1 needs the
// signature that lets the client check it too.
func TestSnapshotProofsRequireTheirSignatures(t *testing.T) {
	root := buildTestRoot(t)

	withoutNSECSig := func(owner string) *Snapshot {
		t.Helper()
		kept := make([]dns.RR, 0, len(root.rrs))
		stripped := false
		for _, rr := range root.rrs {
			if sig, ok := rr.(*dns.RRSIG); ok &&
				sig.TypeCovered == dns.TypeNSEC && dns.CanonicalName(sig.Hdr.Name) == owner {
				stripped = true
				continue
			}
			kept = append(kept, rr)
		}
		if !stripped {
			t.Fatalf("test zone has no RRSIG(NSEC) at %s to strip", owner)
		}
		snap, err := buildSnapshot(kept, time.Now())
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		return snap
	}

	// org. is the unsigned delegation, so its DS answer is the NSEC NODATA
	// proof — which is a proof only while it is signed.
	if _, _, _, _, ok := withoutNSECSig("org.").DSAnswer("org."); ok {
		t.Fatal("a DS NODATA proof with no signature was served")
	}
	// dev. sorts inside com.'s NSEC span, so com.'s NSEC is what denies it.
	if _, ok := withoutNSECSig("com.").Denial("dev."); ok {
		t.Fatal("an NXDOMAIN was synthesized from an unsigned covering NSEC")
	}
	// The apex NSEC is the wildcard half of every NXDOMAIN.
	if _, ok := withoutNSECSig(".").Denial("dev."); ok {
		t.Fatal("an NXDOMAIN was synthesized without a signed wildcard proof")
	}
}
