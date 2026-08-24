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
	if snap.Expired(now.Add(604799 * time.Second)) {
		t.Fatal("expired inside the SOA expire interval")
	}
	if !snap.Expired(now.Add(604801 * time.Second)) {
		t.Fatal("not expired past the SOA expire interval")
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
