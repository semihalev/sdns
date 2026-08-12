package cache

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

// denialProofOnlySnapshot returns the single zone the test cache holds.
func denialProofOnlySnapshot(
	tb testing.TB,
	cache *denialProofCache,
) *denialProofZoneSnapshot {
	tb.Helper()
	if len(cache.zoneIndex) != 1 {
		tb.Fatalf("published zones = %d, want 1", len(cache.zoneIndex))
	}
	for _, snapshot := range cache.zoneIndex {
		return snapshot
	}
	return nil
}

// TestDenialProofAdmissionKeepsZoneIndex pins that admitting into a zone
// reuses the writer's entry map rather than rewriting it. Republishing used
// to clone the map on every admission and every eviction, so a zone holding
// thousands of names paid for all of them to record one.
func TestDenialProofAdmissionKeepsZoneIndex(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	admit := func(label string) {
		t.Helper()
		owner, next := label+".example.", label+"z.example."
		fixture := newDenialProofNSECFixture(
			t, now, owner, dns.TypeA, dns.RcodeNameError, "example.",
			[2]string{owner, next},
		)
		if !cache.record(fixture.msg, "example.", time.Time{}) {
			t.Fatalf("admission of %s was rejected", owner)
		}
	}

	admit("a")
	if len(cache.zoneEntries) != 1 {
		t.Fatalf("writer zones = %d, want 1", len(cache.zoneEntries))
	}
	var key denialProofZoneKey
	for zone := range cache.zoneEntries {
		key = zone
	}
	before := reflect.ValueOf(cache.zoneEntries[key]).Pointer()

	admit("b")
	if after := reflect.ValueOf(cache.zoneEntries[key]).Pointer(); after != before {
		t.Fatal("admission replaced the zone's entry map instead of adding to it")
	}

	cache.purge(dns.Question{
		Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})
	if after := reflect.ValueOf(cache.zoneEntries[key]).Pointer(); after != before {
		t.Fatal("eviction replaced the zone's entry map instead of deleting from it")
	}
}

// TestDenialProofZoneIndexesStayInStep pins that the writer's index does not
// outlive the published view. The two are updated together, and a zone that
// empties has to disappear from both — otherwise the map the writer keeps
// grows for every zone ever seen.
func TestDenialProofZoneIndexesStayInStep(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	// Two entries — one SOA and one NSEC — so admitting a second zone
	// evicts the first one whole.
	cache := newDenialProofTestCache(&now, 2, 2, maxDenialProofTTL)

	admit := func(zone string) {
		t.Helper()
		owner := "gone." + zone
		fixture := newDenialProofNSECFixture(
			t, now, owner, dns.TypeA, dns.RcodeNameError, zone,
			[2]string{owner, "gonez." + zone},
		)
		if !cache.record(fixture.msg, zone, time.Time{}) {
			t.Fatalf("admission into %s was rejected", zone)
		}
	}

	admit("first.example.")
	if len(cache.zoneEntries) != 1 || len(cache.zoneIndex) != 1 {
		t.Fatalf("after admission: %d writer zones, %d published zones, want 1 / 1",
			len(cache.zoneEntries), len(cache.zoneIndex))
	}

	// Displaces the first zone entirely.
	admit("second.example.")

	if len(cache.zoneEntries) != len(cache.zoneIndex) {
		t.Fatalf("after eviction: %d writer zones, %d published zones — the "+
			"writer index is retaining zones nobody can see",
			len(cache.zoneEntries), len(cache.zoneIndex))
	}
	if len(cache.zoneEntries) != 1 {
		t.Fatalf("writer zones = %d, want only the surviving one",
			len(cache.zoneEntries))
	}
}

// TestDenialProofPreparedNSECPublished pins the two halves of the prepared
// NSEC set: publication flattens it in the same order as the entries it came
// from, and a lookup that finds nothing expired evaluates that published
// slice as it stands instead of rebuilding it.
func TestDenialProofPreparedNSECPublished(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	for _, label := range []string{"a", "b"} {
		owner, next := label+".example.", label+"z.example."
		fixture := newDenialProofNSECFixture(
			t, now, owner, dns.TypeA, dns.RcodeNameError, "example.",
			[2]string{owner, next},
		)
		if !cache.record(fixture.msg, "example.", time.Time{}) {
			t.Fatalf("admission of %s was rejected", owner)
		}
	}

	snapshot := denialProofOnlySnapshot(t, cache)
	if len(snapshot.nsec) != 2 {
		t.Fatalf("published NSEC entries = %d, want 2", len(snapshot.nsec))
	}

	var want []dnssec.PreparedNSEC
	for _, entry := range snapshot.nsec {
		want = append(want, entry.preparedNSEC...)
	}
	if !reflect.DeepEqual(snapshot.nsecPrepared, want) {
		t.Fatal("the published prepared set does not match its entries in order")
	}

	live, prepared := denialProofLivePreparedNSEC(
		snapshot.nsec,
		snapshot.nsecPrepared,
		now,
	)
	if len(live) == 0 || &live[0] != &snapshot.nsec[0] {
		t.Fatal("nothing had expired, yet the live entries were copied")
	}
	if len(prepared) == 0 || &prepared[0] != &snapshot.nsecPrepared[0] {
		t.Fatal("nothing had expired, yet the prepared set was rebuilt")
	}
}

// TestDenialProofPreparedNSECDropsExpired covers the other side: once an
// entry has expired the lookup has to filter, and it must do so without
// disturbing the published slice that other readers still hold.
func TestDenialProofPreparedNSECDropsExpired(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	early := newDenialProofNSECFixture(
		t, now, "a.example.", dns.TypeA, dns.RcodeNameError, "example.",
		[2]string{"a.example.", "az.example."},
	)
	if !cache.record(early.msg, "example.", time.Time{}) {
		t.Fatal("first admission was rejected")
	}

	// Admitted 100 seconds later, so it outlives the first by that much.
	now = now.Add(100 * time.Second)
	late := newDenialProofNSECFixture(
		t, now, "b.example.", dns.TypeA, dns.RcodeNameError, "example.",
		[2]string{"b.example.", "bz.example."},
	)
	if !cache.record(late.msg, "example.", time.Time{}) {
		t.Fatal("second admission was rejected")
	}

	snapshot := denialProofOnlySnapshot(t, cache)
	publishedLen := len(snapshot.nsecPrepared)
	if len(snapshot.nsec) != 2 || publishedLen != 2 {
		t.Fatalf("published %d entries / %d prepared, want 2 / 2",
			len(snapshot.nsec), publishedLen)
	}

	// Past the first entry's expiry, short of the second's.
	live, prepared := denialProofLivePreparedNSEC(
		snapshot.nsec,
		snapshot.nsecPrepared,
		now.Add(250*time.Second),
	)
	if len(live) != 1 || len(prepared) != 1 {
		t.Fatalf("live = %d entries / %d prepared, want 1 / 1",
			len(live), len(prepared))
	}
	if owner := live[0].data[0].Header().Name; owner != "b.example." {
		t.Fatalf("surviving entry = %q, want the later one", owner)
	}
	if len(snapshot.nsecPrepared) != publishedLen {
		t.Fatal("filtering an expired entry disturbed the published set")
	}
}

// TestDenialProofAncestorsMatchesSplit pins the ancestor walk to the
// dns.Split-based list it replaced, including the shapes where they could
// differ: the root, a single label, and escaped separators.
func TestDenialProofAncestorsMatchesSplit(t *testing.T) {
	reference := func(name string) []string {
		if name == "." {
			return []string{"."}
		}
		var result []string
		for _, offset := range dns.Split(name) {
			result = append(result, name[offset:])
		}
		return append(result, ".")
	}

	for _, name := range []string{
		".",
		"com.",
		"example.com.",
		"a.b.example.com.",
		`a\.b.example.com.`,
	} {
		want := reference(name)
		got := denialProofAncestors(name, nil)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ancestors of %q = %v, want %v", name, got, want)
		}
	}
}

// TestDenialProofAncestorsUsesCallerStorage pins that the walk allocates
// nothing when the caller's buffer is large enough. Every lookup makes this
// call, which is why the list is not built freshly each time.
func TestDenialProofAncestorsUsesCallerStorage(t *testing.T) {
	var storage [12]string
	allocs := testing.AllocsPerRun(200, func() {
		if got := denialProofAncestors("a.b.example.com.", storage[:0]); len(got) != 5 {
			t.Fatalf("ancestors = %d entries, want 5", len(got))
		}
	})
	if allocs != 0 {
		t.Fatalf("ancestor walk allocated %.1f times per call, want 0", allocs)
	}
}

// TestDenialProofLookupRetiresExpiredEntry pins that a lookup which passes
// over an expired entry retires it. Nothing else would: the entry is never
// re-queried, so it would sit in the zone's published view and be filtered
// out again by every later lookup, permanently defeating the fast path.
func TestDenialProofLookupRetiresExpiredEntry(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	admit := func(label string) {
		t.Helper()
		owner, next := label+".example.", label+"z.example."
		fixture := newDenialProofNSECFixture(
			t, now, owner, dns.TypeA, dns.RcodeNameError, "example.",
			[2]string{owner, next},
		)
		if !cache.record(fixture.msg, "example.", time.Time{}) {
			t.Fatalf("admission of %s was rejected", owner)
		}
	}

	admit("a")
	now = now.Add(100 * time.Second) // the later entry outlives the first
	admit("b")

	if got := cache.len(); got != 3 {
		t.Fatalf("cached entries = %d, want 3 (SOA and two NSEC)", got)
	}

	// Past the first entry's expiry, short of the second's and the SOA's.
	now = now.Add(250 * time.Second)
	cache.Lookup(denialProofTestRequest("q.example.", dns.TypeA, true), nil)

	if got := cache.len(); got != 2 {
		t.Fatalf("cached entries after the lookup = %d, want 2 — the expired "+
			"entry was filtered but never retired", got)
	}

	snapshot := denialProofOnlySnapshot(t, cache)
	if len(snapshot.nsec) != 1 || len(snapshot.nsecPrepared) != 1 {
		t.Fatalf("republished zone holds %d entries / %d prepared, want 1 / 1",
			len(snapshot.nsec), len(snapshot.nsecPrepared))
	}
	if owner := snapshot.nsec[0].data[0].Header().Name; owner != "b.example." {
		t.Fatalf("surviving entry = %q, want the later one", owner)
	}

	// With the stale entry gone the zone is back on the fast path.
	live, prepared := denialProofLivePreparedNSEC(
		snapshot.nsec,
		snapshot.nsecPrepared,
		now,
	)
	if &live[0] != &snapshot.nsec[0] || &prepared[0] != &snapshot.nsecPrepared[0] {
		t.Fatal("the pruned zone still rebuilds its prepared set per lookup")
	}
}

// TestDenialProofLookupRetiresExpiredZone covers the whole-zone case: once the
// SOA has expired the zone cannot answer anything, so it should not keep
// occupying the cache.
func TestDenialProofLookupRetiresExpiredZone(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	fixture := newDenialProofNSECFixture(
		t, now, "a.example.", dns.TypeA, dns.RcodeNameError, "example.",
		[2]string{"a.example.", "az.example."},
	)
	if !cache.record(fixture.msg, "example.", time.Time{}) {
		t.Fatal("admission was rejected")
	}

	now = now.Add(400 * time.Second) // past every record's TTL
	cache.Lookup(denialProofTestRequest("q.example.", dns.TypeA, true), nil)

	if got := cache.len(); got != 0 {
		t.Fatalf("cached entries = %d, want 0 — an expired zone was retained", got)
	}
	if len(cache.zoneIndex) != 0 || len(cache.zoneEntries) != 0 {
		t.Fatalf("zones left behind: %d published, %d writer-side",
			len(cache.zoneIndex), len(cache.zoneEntries))
	}
}

// BenchmarkDenialProofStaleZoneLookup measures repeated lookups against a zone
// that holds one expired entry among many live ones — the shape a resolver
// settles into, since a proof no one re-queries is never replaced.
func BenchmarkDenialProofStaleZoneLookup(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	cache := newDenialProofTestCache(&now, 4096, 512, time.Hour)

	const zone = "bl.example."
	admit := func(index int) {
		owner := fmt.Sprintf("h%03d.%s", index, zone)
		fixture := newDenialProofNSECFixture(
			b, now, owner, dns.TypeA, dns.RcodeNameError, zone,
			[2]string{owner, fmt.Sprintf("h%03dz.%s", index, zone)},
		)
		if !cache.record(fixture.msg, zone, time.Time{}) {
			b.Fatalf("admission %d rejected", index)
		}
	}

	admit(0)
	now = now.Add(100 * time.Second) // everything below outlives entry 0
	for i := 1; i < 200; i++ {
		admit(i)
	}
	now = now.Add(250 * time.Second) // entry 0 has expired, the rest have not

	req := denialProofTestRequest("q000."+zone, dns.TypeA, true)

	b.ReportAllocs()
	for b.Loop() {
		cache.Lookup(req, nil)
	}
}

// TestDenialProofLookupRetiresZoneWhenSOAExpiresFirst covers the case where
// the SOA is shorter-lived than the proofs beneath it, which a server can
// cause at any time by lowering its negative TTL. Retiring only the expired
// entries would leave the zone published without a SOA — unable to answer,
// and invisible to every later lookup, which stops evaluating at the missing
// SOA and so never notices the remaining proofs expiring either.
func TestDenialProofLookupRetiresZoneWhenSOAExpiresFirst(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	long := newDenialProofNSECFixture(
		t, now, "a.example.", dns.TypeA, dns.RcodeNameError, "example.",
		[2]string{"a.example.", "az.example."},
	)
	if !cache.record(long.msg, "example.", time.Time{}) {
		t.Fatal("first admission was rejected")
	}

	// A second proof carrying a much shorter SOA. Only the SOA entry is
	// replaced; the NSEC admitted above keeps its own longer lifetime.
	now = now.Add(50 * time.Second)
	short := newDenialProofNSECFixture(
		t, now, "b.example.", dns.TypeA, dns.RcodeNameError, "example.",
		[2]string{"b.example.", "bz.example."},
	)
	short.soa.Hdr.Ttl = 30
	short.soa.Minttl = 30
	short.soaSig.Hdr.Ttl = 30
	short.soaSig.OrigTtl = 30
	if !cache.record(short.msg, "example.", time.Time{}) {
		t.Fatal("second admission was rejected")
	}

	snapshot := denialProofOnlySnapshot(t, cache)
	if got := cache.len(); got != 3 {
		t.Fatalf("cached entries = %d, want 3 (SOA and two NSEC)", got)
	}
	outlives := 0
	for _, entry := range snapshot.nsec {
		if snapshot.soa.expires.Before(entry.expires) {
			outlives++
		}
	}
	if outlives == 0 {
		t.Fatalf("fixture is wrong: no proof outlives the SOA, which expires at %v",
			snapshot.soa.expires)
	}

	// Past the SOA, short of every proof.
	now = now.Add(100 * time.Second)
	cache.Lookup(denialProofTestRequest("q.example.", dns.TypeA, true), nil)

	if got := cache.len(); got != 0 {
		t.Fatalf("cached entries = %d, want 0 — the zone outlived its SOA", got)
	}
	if len(cache.zoneIndex) != 0 || len(cache.zoneEntries) != 0 {
		t.Fatalf("zones left behind: %d published, %d writer-side",
			len(cache.zoneIndex), len(cache.zoneEntries))
	}
}
