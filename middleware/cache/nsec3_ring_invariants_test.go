package cache

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

func TestP6NSEC3CrossAdmissionOwnerConflictFailsOpen(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSEC3Fixture(
		t,
		now,
		"owner-conflict."+p6NSEC3Zone,
		p6NSEC3Zone,
		"",
		0,
		0,
	)
	cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
	if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
		t.Fatal("initial NSEC3 owner was not admitted")
	}

	conflicting := fixture.msg.Copy()
	var ownerHash string
	for _, rr := range conflicting.Ns {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		ownerHash = dns.SplitDomainName(nsec3.Hdr.Name)[0]
		nsec3.NextDomain = p6AdjacentNSEC3Hash(t, ownerHash, 1)
	}
	if ownerHash == "" {
		t.Fatal("fixture has no NSEC3 record")
	}
	if cache.record(conflicting, p6NSEC3Zone, time.Time{}) {
		t.Fatal("conflicting RDATA for a retained NSEC3 owner was admitted")
	}

	// Once a locally validated admission reveals two different RRsets for the
	// same tuple and owner hash, the tuple is ambiguous. Retaining either
	// historical version would turn a detected collision into synthesis.
	work := &p6NSEC3Work{limit: 8}
	req := denialProofTestRequest("owner-conflict."+p6NSEC3Zone, dns.TypeAAAA, true)
	if got, ok := cache.Lookup(req, work); ok || got != nil {
		t.Fatalf("detected cross-admission owner conflict still synthesized: %#v", got)
	}
	if cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
		t.Fatal("original variant immediately repopulated a quarantined tuple")
	}
	if cache.record(conflicting, p6NSEC3Zone, time.Time{}) {
		t.Fatal("conflicting variant immediately repopulated a quarantined tuple")
	}

	// Both observations carry a 300-second authenticated lifetime. Once that
	// ambiguity window closes, a freshly validated single variant can seed a
	// new generation.
	now = now.Add(301 * time.Second)
	if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
		t.Fatal("expired conflict quarantine did not allow a fresh generation")
	}
}

func TestP6NSEC3ConflictQuarantineIsBounded(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 2, 2, maxDenialProofTTL)
	expires := now.Add(time.Minute)
	params := denialProofNSEC3Params{hash: dns.SHA1}
	keys := []denialProofNSEC3ConflictKey{
		{zone: denialProofZoneKey{zone: "a.example.", qclass: dns.ClassINET}, params: params},
		{zone: denialProofZoneKey{zone: "b.example.", qclass: dns.ClassINET}, params: params},
		{zone: denialProofZoneKey{zone: "c.example.", qclass: dns.ClassINET}, params: params},
	}

	cache.mu.Lock()
	for _, key := range keys {
		cache.recordNSEC3ConflictLocked(key, expires, now)
	}
	if got := len(cache.nsec3Conflicts); got != cache.maxEntries {
		cache.mu.Unlock()
		t.Fatalf("conflict tombstones = %d, want bounded at %d",
			got, cache.maxEntries)
	}
	if !cache.nsec3ConflictActiveLocked(keys[2], now) {
		cache.mu.Unlock()
		t.Fatal("overflow did not activate the global fail-open backstop")
	}
	cache.mu.Unlock()

	now = expires.Add(time.Second)
	cache.mu.Lock()
	cache.pruneNSEC3ConflictsLocked(now)
	if len(cache.nsec3Conflicts) != 0 ||
		!cache.nsec3ConflictOverflowUntil.IsZero() {
		cache.mu.Unlock()
		t.Fatal("expired conflict quarantine did not release bounded state")
	}
	cache.mu.Unlock()
}

func TestP6NSEC3TwoParameterGroupRolloverAndIsolation(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
	type group struct {
		name string
		salt string
	}
	groups := []group{
		{name: "first." + p6NSEC3Zone, salt: "AA"},
		{name: "second." + p6NSEC3Zone, salt: "BB"},
		{name: "third." + p6NSEC3Zone, salt: "CC"},
	}

	for index, group := range groups {
		fixture := newDenialProofNSEC3Fixture(
			t,
			now,
			group.name,
			p6NSEC3Zone,
			group.salt,
			0,
			0,
		)
		if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
			t.Fatalf("group %s was not admitted", group.salt)
		}

		key := denialProofZoneKey{zone: p6NSEC3Zone, qclass: dns.ClassINET}
		cache.mu.RLock()
		snapshot := cache.zoneIndex[key]
		retained := make(map[string]struct{}, len(snapshot.nsec3))
		for params := range snapshot.nsec3 {
			retained[params.salt] = struct{}{}
		}
		cache.mu.RUnlock()

		want := map[string]struct{}{"AA": {}}
		switch index {
		case 1:
			want["BB"] = struct{}{}
		case 2:
			want = map[string]struct{}{"BB": {}, "CC": {}}
		}
		if !maps.Equal(retained, want) {
			t.Fatalf("groups after admission %s = %v, want %v", group.salt, retained, want)
		}
	}

	for index, group := range groups {
		work := &p6NSEC3Work{limit: 32}
		got, ok := cache.Lookup(
			denialProofTestRequest(group.name, dns.TypeAAAA, true),
			work,
		)
		if index == 0 {
			if ok || got != nil {
				t.Fatalf("rolled-over group %s still synthesized: %#v", group.salt, got)
			}
			continue
		}
		if !ok || got == nil || got.Rcode != dns.RcodeSuccess {
			t.Fatalf("retained isolated group %s missed: response=%#v hit=%v",
				group.salt,
				got,
				ok,
			)
		}
	}
}

func TestP6NSEC3UnusableRecordAdmissionDoesNoHashWork(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*dns.NSEC3)
	}{
		{
			name: "undefined flags",
			mutate: func(nsec3 *dns.NSEC3) {
				nsec3.Flags = 2
			},
		},
		{
			name: "unknown algorithm",
			mutate: func(nsec3 *dns.NSEC3) {
				nsec3.Hash = 2
			},
		},
		{
			name: "iteration cap exceeded",
			mutate: func(nsec3 *dns.NSEC3) {
				nsec3.Iterations = 151
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
			fixture := newDenialProofNSEC3Fixture(
				t,
				now,
				"unusable."+p6NSEC3Zone,
				p6NSEC3Zone,
				"",
				0,
				0,
			)
			for _, rr := range fixture.msg.Ns {
				if nsec3, ok := rr.(*dns.NSEC3); ok {
					test.mutate(nsec3)
				}
			}

			cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
			if cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
				t.Fatal("unusable NSEC3 record was admitted")
			}

			work := &p6NSEC3Work{limit: 8}
			got, ok := cache.Lookup(
				denialProofTestRequest("unusable."+p6NSEC3Zone, dns.TypeAAAA, true),
				work,
			)
			if ok || got != nil {
				t.Fatalf("unusable NSEC3 record synthesized: %#v", got)
			}
			if work.attempts != 0 || work.calls != 0 {
				t.Fatalf("unusable NSEC3 record consumed hash work: attempts=%d calls=%d",
					work.attempts,
					work.calls,
				)
			}
		})
	}
}

func TestP6NSEC3OverlappingIntervalsAreAmbiguous(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
	cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
	if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
		t.Fatal("initial complete NSEC3 proof was not admitted")
	}

	qnameHash := dns.HashName(p6NSEC3Denied, dns.SHA1, 0, "")
	lower := p6AdjacentNSEC3Hash(t, qnameHash, -1)
	upper := p6AdjacentNSEC3Hash(t, qnameHash, 1)
	overlap := p6NSEC3Record(
		p6NSEC3Zone,
		p6AdjacentNSEC3Hash(t, lower, -1),
		p6AdjacentNSEC3Hash(t, upper, 1),
		0,
		[]uint16{dns.TypeRRSIG, dns.TypeNSEC3},
	)
	expiration := uint32(now.Add(2 * time.Hour).Unix()) //nolint:gosec // fixed DNSSEC test epoch
	overlapSig := p6PackableSignature(
		overlap.Hdr.Name,
		dns.TypeNSEC3,
		p6NSEC3Zone,
		expiration,
	)
	second := fixture.msg.Copy()
	second.Ns = []dns.RR{
		dns.Copy(fixture.soa),
		dns.Copy(fixture.soaSig),
		overlap,
		overlapSig,
	}
	if !cache.record(second, p6NSEC3Zone, time.Time{}) {
		t.Fatal("independently valid overlapping interval was not retained")
	}

	work := &p6NSEC3Work{limit: 8}
	got, ok := cache.Lookup(
		denialProofTestRequest(p6NSEC3Denied, dns.TypeA, true),
		work,
	)
	if ok || got != nil {
		t.Fatalf("overlapping NSEC3 intervals synthesized: %#v", got)
	}
	if work.attempts != 1 {
		t.Fatalf("ambiguous interval detection used %d hashes, want one qname preflight",
			work.attempts,
		)
	}
}

func TestP6NSEC3ForwarderConfigDisablesAdmissionAndLookup(t *testing.T) {
	cache := New(&config.Config{
		CacheSize:        1024,
		Expire:           300,
		DNSSEC:           "on",
		ForwarderServers: []string{"192.0.2.53:53"},
	})
	defer cache.Stop()

	now := time.Now().UTC()
	fixture := newDenialProofNSEC3Fixture(
		t,
		now,
		"forwarder-config."+p6NSEC3Zone,
		p6NSEC3Zone,
		"",
		0,
		0,
	)
	if cache.store.RecordDenialProof(
		fixture.msg,
		p6NSEC3Zone,
		middleware.ValidatedNegativeProofNSEC3,
		time.Time{},
	) {
		t.Fatal("forwarder-configured cache admitted shared NSEC3 proof state")
	}

	// Plant proof state below the Store policy seam so lookup is tested
	// independently of the admission rejection above.
	if !cache.store.denialProofs.record(
		fixture.msg,
		p6NSEC3Zone,
		time.Time{},
	) {
		t.Fatal("could not plant lower-level proof state for lookup bypass test")
	}
	work := &p6NSEC3Work{limit: 8}
	req := denialProofTestRequest(
		"forwarder-config."+p6NSEC3Zone,
		dns.TypeAAAA,
		true,
	)
	if got, kind, zone, ok := cache.store.LookupDenialProof(req, work); ok ||
		got != nil ||
		kind != middleware.ValidatedNegativeProofUnknown ||
		zone != "" {
		t.Fatalf("forwarder-configured lookup consumed shared proof: response=%#v kind=%d zone=%q hit=%v",
			got,
			kind,
			zone,
			ok,
		)
	}
	if work.attempts != 0 || work.calls != 0 {
		t.Fatalf("forwarder-configured lookup hashed: attempts=%d calls=%d",
			work.attempts,
			work.calls,
		)
	}
	if got, ok := cache.store.GetWithContext(context.Background(), req); ok || got != nil {
		t.Fatalf("Store.GetWithContext bypassed forwarder policy: %#v", got)
	}
}
