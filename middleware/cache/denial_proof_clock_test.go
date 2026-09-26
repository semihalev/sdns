package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

const clockProofZone = "sig.test."

// clockProofCache is a cache holding one validated NSEC proof for
// clockProofZone, admitted under inherited, whose sets cover the wildcard
// and every name from m to z. A non-zero stepped then replaces every set's
// deadlines, its monotonic one as the cache's TTL deadline and its wall
// clock one as the calendar instant: the state a clock step leaves behind.
func clockProofCache(t *testing.T, inherited, stepped lease.Lease) *Cache {
	t.Helper()
	c := New(&config.Config{CacheSize: 1024, Expire: 300})
	t.Cleanup(c.Stop)
	fixture := newDenialProofNSECFixture(
		t, time.Now().UTC(), "n."+clockProofZone, dns.TypeA, dns.RcodeNameError, clockProofZone,
		[2]string{clockProofZone, "a." + clockProofZone},
		[2]string{"m." + clockProofZone, "z." + clockProofZone},
	)
	aggressiveNegativeMakeSignaturesPackable(fixture.msg)
	if !c.store.recordDenialProof(fixture.msg, clockProofZone, middleware.ValidatedNegativeProofNSEC, inherited) {
		t.Fatal("valid proof was not admitted")
	}
	if !stepped.IsZero() {
		proofs := c.store.denialProofs
		proofs.mu.Lock()
		for _, entry := range proofs.byID {
			entry.expires, entry.wallExpires = stepped.Mono().Until, stepped.Wall().Until
		}
		proofs.mu.Unlock()
	}
	return c
}

// proofServePaths are the ways a proof answers a covered name: the Msg path
// and the store's resolver-facing lookup. A wire-born question is answered
// by the Msg path, so it takes the first. Each reports whether the proof
// served, and the lease the request tree was bound to.
var proofServePaths = []struct {
	name  string
	serve func(t *testing.T, c *Cache) (bool, lease.Lease)
}{
	{"msg", func(t *testing.T, c *Cache) (bool, lease.Lease) {
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)
		reached := false
		downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			reached = true
			resp := new(dns.Msg)
			resp.SetRcode(ch.Request.Msg(), dns.RcodeServerFailure)
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
		})
		w := mock.NewWriter("udp", "192.0.2.9:53000")
		ch := middleware.NewChain([]middleware.Handler{c, downstream})
		ch.Reset(w, denialProofTestRequest("other."+clockProofZone, dns.TypeA, true))
		ch.Next(ctx)
		return !reached && w.Msg().Rcode == dns.RcodeNameError, meta.Cut()
	}},
	{"store", func(_ *testing.T, c *Cache) (bool, lease.Lease) {
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)
		resp, ok := c.store.GetWithContext(ctx, denialProofTestRequest("other."+clockProofZone, dns.TypeA, true))
		return ok && resp.Rcode == dns.RcodeNameError, meta.Cut()
	}},
}

// A proof set keeps a wall-clock deadline beside its monotonic one: its
// signatures' expiration as the calendar instant it is, or an inherited
// wall-clock lease when that ends first.
func TestDenialProofKeepsItsSignatureExpirationOnTheWallClock(t *testing.T) {
	now := time.Now()
	inheritedWall := wallOnly(now.Add(30 * time.Second))
	for _, tc := range []struct {
		name           string
		inherited      lease.Lease
		inheritedFirst bool
	}{
		{"no lease", lease.Lease{}, false},
		{"monotonic lease", lease.Of(now.Add(time.Minute), 1), false},
		{"wall-clock lease ending first", lease.Of(inheritedWall, 2), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proofs := clockProofCache(t, tc.inherited, lease.Lease{}).store.denialProofs
			proofs.mu.RLock()
			defer proofs.mu.RUnlock()
			if len(proofs.byID) == 0 {
				t.Fatal("no proof sets retained")
			}
			for id, entry := range proofs.byID {
				// The expected expiration is read off the records the set
				// admitted; the SOA's signature bounds every set with it.
				var want time.Time
				for _, set := range []*denialProofEntry{proofs.zoneIndex[entry.zoneKey].soa, entry} {
					for _, rr := range set.records {
						if sig, ok := rr.(*dns.RRSIG); ok {
							if at := time.Unix(int64(sig.Expiration), 0); want.IsZero() || at.Before(want) {
								want = at
							}
						}
					}
				}
				if tc.inheritedFirst {
					if !inheritedWall.Before(want) {
						t.Fatalf("bad fixture: the inherited lease %v does not end before the signatures %v", inheritedWall, want)
					}
					want = inheritedWall
				}
				if !entry.wallExpires.Equal(want) || lease.Monotonic(entry.wallExpires) {
					t.Fatalf("set %v wall-clock deadline %v, want the calendar instant %v", id.owner, entry.wallExpires, want)
				}
				if left := time.Until(entry.expires); left <= 0 || left > 300*time.Second {
					t.Fatalf("set %v monotonic lifetime %v, want the proof TTL cap kept", id.owner, left)
				}
			}
		})
	}
}

// Every path a proof serves by hands the request tree the proof's deadline
// on both clocks, so an answer derived from it ends with the proof however
// the wall clock moves afterwards.
func TestDenialProofHitCarriesBothClocks(t *testing.T) {
	for _, path := range proofServePaths {
		t.Run(path.name, func(t *testing.T) {
			now := time.Now()
			wall := wallOnly(now.Add(30 * time.Second))
			c := clockProofCache(t, lease.Of(now.Add(time.Minute), 1).Min(lease.Of(wall, 2)), lease.Lease{})

			served, bound := path.serve(t, c)
			if !served {
				t.Fatal("the proof did not serve a covered name")
			}
			if left := time.Until(bound.Mono().Until); left <= 0 || left > time.Minute {
				t.Fatalf("request tree bound to %v on the monotonic clock, want within the lease", left)
			}
			if !bound.Wall().Until.Equal(wall) {
				t.Fatalf("request tree bound to %v on the wall clock, want the lease's %v", bound.Wall().Until, wall)
			}

			admit := time.Now()
			derived := newCacheEntryAt(snapAnswer("derived.test.", 3600, "192.0.2.2"), time.Hour, 0, 0, admit)
			derived.setLease(bound)
			if derived.remaining(clockAfter(t, admit, time.Second, time.Second)) <= 0 {
				t.Fatal("bad fixture: the derived answer is dead with both clocks steady")
			}
			if left := derived.remaining(clockAfter(t, admit, time.Second, 31*time.Second)); left > 0 {
				t.Fatalf("wall clock jumped past the proof: the derived answer has %v left", left)
			}
			if left := derived.remaining(clockAfter(t, admit, 61*time.Second, 0)); left > 0 {
				t.Fatalf("wall clock held back past the proof's monotonic deadline: the derived answer has %v left", left)
			}
		})
	}
}

// A proof whose deadline has passed on either clock serves on no path,
// while the other clock still has time left.
func TestDenialProofNotServedPastEitherClock(t *testing.T) {
	now := time.Now()
	for _, step := range []struct {
		name string
		l    lease.Lease
	}{
		{"wall clock stepped past the wall-clock deadline",
			lease.Of(now.Add(time.Minute), 0).Min(lease.Of(wallOnly(now.Add(-time.Second)), 0))},
		{"monotonic deadline passed, wall clock stepped back",
			lease.Of(now.Add(-time.Second), 0).Min(lease.Of(wallOnly(now.Add(time.Hour)), 0))},
	} {
		for _, path := range proofServePaths {
			t.Run(step.name+"/"+path.name, func(t *testing.T) {
				c := clockProofCache(t, lease.Lease{}, step.l)
				if served, _ := path.serve(t, c); served {
					t.Fatal("an expired proof served")
				}
			})
		}
	}
}

// Admitting a proof under a wall-clock lease publishes the zone like any
// admission, so a failure's miss witness recorded before it stops holding:
// the wire path must not serve a failure the new proof may now deny.
func TestWallClockProofAdmissionBreaksTheMissWitness(t *testing.T) {
	c := New(makeTestConfig())
	defer c.Stop()
	s := c.store

	witnessTestProof(t, s, clockProofZone, "b."+clockProofZone, "c."+clockProofZone)
	witness := s.failureMissWitness("down."+clockProofZone, dns.ClassINET)
	onPath, _ := wireTestRequest(t, "down."+clockProofZone, dns.TypeA, false)
	if !s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, witness) {
		t.Fatal("precondition: the fresh witness does not hold")
	}

	fixture := newDenialProofNSECFixture(
		t, time.Now().UTC(), "n."+clockProofZone, dns.TypeA, dns.RcodeNameError, clockProofZone,
		[2]string{"m." + clockProofZone, "z." + clockProofZone},
	)
	aggressiveNegativeMakeSignaturesPackable(fixture.msg)
	now := time.Now()
	if !s.recordDenialProof(fixture.msg, clockProofZone, middleware.ValidatedNegativeProofNSEC,
		lease.Of(now.Add(time.Minute), 1).Min(lease.Of(wallOnly(now.Add(30*time.Second)), 2))) {
		t.Fatal("a proof under a wall-clock lease was not admitted")
	}
	if s.denialProofs.missWitnessHoldsWire(onPath.WireName(), dns.ClassINET, witness) {
		t.Fatal("the witness held across an admission under a wall-clock lease")
	}
}

// A retained NSEC3 set whose wall-clock deadline has passed is no longer an
// observation: a different set at the same owner that follows it is a
// renewal and replaces it whole, not a conflict to quarantine. The
// quarantine itself stays on the monotonic clock.
func TestNSEC3SetPastItsWallClockDeadlineIsReplacedNotConflicted(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSEC3Fixture(t, now, "renewed."+p6NSEC3Zone, p6NSEC3Zone, "", 0, 0)
	cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
	if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
		t.Fatal("initial NSEC3 owner was not admitted")
	}

	renewed := fixture.msg.Copy()
	for _, rr := range renewed.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3.NextDomain = p6AdjacentNSEC3Hash(t, dns.SplitDomainName(nsec3.Hdr.Name)[0], 1)
		}
	}

	// The wall clock has stepped past the retained set's calendar deadline,
	// while its TTL has time left.
	cache.mu.Lock()
	for _, entry := range cache.byID {
		if entry.id.kind == denialProofNSEC3 {
			entry.wallExpires = now.Add(-time.Second)
		}
	}
	cache.mu.Unlock()

	if !cache.record(renewed, p6NSEC3Zone, time.Time{}) {
		t.Fatal("a set following one past its wall-clock deadline was refused as a conflict")
	}
	cache.mu.RLock()
	conflicts := len(cache.nsec3Conflicts)
	cache.mu.RUnlock()
	if conflicts != 0 {
		t.Fatalf("%d conflict tombstones, want the renewal to leave none", conflicts)
	}
}
