package resolver

import (
	"hash/maphash"
	"sync/atomic"
)

// zoneInflightBuckets is the size of the per-zone in-flight table. Zones
// hash into a fixed bucket array — no locks, no allocation, no cleanup.
// Two zones sharing a bucket share a quota; with in-flight lookups bounded
// by resolutionSlots (≤ a few thousand) collisions are rare and the only
// consequence is a slightly stricter shared limit.
const zoneInflightBuckets = 4096

// zoneInflightLimiter bounds concurrent zone-level lookups PER ZONE — the
// destination-fairness layer of the outage defenses (the analog of BIND's
// fetches-per-zone). The global resolutionSlots pool bounds the aggregate,
// but it is blind to who consumes it: one popular destination going dark
// (say, a cloud provider's authority set) would otherwise pin slots at
// arrival-rate × timeout and shed HEALTHY destinations along with the dead
// one. With a per-zone quota, a hanging zone can never occupy more than its
// slice, no matter how popular it is — resolution for everyone else keeps
// flowing at full speed through every phase of the incident, including the
// window before per-server circuit breakers open.
type zoneInflightLimiter struct {
	seed    maphash.Seed
	perZone int32
	buckets [zoneInflightBuckets]atomic.Int32
}

func newZoneInflightLimiter(perZone int) *zoneInflightLimiter {
	return &zoneInflightLimiter{
		seed:    maphash.MakeSeed(),
		perZone: int32(min(perZone, 1<<30)), //nolint:gosec // G115 - bounded above
	}
}

// acquire reserves one in-flight lookup for zone. It never blocks: it
// either takes the reservation or reports the zone's quota exhausted.
func (l *zoneInflightLimiter) acquire(zone string) (release func(), ok bool) {
	bucket := &l.buckets[maphash.String(l.seed, zone)%zoneInflightBuckets]
	if bucket.Add(1) > l.perZone {
		bucket.Add(-1)
		return nil, false
	}
	return func() { bucket.Add(-1) }, true
}
