package cache

import (
	"github.com/miekg/dns"
	internalcache "github.com/semihalev/sdns/internal/cache"
)

// The miss witness: RFC 9520 failure state exists only because a real
// resolution was attempted, and the Msg ladder attempts resolution only
// after RFC 8198 aggressive denial missed, so at the moment a failure is
// recorded, denial provably does not apply to that name. The witness
// captures that proof as the (zone hash, snapshot pointer) pairs of every
// cached denial zone on the name's ancestor path. The wire path may serve
// the failure without materializing exactly while the witness still
// holds: every denial zone on the lookup name's path is pointer-identical
// to what the record saw. A replaced snapshot, a newly admitted zone, or
// a missing witness sends the query to the Msg path, which re-evaluates,
// the answer a client receives is therefore identical on both paths by
// construction; only where it is composed differs.
//
// The RFC grounding, for the reviewer: RFC 8198 is SHOULD-level and its
// Appendix B discards parent-zone NSECs below a delegation, so aggressive
// denial for a name is answerable only from the name's cached ancestor
// zones, the exact set the witness pins. RFC 9520 §3.2 constrains
// outgoing queries, not cache-lookup order, and leaves precedence between
// failure state and other cached data open.

// denialZoneHashSalt separates the denial cache's private wire index from
// every other user of the canonical question hash.
const denialZoneHashSalt = 0x8198f00dd1a70b3c

// denialZoneHash is the canonical hash of a denial zone identity,
// bit-identical whether computed from the presentation name (publish
// time) or wire bytes (lookup time, via KeyWire with a zero qtype).
func denialZoneHash(zone string, qclass uint16) uint64 {
	q := dns.Question{Name: zone, Qtype: 0, Qclass: qclass}
	return internalcache.Key(q, false) ^ denialZoneHashSalt
}

// denialWitnessPair is one cached denial zone as the failure record saw
// it. The pointer is compared for identity only, never dereferenced,
// the snapshot's content is irrelevant, its replacement is the signal.
type denialWitnessPair struct {
	hash     uint64
	zone     string
	snapshot *denialProofZoneSnapshot
}

// missWitness captures the denial zones on qname's ancestor path the
// moment the denial rung misses. A nil result means no on-path zone was
// cached, a state the wire gate can re-establish for itself at lookup
// time, so nil is not a weaker witness, just a cheaper one.
//
// A path that crosses a zone holding NSEC3 state yields no witness at
// all: NSEC3 evaluation draws on the shared DNSSEC crypto budget, so its
// miss can be starvation rather than absence, and a witness must never
// freeze a starved verdict into servable state. NSEC evaluation takes no
// budget; only NSEC-backed paths are witnessable.
func (c *denialProofCache) missWitness(qname string, qclass uint16) []denialWitnessPair {
	if c == nil {
		return nil
	}
	var ancestorStorage [12]string
	var witness []denialWitnessPair
	c.mu.RLock()
	if !c.stopped && len(c.zoneIndex) > 0 {
		for _, zone := range denialProofAncestors(qname, ancestorStorage[:0]) {
			key := denialProofZoneKey{zone: zone, qclass: qclass}
			snapshot := c.zoneIndex[key]
			if snapshot == nil {
				continue
			}
			if len(snapshot.nsec3) > 0 {
				witness = nil
				break
			}
			witness = append(witness, denialWitnessPair{
				hash:     denialZoneHash(zone, qclass),
				zone:     zone,
				snapshot: snapshot,
			})
		}
	}
	c.mu.RUnlock()
	return witness
}

// missWitnessHoldsWire reports whether aggressive denial still provably
// misses the wire-born name: every cached denial zone on its suffix path
// must be pointer-identical to the witness. No on-path zones at all is a
// hold with any witness, the empty one included, with no candidate
// zones, the Msg evaluator has nothing to evaluate.
func (c *denialProofCache) missWitnessHoldsWire(
	name []byte,
	qclass uint16,
	witness []denialWitnessPair,
) bool {
	if c == nil {
		return true
	}
	holds := true
	c.mu.RLock()
	if c.stopped {
		c.mu.RUnlock()
		return false
	}
	if len(c.zoneWireIndex) > 0 {
		walkWireSuffixes(name, func(zone []byte) bool {
			hash, ok := internalcache.KeyWire(zone, 0, qclass, false)
			if !ok {
				holds = false
				return false
			}
			snapshot := c.zoneWireIndex[hash^denialZoneHashSalt]
			if snapshot == nil {
				return true
			}
			for _, w := range witness {
				if w.hash == hash^denialZoneHashSalt && w.snapshot == snapshot &&
					internalcache.WireNameEqualsPresentation(zone, w.zone) {
					return true
				}
			}
			holds = false
			return false
		})
	}
	c.mu.RUnlock()
	return holds
}
