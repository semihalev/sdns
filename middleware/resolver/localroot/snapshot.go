// Package localroot maintains a local, verified copy of the root zone (RFC
// 8806) and answers the three questions the resolver's walk would otherwise
// ask a root server: where a TLD's delegation lives, whether a TLD's DS
// exists, and the signed proof that a TLD does not exist.
//
// A copy is only ever served after ZONEMD verification (RFC 8976) chained to
// the resolver's root trust anchors; refresh follows the zone's own SOA
// schedule; and a copy past its SOA expire is withdrawn, returning the walk
// to the real root servers.
package localroot

import (
	"sort"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
)

// Snapshot is one immutable, verified copy of the root zone, indexed for the
// three lookups the resolver makes. It is built once and never mutated; the
// manager publishes it with an atomic pointer swap.
type Snapshot struct {
	serial   uint32
	loaded   time.Time
	expireAt time.Time

	soa    *dns.SOA
	soaSig []dns.RR // RRSIG(SOA) at the apex

	// apexNSEC proves the root's own types and, because "*" sorts before
	// every TLD, doubles as the wildcard-denial proof for any NXDOMAIN.
	apexNSEC    *dns.NSEC
	apexNSECSig []dns.RR

	// owners groups every record in the zone by canonical owner and type.
	// TLD lookups, DS answers and glue collection all read from it.
	owners map[string]map[uint16][]dns.RR

	// nsecOwners is every NSEC owner in canonical order, for the covering
	// search behind NXDOMAIN synthesis.
	nsecOwners []string
}

// Serial returns the copy's SOA serial.
func (s *Snapshot) Serial() uint32 { return s.serial }

// Loaded returns when this copy was transferred.
func (s *Snapshot) Loaded() time.Time { return s.loaded }

// Expired reports whether the copy has outlived its SOA expire interval and
// must no longer be served (RFC 1035 secondary semantics).
func (s *Snapshot) Expired(now time.Time) bool { return now.After(s.expireAt) }

// SOA returns the apex SOA and its RRSIGs.
func (s *Snapshot) SOA() (*dns.SOA, []dns.RR) { return s.soa, s.soaSig }

// Referral is the delegation material for one TLD: the NS set, the DS set
// (empty for an unsigned delegation), and the glue addresses for each NS
// target present in the zone.
type Referral struct {
	NS   []dns.RR
	DS   []dns.RR
	Glue map[string][]dns.RR // canonical NS host -> A/AAAA records
}

// Referral returns the delegation for tld (a canonical, rooted, one-label
// name) or ok=false when the zone holds no such delegation.
func (s *Snapshot) Referral(tld string) (Referral, bool) {
	sets, ok := s.owners[tld]
	if !ok {
		return Referral{}, false
	}
	ns := sets[dns.TypeNS]
	if len(ns) == 0 {
		return Referral{}, false
	}
	ref := Referral{NS: ns, DS: sets[dns.TypeDS], Glue: make(map[string][]dns.RR)}
	for _, rr := range ns {
		host := dns.CanonicalName(rr.(*dns.NS).Ns)
		if hostSets, ok := s.owners[host]; ok {
			glue := append([]dns.RR(nil), hostSets[dns.TypeA]...)
			glue = append(glue, hostSets[dns.TypeAAAA]...)
			if len(glue) > 0 {
				ref.Glue[host] = glue
			}
		}
	}
	return ref, true
}

// DSAnswer returns the material for an authoritative DS response at tld:
// the DS set with its RRSIGs when the delegation is signed, or the TLD's
// own NSEC with its RRSIGs as the exact-owner NODATA proof when it is not.
// ok=false when the TLD does not exist.
func (s *Snapshot) DSAnswer(tld string) (ds, dsSig []dns.RR, nsec, nsecSig []dns.RR, ok bool) {
	sets, exists := s.owners[tld]
	if !exists || len(sets[dns.TypeNS]) == 0 {
		return nil, nil, nil, nil, false
	}
	if len(sets[dns.TypeDS]) > 0 {
		return sets[dns.TypeDS], sigsCovering(sets[dns.TypeRRSIG], dns.TypeDS), nil, nil, true
	}
	nsecSet := sets[dns.TypeNSEC]
	if len(nsecSet) == 0 {
		return nil, nil, nil, nil, false
	}
	return nil, nil, nsecSet, sigsCovering(sets[dns.TypeRRSIG], dns.TypeNSEC), true
}

// Denial returns the NSEC records proving name does not exist under the
// root: the covering NSEC for the name and the apex NSEC as the wildcard
// proof (deduplicated when they are the same record), each with RRSIGs.
// ok=false when the chain cannot cover the name — a snapshot in that state
// is not usable for denial and the caller falls back.
func (s *Snapshot) Denial(name string) (proof []dns.RR, ok bool) {
	owner, found := s.coveringOwner(name)
	if !found {
		return nil, false
	}
	sets := s.owners[owner]
	covering := sets[dns.TypeNSEC]
	if len(covering) == 0 {
		return nil, false
	}
	proof = append(proof, covering...)
	proof = append(proof, sigsCovering(sets[dns.TypeRRSIG], dns.TypeNSEC)...)
	if owner != "." && s.apexNSEC != nil {
		proof = append(proof, s.apexNSEC)
		proof = append(proof, s.apexNSECSig...)
	}
	return proof, true
}

// coveringOwner finds the NSEC owner whose span covers name: the greatest
// owner canonically below it. The chain is circular, so a name below the
// first owner or past the last is covered by the last NSEC.
func (s *Snapshot) coveringOwner(name string) (string, bool) {
	if len(s.nsecOwners) == 0 {
		return "", false
	}
	// First owner canonically greater than name; the one before it covers.
	i := sort.Search(len(s.nsecOwners), func(i int) bool {
		return dnsname.CanonicalCompare(s.nsecOwners[i], name) > 0
	})
	if i == 0 {
		// Below the apex: nothing sorts before "."; not coverable.
		return "", false
	}
	owner := s.nsecOwners[i-1]
	if dnsname.CanonicalCompare(owner, name) == 0 {
		// The name exists; this is not a denial.
		return "", false
	}
	return owner, true
}

// sigsCovering filters an owner's RRSIGs to those covering one type.
func sigsCovering(sigs []dns.RR, covered uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covered {
			out = append(out, sig)
		}
	}
	return out
}

// buildSnapshot indexes a verified record set into a Snapshot. It assumes
// verify has already established the zone's integrity; structural gaps here
// (no SOA, no apex NSEC) still refuse, because a snapshot that cannot answer
// is worse than no snapshot.
func buildSnapshot(rrs []dns.RR, now time.Time) (*Snapshot, error) {
	s := &Snapshot{
		loaded: now,
		owners: make(map[string]map[uint16][]dns.RR),
	}

	for _, rr := range rrs {
		owner := dns.CanonicalName(rr.Header().Name)
		sets, ok := s.owners[owner]
		if !ok {
			sets = make(map[uint16][]dns.RR)
			s.owners[owner] = sets
		}
		t := rr.Header().Rrtype
		sets[t] = append(sets[t], rr)
	}

	apex, ok := s.owners["."]
	if !ok {
		return nil, errNoApex
	}
	soaSet := apex[dns.TypeSOA]
	if len(soaSet) != 1 {
		return nil, errNoApex
	}
	s.soa = soaSet[0].(*dns.SOA)
	s.serial = s.soa.Serial
	s.expireAt = now.Add(time.Duration(s.soa.Expire) * time.Second)
	s.soaSig = sigsCovering(apex[dns.TypeRRSIG], dns.TypeSOA)

	if nsecSet := apex[dns.TypeNSEC]; len(nsecSet) == 1 {
		s.apexNSEC = nsecSet[0].(*dns.NSEC)
		s.apexNSECSig = sigsCovering(apex[dns.TypeRRSIG], dns.TypeNSEC)
	}

	for owner, sets := range s.owners {
		if len(sets[dns.TypeNSEC]) > 0 {
			s.nsecOwners = append(s.nsecOwners, owner)
		}
	}
	sort.Slice(s.nsecOwners, func(i, j int) bool {
		return dnsname.CanonicalCompare(s.nsecOwners[i], s.nsecOwners[j]) < 0
	})

	return s, nil
}

// TLDOf returns the canonical last label of a rooted name, or "" for the
// root itself. The split is label-aware: an escaped dot inside a label
// ("a\.com.") must not masquerade as a boundary, or a hostile single-label
// name would borrow a real TLD's delegation path.
func TLDOf(name string) string {
	name = dns.CanonicalName(name)
	if name == "." {
		return ""
	}
	labels := dns.CountLabel(name)
	off, _ := dns.PrevLabel(name, 1)
	if labels < 1 || off >= len(name) {
		return ""
	}
	return name[off:]
}
