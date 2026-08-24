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

// Expired reports whether the copy has outlived its horizon — the SOA
// expire interval (RFC 1035 secondary semantics) or the earliest RRSIG
// expiration in the zone, whichever comes first — and must no longer be
// served.
func (s *Snapshot) Expired(now time.Time) bool { return now.After(s.expireAt) }

// ValidUntil is the copy's serving horizon; nothing derived from the copy
// may claim a longer life.
func (s *Snapshot) ValidUntil() time.Time { return s.expireAt }

// SOA returns the apex SOA and its RRSIGs.
func (s *Snapshot) SOA() (*dns.SOA, []dns.RR) { return s.soa, s.soaSig }

// Referral is the delegation material for one TLD: the NS set, the DS set
// (empty for an unsigned delegation), and the glue addresses for each NS
// target present in the zone.
type Referral struct {
	NS   []dns.RR
	DS   []dns.RR
	Glue map[string][]dns.RR // canonical NS host -> A/AAAA records

	// SecurityTTL is how long the delegation's DNSSEC status may be relied
	// on: the DS RRset's own smallest TTL when the delegation is signed, or
	// the TTL of the NSEC that proves no DS exists when it is not. A
	// delegation whose status the copy cannot evidence at all reports zero,
	// which drives the caller's lease to zero and sends the walk to the
	// real roots rather than asserting an unproven security status.
	SecurityTTL uint32
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
	if len(ref.DS) > 0 {
		ref.SecurityTTL = minRRSetTTL(ref.DS)
	} else if nsec, _, ok := dsAbsenceProof(sets); ok {
		// Unsigned: the evidence is the NSEC that actually denies DS at
		// this owner, and its lifetime is what bounds the claim. An NSEC
		// that does not deny it leaves SecurityTTL at zero — installing the
		// delegation with an empty DS set would assert the child is
		// insecure on a proof the copy does not hold.
		ref.SecurityTTL = minRRSetTTL(nsec)
	}
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
// ok=false when the TLD does not exist, or when the copy holds no NSEC
// that actually proves the DS absent — the absence of a DS record in the
// index is not itself a proof, and an answer that cannot be proven is left
// to the real roots.
func (s *Snapshot) DSAnswer(tld string) (ds, dsSig []dns.RR, nsec, nsecSig []dns.RR, ok bool) {
	sets, exists := s.owners[tld]
	if !exists || len(sets[dns.TypeNS]) == 0 {
		return nil, nil, nil, nil, false
	}
	if len(sets[dns.TypeDS]) > 0 {
		return sets[dns.TypeDS], sigsCovering(sets[dns.TypeRRSIG], dns.TypeDS), nil, nil, true
	}
	nsec, nsecSig, ok = dsAbsenceProof(sets)
	if !ok {
		return nil, nil, nil, nil, false
	}
	return nil, nil, nsec, nsecSig, true
}

// dsAbsenceProof returns the exact-owner NSEC RRset that proves no DS exists
// at this owner, with its RRSIGs, or ok=false when the records at the owner
// prove no such thing. It is the single place that answers the question, so
// the referral's security lifetime and the DS answer cannot disagree about
// what counts as a proof.
//
// RFC 4035 §5.2: the proof of an insecure delegation is an NSEC at the
// delegation name whose bitmap carries NS but neither DS nor SOA. Both
// halves matter, and the resolver's own VerifyDelegationNSEC requires
// exactly the same:
//
//   - NS must be present, because that is what makes the record the
//     parent's word about a delegation. Without it, a stripped-DS bitmap
//     would be taken as evidence that a signed child is insecure — the
//     downgrade the requirement exists to prevent. Here it is also an
//     internal contradiction: the copy holds the owner's real NS RRset, so
//     a bitmap that omits NS disagrees with the zone it came from.
//   - DS must be absent, because a bitmap asserting the type contradicts
//     the missing record — a truncated or tampered index, or a zone the
//     copy did not fully hold.
//   - SOA must be absent, because DS non-existence is only provable on the
//     parent side: an NSEC carrying SOA is the child apex's own, and the
//     child cannot testify about its own delegation.
//   - CNAME disqualifies too, because then the NSEC proves something else
//     entirely.
func dsAbsenceProof(sets map[uint16][]dns.RR) (nsec, nsecSig []dns.RR, ok bool) {
	nsecSet := sets[dns.TypeNSEC]
	if len(nsecSet) == 0 {
		return nil, nil, false
	}
	for _, rr := range nsecSet {
		n, isNSEC := rr.(*dns.NSEC)
		if !isNSEC {
			return nil, nil, false
		}
		hasNS := false
		for _, t := range n.TypeBitMap {
			switch t {
			case dns.TypeNS:
				hasNS = true
			case dns.TypeDS, dns.TypeSOA, dns.TypeCNAME:
				return nil, nil, false
			}
		}
		if !hasNS {
			return nil, nil, false
		}
	}
	return nsecSet, sigsCovering(sets[dns.TypeRRSIG], dns.TypeNSEC), true
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

// minRRSetTTL returns the smallest TTL among rrs, or 0 when rrs is empty —
// the same shape the resolver's delegation path uses, where "has records"
// and "their TTL is positive" are deliberately separate questions.
func minRRSetTTL(rrs []dns.RR) uint32 {
	var minTTL uint32
	for i, rr := range rrs {
		if i == 0 || rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	return minTTL
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
	s.soaSig = sigsCovering(apex[dns.TypeRRSIG], dns.TypeSOA)

	// The copy's lifetime is the earlier of the SOA expire interval and the
	// earliest RRSIG expiration anywhere in the zone: past that instant the
	// copy would be handing clients proofs whose signatures no longer
	// verify, and an AD=1 answer built on an expired signature is exactly
	// the lie the verification gate exists to prevent. (RRSIG Expiration is
	// a uint32 UNIX instant; the root re-signs on a ~2-week window, so the
	// serial-arithmetic wrap is not reachable while the maths below holds.)
	s.expireAt = now.Add(time.Duration(s.soa.Expire) * time.Second)
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		// The apex RRSIG(ZONEMD) records are the one part of the zone the
		// digest does not cover — RFC 8976 excludes them, because they are
		// written after the digest is computed — and verification accepts
		// the RRset as long as one covering signature validates. So an
		// appended, already-expired RRSIG(ZONEMD) rides in unauthenticated,
		// and trusting its expiration here would let anyone who can add a
		// record to a transfer expire a sound copy on arrival. Nothing is
		// served from these signatures either; every proof the copy hands
		// out carries signatures the digest does authenticate, and those
		// still bound the horizon below.
		if sig.TypeCovered == dns.TypeZONEMD &&
			dns.CanonicalName(sig.Header().Name) == "." {
			continue
		}
		if exp := time.Unix(int64(sig.Expiration), 0); exp.Before(s.expireAt) {
			s.expireAt = exp
		}
	}

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
