package localroot

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

var (
	errNoApex         = errors.New("localroot: zone has no usable apex")
	errNoZONEMD       = errors.New("localroot: no supported ZONEMD at the apex")
	errSerialMismatch = errors.New("localroot: ZONEMD serial does not match the SOA")
	errDigestMismatch = errors.New("localroot: zone digest does not match ZONEMD")
	errAnchorChain    = errors.New("localroot: DNSKEY set does not chain to a trust anchor")
	errBadSignature   = errors.New("localroot: apex RRset signature did not verify")
	errSerialRollback = errors.New("localroot: zone serial is older than the live copy")
)

const (
	zonemdSchemeSimple = 1 // RFC 8976 §2.2.4
	zonemdHashSHA384   = 1 // RFC 8976 §2.2.5
)

// verifyZone establishes a transferred record set as an authentic copy of
// the root zone, chained to the resolver's trust anchors, before anything
// is built from it. The chain (RFC 8976 §4, RFC 8806 §3):
//
//  1. The apex DNSKEY RRset must match a configured trust anchor DS and
//     carry a valid self-signature.
//  2. The apex SOA and ZONEMD RRsets must verify against those keys.
//  3. A supported ZONEMD (SIMPLE/SHA-384) must carry the SOA's serial, and
//     the digest of the whole zone in canonical form — every record, glue
//     included, deduplicated, excluding the apex ZONEMD RRset and the
//     RRSIGs covering it — must match it exactly.
//
// The ZONEMD match authenticates the entire zone contents in one stroke;
// individual RRSIGs elsewhere in the zone are carried for clients, not
// re-verified here.
func verifyZone(rrs []dns.RR, anchors []dns.RR) error {
	var (
		dnskeys []*dns.DNSKEY
		zonemds []*dns.ZONEMD
		soa     *dns.SOA
		apexSig []dns.RR
	)
	for _, rr := range rrs {
		if dns.CanonicalName(rr.Header().Name) != "." {
			continue
		}
		switch t := rr.(type) {
		case *dns.DNSKEY:
			dnskeys = append(dnskeys, t)
		case *dns.ZONEMD:
			zonemds = append(zonemds, t)
		case *dns.SOA:
			soa = t
		case *dns.RRSIG:
			apexSig = append(apexSig, t)
		}
	}
	if soa == nil {
		return errNoApex
	}
	if len(dnskeys) == 0 {
		return errAnchorChain
	}

	if len(anchors) == 0 {
		return errAnchorChain
	}

	// The chain order is the whole defense. First, only the keys that
	// actually match a trust anchor DS may authenticate the DNSKEY RRset —
	// handing that verification the full transferred set would let an
	// attacker include the well-known real KSK for the anchor match while
	// signing everything with a key of their own, also in the set. Only a
	// DNSKEY RRset signed by an anchor-matched key promotes the rest of
	// the set into keyMap for the SOA and ZONEMD checks.
	anchorKeys := make(map[uint16][]*dns.DNSKEY)
	for _, k := range dnskeys {
		if dnskeyMatchesAnchor(k, anchors) {
			tag := dnssec.KeyTag(k)
			anchorKeys[tag] = append(anchorKeys[tag], k)
		}
	}
	if len(anchorKeys) == 0 {
		return errAnchorChain
	}
	if err := verifyApexRRset(anchorKeys, typedApexSet(dnskeys), apexSig); err != nil {
		return errAnchorChain
	}

	keyMap := make(map[uint16][]*dns.DNSKEY, len(dnskeys))
	for _, k := range dnskeys {
		tag := dnssec.KeyTag(k)
		keyMap[tag] = append(keyMap[tag], k)
	}

	for _, set := range [][]dns.RR{
		{soa},
		typedApexSet(zonemds),
	} {
		if len(set) == 0 {
			continue
		}
		if err := verifyApexRRset(keyMap, set, apexSig); err != nil {
			return err
		}
	}

	var chosen *dns.ZONEMD
	for _, z := range zonemds {
		if z.Scheme == zonemdSchemeSimple && z.Hash == zonemdHashSHA384 {
			chosen = z
			break
		}
	}
	if chosen == nil {
		return errNoZONEMD
	}
	if chosen.Serial != soa.Serial {
		return errSerialMismatch
	}

	digest, err := ComputeDigest(rrs, ".")
	if err != nil {
		return err
	}
	want, err := hexDecode(chosen.Digest)
	if err != nil || len(want) != sha512.Size384 {
		return errDigestMismatch
	}
	if subtle.ConstantTimeCompare(digest, want) != 1 {
		return errDigestMismatch
	}
	return nil
}

// dnskeyMatchesAnchor reports whether key's DS, computed at each anchor's
// own digest type, reproduces that anchor exactly — tag, algorithm and
// digest alike.
func dnskeyMatchesAnchor(key *dns.DNSKEY, anchors []dns.RR) bool {
	for _, rr := range anchors {
		ds, ok := rr.(*dns.DS)
		if !ok || ds.Algorithm != key.Algorithm {
			continue
		}
		computed, err := dnssec.DNSKEYToDSWithWork(key, ds.DigestType, nil)
		if err != nil {
			continue
		}
		if computed.KeyTag == ds.KeyTag &&
			strings.EqualFold(computed.Digest, ds.Digest) {
			return true
		}
	}
	return false
}

// verifyApexRRset verifies one apex RRset against the zone keys using the
// covering RRSIG from the apex signature pool.
func verifyApexRRset(keys map[uint16][]*dns.DNSKEY, set []dns.RR, sigs []dns.RR) error {
	covered := set[0].Header().Rrtype
	msg := new(dns.Msg)
	msg.Answer = append(msg.Answer, set...)
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covered {
			msg.Answer = append(msg.Answer, sig)
		}
	}
	if len(msg.Answer) == len(set) {
		return errBadSignature // no covering signature at all
	}
	if ok, err := dnssec.VerifyRRSIG(".", keys, msg); err != nil || !ok {
		return errBadSignature
	}
	return nil
}

func typedApexSet[T dns.RR](set []T) []dns.RR {
	out := make([]dns.RR, 0, len(set))
	for _, rr := range set {
		out = append(out, rr)
	}
	return out
}

// ComputeDigest is RFC 8976 §3.3.1's SIMPLE scheme over SHA-384: every
// record in canonical wire form and canonical order — owner order (§6.1 of
// RFC 4034), then ascending TYPE for RRsets sharing an owner, then RDATA
// (§6.3) — with duplicates collapsed and two exclusions at the apex: the
// ZONEMD RRset itself, and the RRSIGs covering it.
func ComputeDigest(rrs []dns.RR, apex string) ([]byte, error) {
	type entry struct {
		owner    string
		rtype    uint16
		wire     []byte
		rdataOff int
	}
	entries := make([]entry, 0, len(rrs))
	for _, rr := range rrs {
		owner := dns.CanonicalName(rr.Header().Name)
		rtype := rr.Header().Rrtype
		if !dns.IsSubDomain(apex, owner) {
			// Out-of-zone data is not part of the zone and not digested.
			continue
		}
		if owner == apex {
			if rtype == dns.TypeZONEMD {
				continue
			}
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
				continue
			}
		}
		wire, off, err := dnssec.CanonicalWireRR(rr)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{owner: owner, rtype: rtype, wire: wire, rdataOff: off})
	}

	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if c := dnsname.CanonicalCompare(a.owner, b.owner); c != 0 {
			return c < 0
		}
		if a.rtype != b.rtype {
			return a.rtype < b.rtype
		}
		return bytes.Compare(a.wire[a.rdataOff:], b.wire[b.rdataOff:]) < 0
	})

	h := sha512.New384()
	var prev []byte
	for i := range entries {
		// Duplicate RRs (equal owner, class, type, RDATA) digest once.
		// After sorting, duplicates are adjacent and their canonical
		// wire forms are byte-identical.
		if prev != nil && bytes.Equal(prev, entries[i].wire) {
			continue
		}
		h.Write(entries[i].wire)
		prev = entries[i].wire
	}
	return h.Sum(nil), nil
}

// hexDecode decodes the ZONEMD digest presentation (hex, upper or lower).
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errDigestMismatch
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, errDigestMismatch
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
