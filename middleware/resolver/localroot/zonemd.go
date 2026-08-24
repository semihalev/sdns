package localroot

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

var (
	errNoApex            = errors.New("localroot: zone has no usable apex")
	errNoZONEMD          = errors.New("localroot: no supported ZONEMD at the apex")
	errSerialMismatch    = errors.New("localroot: ZONEMD serial does not match the SOA")
	errDigestMismatch    = errors.New("localroot: zone digest does not match ZONEMD")
	errAnchorChain       = errors.New("localroot: DNSKEY set does not chain to a trust anchor")
	errBadSignature      = errors.New("localroot: apex RRset signature did not verify")
	errSerialRollback    = errors.New("localroot: zone serial is older than the live copy")
	errSerialBehindProbe = errors.New("localroot: transferred zone is older than the serial the source announced")
	errDuplicateZONEMD   = errors.New("localroot: apex carries a repeated ZONEMD scheme/hash tuple")
	errApexTooLarge      = errors.New("localroot: apex carries an implausible number of keys or digests")
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
//
// authUntil is when that authentication lapses — the expiration of the
// signature that carried the ZONEMD RRset through verification. The copy
// may not be served past it: the digest is only evidence for as long as
// the signature over it holds.
func verifyZone(rrs []dns.RR, anchors []dns.RR) (authUntil time.Time, err error) {
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
		return time.Time{}, errNoApex
	}
	if len(dnskeys) == 0 {
		return time.Time{}, errAnchorChain
	}
	// Refuse an implausible apex before any of it is hashed. Capping the
	// number of candidate signatures is not enough on its own: each
	// verification hashes the whole RRset it covers, and each key is
	// digested once per anchor, so an inflated DNSKEY or ZONEMD RRset
	// turns transfer bytes into cryptographic work regardless of how few
	// signatures are tried. The root publishes a handful of keys and one
	// or two digests; a zone claiming dozens is not one this should be
	// spending anything on.
	if len(dnskeys) > maxApexRecords || len(zonemds) > maxApexRecords {
		return time.Time{}, errApexTooLarge
	}

	if len(anchors) == 0 {
		return time.Time{}, errAnchorChain
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
		return time.Time{}, errAnchorChain
	}
	if _, err := verifyApexRRset(anchorKeys, typedApexSet(dnskeys), apexSig); err != nil {
		return time.Time{}, errAnchorChain
	}

	keyMap := make(map[uint16][]*dns.DNSKEY, len(dnskeys))
	for _, k := range dnskeys {
		tag := dnssec.KeyTag(k)
		keyMap[tag] = append(keyMap[tag], k)
	}

	if _, err := verifyApexRRset(keyMap, []dns.RR{soa}, apexSig); err != nil {
		return time.Time{}, err
	}
	if len(zonemds) == 0 {
		return time.Time{}, errNoZONEMD
	}
	// The ZONEMD RRset's own signature is what makes the digest evidence,
	// so its expiration is the authentication's, and the caller carries it
	// into the copy's horizon.
	authUntil, err = verifyApexRRset(keyMap, typedApexSet(zonemds), apexSig)
	if err != nil {
		return time.Time{}, err
	}

	// RFC 8976 §4 step 4: "If the ZONEMD RRset contains more than one RR
	// with the same Scheme and Hash Algorithm, digest verification for
	// those ZONEMD RRs MUST NOT be considered successful." The
	// disqualification is scoped to the repeated tuple — step 5 adds that
	// "a match using any one of the recipient's supported Schemes and Hash
	// Algorithms is sufficient to verify the zone" — so a zone carrying a
	// duplicated tuple alongside a sound unique one still verifies through
	// the latter. Counting first, then skipping only the duplicates, is
	// what keeps an appended digest from being usable without letting it
	// deny an otherwise valid zone.
	tupleCount := make(map[uint16]int, len(zonemds))
	for _, z := range zonemds {
		tupleCount[uint16(z.Scheme)<<8|uint16(z.Hash)]++
	}

	var chosen *dns.ZONEMD
	duplicated := false
	for _, z := range zonemds {
		if z.Scheme != zonemdSchemeSimple || z.Hash != zonemdHashSHA384 {
			continue
		}
		if tupleCount[uint16(z.Scheme)<<8|uint16(z.Hash)] > 1 {
			duplicated = true
			continue
		}
		chosen = z
		break
	}
	if chosen == nil {
		if duplicated {
			return time.Time{}, errDuplicateZONEMD
		}
		return time.Time{}, errNoZONEMD
	}
	if chosen.Serial != soa.Serial {
		return time.Time{}, errSerialMismatch
	}

	digest, err := ComputeDigest(rrs, ".")
	if err != nil {
		return time.Time{}, err
	}
	want, err := hexDecode(chosen.Digest)
	if err != nil || len(want) != sha512.Size384 {
		return time.Time{}, errDigestMismatch
	}
	if subtle.ConstantTimeCompare(digest, want) != 1 {
		return time.Time{}, errDigestMismatch
	}
	return authUntil, nil
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

// maxApexSignatureAttempts bounds how many public-key operations one apex
// RRset may cost. A zone carrying more than a handful of signatures over
// one RRset is already pathological — the root publishes one, a rollover a
// few — and the cap cannot be used to hide a sound signature behind
// higher-expiring forgeries in any meaningful sense: anyone able to add
// records to a transfer can already deny the copy outright by disturbing a
// digested record. What the cap removes is the amplification, which is a
// capability they did not otherwise have.
//
// It bounds the count of operations only. What each one costs is bounded
// separately by maxApexRecords, since a verification hashes the whole
// RRset it covers.
const maxApexSignatureAttempts = 16

// maxApexRecords bounds how many records of one apex type verification will
// look at. The real root publishes about four DNSKEYs and one ZONEMD; the
// margin here is for a rollover, not for a zone that wants to be expensive.
const maxApexRecords = 32

// verifyApexRRset verifies one apex RRset against the zone keys and returns
// how long the result holds: the expiration of the signature that carried
// it. Authentication is only as good as the signature behind it (RFC 4035
// §5.3.3), so the answer must name a specific signature rather than the
// RRset as a whole — a sibling that fails to verify cannot lend its
// timestamps to the result.
//
// Candidates are deduplicated, ordered by descending expiration and tried
// until one verifies. Order is what makes stopping correct: the first
// signature to verify necessarily carries the latest expiration among those
// that would, because everything longer-lived was tried before it. It is
// also what keeps the work down — a sound zone verifies on the first
// attempt — and the cap bounds the rest, since apex RRSIG(ZONEMD) records
// sit outside the digest and can be appended freely.
func verifyApexRRset(keys map[uint16][]*dns.DNSKEY, set []dns.RR, sigs []dns.RR) (time.Time, error) {
	covered := set[0].Header().Rrtype

	covering := make([]*dns.RRSIG, 0, 4)
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covered {
			covering = append(covering, sig)
		}
	}
	// Deduplicate on the identity the verifier itself uses. Anything less
	// can collapse a sound signature into an unsound one that merely
	// resembles it — two records differing only in, say, original TTL sign
	// different data, so one may verify where the other cannot.
	candidates := dnssec.UniqueRRSIGs(covering)

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Expiration > candidates[j].Expiration
	})
	if len(candidates) > maxApexSignatureAttempts {
		candidates = candidates[:maxApexSignatureAttempts]
	}

	for _, sig := range candidates {
		msg := new(dns.Msg)
		msg.Answer = append(msg.Answer, set...)
		msg.Answer = append(msg.Answer, sig)
		if verified, err := dnssec.VerifyRRSIG(".", keys, msg); err != nil || !verified {
			continue
		}
		return time.Unix(int64(sig.Expiration), 0), nil
	}
	return time.Time{}, errBadSignature
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
