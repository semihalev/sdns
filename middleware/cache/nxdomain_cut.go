package cache

import (
	"time"

	"github.com/miekg/dns"
	internalcache "github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// nxDomainCutQType is an internal cache-key discriminator. RFC 8020 cuts are
// QTYPE-independent, so they cannot use the QTYPE from the request that
// originally received NXDOMAIN.
const (
	nxDomainCutQType         uint16 = 0
	maxNXDomainCutProofRRs          = 32
	maxNXDomainCutProofBytes        = 8 << 10
)

// nxDomainCutEntry is an immutable, locally validated RFC 8020 cut. It stores
// only the terminal denial proof; CNAME/DNAME records from an outer alias
// response must never leak into a synthesized descendant response.
type nxDomainCutEntry struct {
	deniedName string
	zone       string
	qclass     uint16
	msg        *dns.Msg
	stored     time.Time
	expires    time.Time
}

// nxDomainCutCache is deliberately separate from the ordinary answer cache.
// Random names can create many distinct cuts, so the index must have its own
// hard bound and must not evict useful positive answers.
type nxDomainCutCache struct {
	cache  *internalcache.Cache
	maxTTL time.Duration
}

func newNXDomainCutCache(size int, maxTTL time.Duration) *nxDomainCutCache {
	if size < 1 {
		size = 1
	}
	if maxTTL <= 0 {
		maxTTL = dnsutil.MaxCacheTTL
	}
	return &nxDomainCutCache{
		cache:  internalcache.New(size),
		maxTTL: maxTTL,
	}
}

func nxDomainCutKey(name string, qclass uint16) uint64 {
	return internalcache.KeyString(name, nxDomainCutQType, qclass, false)
}

// record publishes a cut for the exact locally validated denied name. zone is
// the signer zone selected by the validator; it is used to extract only the
// terminal proof when an outer CNAME/DNAME response contains records from
// multiple zones.
func (c *nxDomainCutCache) record(msg *dns.Msg, deniedName, zone string, cutUntil time.Time) bool {
	if c == nil || msg == nil || msg.Rcode != dns.RcodeNameError ||
		msg.CheckingDisabled {
		return false
	}

	deniedName = dns.CanonicalName(deniedName)
	zone = dns.CanonicalName(zone)
	if deniedName == "." || !dns.IsSubDomain(zone, deniedName) {
		return false
	}

	proof, soa, ok := nxDomainCutProof(msg, deniedName, zone)
	if !ok {
		return false
	}

	now := time.Now()
	ttl := c.maxTTL
	bound := func(candidate time.Duration) {
		if candidate < ttl {
			ttl = candidate
		}
	}

	// RFC 2308 negative TTL. No configured minimum is applied: a cache floor
	// must never extend an authenticated denial beyond any proof component.
	bound(time.Duration(soa.Hdr.Ttl) * time.Second)
	bound(time.Duration(soa.Minttl) * time.Second)
	for _, rr := range proof.Ns {
		bound(time.Duration(rr.Header().Ttl) * time.Second)
		switch record := rr.(type) {
		case *dns.SOA:
			bound(time.Duration(record.Minttl) * time.Second)
		case *dns.RRSIG:
			bound(time.Duration(record.OrigTtl) * time.Second)
			bound(time.Unix(int64(record.Expiration), 0).Sub(now))
		}
	}
	if !cutUntil.IsZero() {
		bound(cutUntil.Sub(now))
	}
	if ttl <= 0 {
		return false
	}

	entry := &nxDomainCutEntry{
		deniedName: deniedName,
		zone:       zone,
		qclass:     soa.Hdr.Class,
		msg:        proof,
		stored:     now,
		expires:    now.Add(ttl),
	}
	c.cache.Add(nxDomainCutKey(deniedName, entry.qclass), entry)
	return true
}

// nxDomainCutProof extracts the SOA and authenticated NSEC/NSEC3 proof RRsets
// belonging to zone. It intentionally discards Answer and Extra: RFC 8020
// descendant replies prove only the terminal denied subtree, not the alias
// chain that happened to discover it.
func nxDomainCutProof(msg *dns.Msg, deniedName, zone string) (*dns.Msg, *dns.SOA, bool) {
	type rrsetKey struct {
		owner  string
		rtype  uint16
		qclass uint16
	}

	if dnsutil.HasNSEC3OptOut(msg.Ns, zone) {
		return nil, nil, false
	}
	useNSEC3 := false
	for _, rr := range msg.Ns {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok || !dns.IsSubDomain(zone, dns.CanonicalName(nsec3.Hdr.Name)) {
			continue
		}
		useNSEC3 = true
	}

	var soa *dns.SOA
	for _, rr := range msg.Ns {
		record, ok := rr.(*dns.SOA)
		if !ok || !equalNameASCIIFold(dns.CanonicalName(record.Hdr.Name), zone) {
			continue
		}
		soa = record
		break
	}
	if soa == nil || len(msg.Question) != 1 ||
		msg.Question[0].Qclass != soa.Hdr.Class {
		return nil, nil, false
	}

	// Retain complete RRsets only. Provenance proves the original message,
	// but the synthesized response must not copy an unrelated/orphan RRSIG
	// or an NSEC whose NextDomain escaped the validated signer zone.
	retained := make(map[rrsetKey]struct{})
	soaKey := rrsetKey{
		owner:  zone,
		rtype:  dns.TypeSOA,
		qclass: soa.Hdr.Class,
	}
	retained[soaKey] = struct{}{}
	proofKeys := make(map[rrsetKey]struct{})

	for _, rr := range msg.Ns {
		owner := dns.CanonicalName(rr.Header().Name)
		if !dns.IsSubDomain(zone, owner) || rr.Header().Class != soa.Hdr.Class {
			continue
		}

		var key rrsetKey
		switch record := rr.(type) {
		case *dns.SOA:
			if owner != zone {
				continue
			}
			key = soaKey
		case *dns.NSEC:
			next := dns.CanonicalName(record.NextDomain)
			if useNSEC3 || !dns.IsSubDomain(zone, next) {
				continue
			}
			key = rrsetKey{owner: owner, rtype: dns.TypeNSEC, qclass: record.Hdr.Class}
			proofKeys[key] = struct{}{}
		case *dns.NSEC3:
			if !useNSEC3 {
				continue
			}
			key = rrsetKey{owner: owner, rtype: dns.TypeNSEC3, qclass: record.Hdr.Class}
			proofKeys[key] = struct{}{}
		default:
			continue
		}
		retained[key] = struct{}{}
	}

	if len(proofKeys) == 0 || !dns.IsSubDomain(zone, deniedName) {
		return nil, nil, false
	}

	signed := make(map[rrsetKey]struct{})
	for _, rr := range msg.Ns {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.Hdr.Class != soa.Hdr.Class ||
			dns.CanonicalName(sig.SignerName) != zone {
			continue
		}
		key := rrsetKey{
			owner:  dns.CanonicalName(sig.Hdr.Name),
			rtype:  sig.TypeCovered,
			qclass: sig.Hdr.Class,
		}
		if _, ok := retained[key]; ok {
			signed[key] = struct{}{}
		}
	}
	for key := range retained {
		if _, ok := signed[key]; !ok {
			return nil, nil, false
		}
	}

	proof := new(dns.Msg)
	proof.Response = true
	proof.Rcode = dns.RcodeNameError
	proof.RecursionAvailable = true
	proof.AuthenticatedData = true
	proof.Question = []dns.Question{{
		Name:   deniedName,
		Qtype:  dns.TypeA,
		Qclass: soa.Hdr.Class,
	}}
	for _, rr := range msg.Ns {
		key := rrsetKey{
			owner:  dns.CanonicalName(rr.Header().Name),
			rtype:  rr.Header().Rrtype,
			qclass: rr.Header().Class,
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			if dns.CanonicalName(sig.SignerName) != zone {
				continue
			}
			key.rtype = sig.TypeCovered
		}
		if _, ok := retained[key]; ok {
			proof.Ns = append(proof.Ns, dns.Copy(rr))
		}
	}
	// A hostile but legitimately signed zone can pad negative responses with
	// unrelated signed denial RRsets. The ordinary exact response may retain
	// those bytes; duplicating an unbounded proof into every subtree-cut entry
	// would turn the separate cut index into a memory amplifier. Ordinary
	// NSEC/NSEC3 NXDOMAIN proofs fit comfortably inside these conservative
	// limits; oversized inputs simply remain exact-cache-only.
	if len(proof.Ns) > maxNXDomainCutProofRRs ||
		proof.Len() > maxNXDomainCutProofBytes {
		return nil, nil, false
	}

	soaCopy, _ := dns.Copy(soa).(*dns.SOA)
	if soaCopy == nil {
		return nil, nil, false
	}
	return proof, soaCopy, true
}

// lookup returns the closest cached denied ancestor of q. Walking DNS label
// boundaries (rather than using a string suffix) keeps sibling names such as
// notexample.com. isolated from example.com.
func (c *nxDomainCutCache) lookup(q dns.Question) (*nxDomainCutEntry, bool) {
	if c == nil || c.cache.Len() == 0 || q.Qclass == 0 {
		return nil, false
	}

	name := dns.CanonicalName(q.Name)
	for _, offset := range dns.Split(name) {
		candidate := name[offset:]
		key := nxDomainCutKey(candidate, q.Qclass)
		value, ok := c.cache.Get(key)
		if !ok {
			continue
		}
		entry, ok := value.(*nxDomainCutEntry)
		if !ok || entry == nil ||
			entry.qclass != q.Qclass ||
			!equalNameASCIIFold(entry.deniedName, candidate) {
			continue
		}
		if !time.Now().Before(entry.expires) {
			c.cache.CompareAndDelete(key, entry)
			continue
		}
		return entry, true
	}
	return nil, false
}

func (e *nxDomainCutEntry) response(req *dns.Msg) *dns.Msg {
	if e == nil || req == nil || len(req.Question) == 0 || req.CheckingDisabled {
		return nil
	}
	now := time.Now()
	remaining := e.expires.Sub(now)
	if remaining <= 0 {
		return nil
	}

	resp := e.msg.Copy()
	resp.SetReply(req)
	resp.Rcode = dns.RcodeNameError
	resp.Authoritative = false
	resp.RecursionAvailable = true
	resp.AuthenticatedData = true
	resp.CheckingDisabled = false
	resp.Answer = nil
	resp.Extra = nil

	ttl := uint32(remaining / time.Second) //nolint:gosec // positive duration bounded by configured cache TTL
	for _, rr := range resp.Ns {
		rr.Header().Ttl = ttl
	}

	if opt := req.IsEdns0(); opt == nil || !opt.Do() {
		resp = dnsutil.ClearDNSSEC(resp)
	}
	return resp
}

// purge removes every cut that currently covers q. Without this, an explicit
// operator purge of a descendant would immediately be hidden again by its
// cached denied ancestor.
func (c *nxDomainCutCache) purge(q dns.Question) {
	if c == nil || c.cache.Len() == 0 {
		return
	}
	name := dns.CanonicalName(q.Name)
	for _, offset := range dns.Split(name) {
		candidate := name[offset:]
		key := nxDomainCutKey(candidate, q.Qclass)
		value, ok := c.cache.Get(key)
		if !ok {
			continue
		}
		entry, ok := value.(*nxDomainCutEntry)
		if ok && entry != nil &&
			entry.qclass == q.Qclass &&
			equalNameASCIIFold(entry.deniedName, candidate) {
			c.cache.CompareAndDelete(key, entry)
		}
	}
}

func (c *nxDomainCutCache) len() int {
	if c == nil {
		return 0
	}
	return c.cache.Len()
}

func (c *nxDomainCutCache) stop() {
	if c != nil {
		c.cache.Stop()
	}
}
