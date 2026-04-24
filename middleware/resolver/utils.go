package resolver

import (
	"encoding/base64"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

var (
	localIPaddrs []net.IP
)

func init() {
	var err error
	localIPaddrs, err = findLocalIPAddresses()
	if err != nil {
		zlog.Fatal("Find local ip addresses failed", zlog.String("error", err.Error()))
	}
}

func formatQuestion(q dns.Question) string {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(q.Name))
	sb.WriteByte(' ')
	sb.WriteString(dns.ClassToString[q.Qclass])
	sb.WriteByte(' ')
	sb.WriteString(dns.TypeToString[q.Qtype])
	return sb.String()
}

func shuffleStr(vals []string) []string {
	ret := slices.Clone(vals)
	rand.Shuffle(len(ret), func(i, j int) {
		ret[i], ret[j] = ret[j], ret[i]
	})
	return ret
}

func searchAddrs(msg *dns.Msg) (addrs []string, found bool) {
	found = false

	for _, rr := range msg.Answer {
		if r, ok := rr.(*dns.A); ok {
			if isLocalIP(r.A) {
				continue
			}

			if r.A.To4() == nil {
				continue
			}

			if r.A.IsLoopback() {
				continue
			}

			addrs = append(addrs, r.A.String())
			found = true
		} else if r, ok := rr.(*dns.AAAA); ok {
			if isLocalIP(r.AAAA) {
				continue
			}

			if r.AAAA.To16() == nil {
				continue
			}

			if r.AAAA.IsLoopback() {
				continue
			}

			addrs = append(addrs, r.AAAA.String())
			found = true
		}
	}

	return
}

func findLocalIPAddresses() ([]net.IP, error) {
	var list []net.IP
	tt, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, t := range tt {
		aa, err := t.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range aa {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			list = append(list, ipnet.IP)
		}
	}

	return list, nil
}

func isLocalIP(ip net.IP) (ok bool) {
	for _, l := range localIPaddrs {
		if ip.Equal(l) {
			ok = true
			return
		}
	}

	return
}

func extractRRSet(in []dns.RR, name string, t ...uint16) []dns.RR {
	if len(in) == 0 {
		return nil
	}

	// Pre-allocate with reasonable capacity
	out := make([]dns.RR, 0, min(len(in)/2, 10))

	// Optimize for common single-type queries
	if len(t) == 1 {
		targetType := t[0]
		for _, r := range in {
			if r.Header().Rrtype == targetType {
				if name != "" && !strings.EqualFold(name, r.Header().Name) {
					continue
				}
				out = append(out, r)
			}
		}
		return out
	}

	// For multiple types, use map
	template := make(map[uint16]struct{}, len(t))
	for _, typ := range t {
		template[typ] = struct{}{}
	}
	for _, r := range in {
		if _, ok := template[r.Header().Rrtype]; ok {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

// isSupportedDSDigest reports whether the given DS digest type is
// implemented locally. RFC 6840 §5.2 requires validators to ignore DS
// records that use unknown or unimplemented digest algorithms. Only the
// three digest types miekg/dns' DNSKEY.ToDS actually computes are
// treated as supported here — anything else (GOST94, future digest
// types, unknown values) is skipped.
func isSupportedDSDigest(t uint8) bool {
	switch t {
	case dns.SHA1, dns.SHA256, dns.SHA384:
		return true
	}
	return false
}

// isSupportedDNSKEYAlgorithm reports whether miekg/dns' RRSIG.Verify can
// process signatures of the given algorithm without returning ErrAlg.
// DS records advertising unsupported DNSKEY algorithms are unusable —
// DNSKEY.ToDS will still hash them, but later RRSIG verification would
// fail. Per RFC 6840 §5.2 such DS entries must be disregarded so an
// unsupported-only DS RRset is treated as insecure rather than bogus.
//
// The list intentionally matches miekg/dns' switch in RRSIG.Verify
// exactly. RSAMD5 (deprecated by RFC 8624) is *not* accepted there, so
// classifying it as supported would let an RSAMD5 DS RRset appear
// usable and then bogus out on verification instead of downgrading to
// insecure.
func isSupportedDNSKEYAlgorithm(alg uint8) bool {
	switch alg {
	case dns.RSASHA1,
		dns.RSASHA1NSEC3SHA1,
		dns.RSASHA256,
		dns.RSASHA512,
		dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384,
		dns.ED25519:
		return true
	}
	return false
}

// isSupportedDS reports whether a DS record is usable for validation:
// both its digest type and the DNSKEY algorithm it advertises must be
// something this validator can verify.
func isSupportedDS(ds *dns.DS) bool {
	return isSupportedDSDigest(ds.DigestType) && isSupportedDNSKEYAlgorithm(ds.Algorithm)
}

// verifyDS looks for a DS record in parentDSSet that authenticates one
// of the KSKs in keyMap. It returns (unsupportedOnly, err):
//
//   - (false, nil)  — at least one supported DS matched a KSK.
//   - (false, err)  — at least one supported DS was present but none
//     matched; the zone is bogus (not "insecure").
//   - (true, err)   — every DS in the RRset uses an unsupported digest
//     type. Per RFC 6840 §5.2 validators MUST ignore such records, and
//     if none remain the caller must treat the zone as insecure.
//
// keyMap groups DNSKEYs by key tag because RFC 4034 Appendix B.1 does
// not guarantee key-tag uniqueness: a colliding tag could otherwise
// mask the KSK that actually authenticates the DS.
func verifyDS(keyMap map[uint16][]*dns.DNSKEY, parentDSSet []dns.RR) (bool, error) {
	total := 0
	supported := 0
	var lastErr error
	for _, r := range parentDSSet {
		parentDS, ok := r.(*dns.DS)
		if !ok {
			continue
		}
		total++
		if !isSupportedDS(parentDS) {
			continue
		}
		supported++

		candidates, present := keyMap[parentDS.KeyTag]
		if !present {
			lastErr = errMissingKSK
			continue
		}
		matched := false
		for _, ksk := range candidates {
			ds := ksk.ToDS(parentDS.DigestType)
			if ds == nil {
				continue
			}
			if ds.Digest == parentDS.Digest {
				matched = true
				break
			}
			lastErr = errMismatchingDS
		}
		if matched {
			return false, nil
		}
	}

	if total == 0 {
		return false, errMissingKSK
	}
	if supported == 0 {
		return true, errFailedToConvertKSK
	}
	if lastErr == nil {
		lastErr = errMissingKSK
	}
	return false, lastErr
}

func isDO(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}

	return false
}

// verifyRRSIG validates that every in-zone RRset in msg is covered by at
// least one RRSIG that successfully verifies against the supplied DNSKEYs.
//
// The signer zone is derived from the DNSKEY header names (verifyDNSSEC
// fetches keys per zone, so they share a common owner). RRsets whose
// owner name is not in that zone — for example, target records appended
// via DNAME synthesis — are validated by their own recursion and are
// skipped here. An unsigned RRset inside the zone is rejected; a
// signature that fails (missing key, bad exponent, verify error,
// expired) only causes the RRset to fail if no sibling signature
// succeeds.
func verifyRRSIG(signer string, keys map[uint16][]*dns.DNSKEY, msg *dns.Msg) (bool, error) {
	if len(keys) == 0 {
		return false, errMissingDNSKEY
	}

	// signer is supplied by the caller (verifyDNSSEC / verifyRootKeys)
	// and represents the zone whose keys should authenticate this
	// response. Do NOT derive the zone from the keys map: after the
	// key-tag collision fix, that map can contain same-tag clones
	// from a different owner, and picking the first one would make
	// the whole zone filter misclassify in-zone records as foreign.
	signerZone := strings.ToLower(dns.Fqdn(signer))
	if signerZone == "" {
		return false, errMissingDNSKEY
	}

	type rrsetKey struct {
		name  string
		rtype uint16
	}

	// Collect DNAMEs in the signer zone first so we can recognise the
	// synthesised CNAMEs a DNAME answer is allowed to ship unsigned.
	var dnames []*dns.DNAME
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, r := range section {
			if d, ok := r.(*dns.DNAME); ok {
				if nameInZone(strings.ToLower(d.Header().Name), signerZone) {
					dnames = append(dnames, d)
				}
			}
		}
	}

	rrsets := make(map[rrsetKey][]dns.RR)
	// Every record in the validation pass must belong to the signer
	// zone (apart from the narrow synthesised-CNAME exception RFC
	// 6672 §5.3.1 allows when an in-zone DNAME signs the synthesis).
	// Callers that splice records from a separately-validated zone
	// (DNAME target answers) are expected to merge them only *after*
	// this function has returned, and to AND the other zone's AD
	// into the combined response themselves. Without this guard, a
	// signed response could carry attacker-injected foreign RRsets
	// alongside legitimately authenticated in-zone data and still
	// end up marked AuthenticatedData=true, violating RFC 4035
	// §3.2.3.
	var collectErr error
	collect := func(records []dns.RR, fromAuthority bool) {
		for _, r := range records {
			rtype := r.Header().Rrtype
			if rtype == dns.TypeRRSIG {
				continue
			}
			if rtype == dns.TypeNS && fromAuthority {
				continue
			}
			if rtype == dns.TypeCNAME {
				if cname, ok := r.(*dns.CNAME); ok && isSynthesizedCNAME(cname, dnames) {
					// RFC 6672 §5.3.1: the synthesised CNAME carries
					// no RRSIG of its own; the DNAME signature plus
					// correct synthesis is the proof.
					continue
				}
			}
			name := strings.ToLower(r.Header().Name)
			if !nameInZone(name, signerZone) {
				if collectErr == nil {
					collectErr = errMissingSigned
				}
				continue
			}
			k := rrsetKey{name: name, rtype: rtype}
			rrsets[k] = append(rrsets[k], r)
		}
	}
	collect(msg.Answer, false)
	collect(msg.Ns, true)
	if collectErr != nil {
		return false, collectErr
	}

	if len(rrsets) == 0 {
		// Nothing authoritative for this signer (e.g., an NS-only
		// delegation referral, or a DNAME answer whose outer zone
		// was validated under a different signer). The caller is
		// responsible for ensuring a separate cryptographic proof
		// (DS, NSEC/NSEC3) exists.
		return true, nil
	}

	sigs := append(
		extractRRSet(msg.Answer, "", dns.TypeRRSIG),
		extractRRSet(msg.Ns, "", dns.TypeRRSIG)...,
	)
	if len(sigs) == 0 {
		return false, errNoSignatures
	}

	sigIndex := make(map[rrsetKey][]*dns.RRSIG)
	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		name := strings.ToLower(sig.Header().Name)
		if !nameInZone(name, signerZone) {
			continue
		}
		k := rrsetKey{name: name, rtype: sig.TypeCovered}
		sigIndex[k] = append(sigIndex[k], sig)
	}

	for key, set := range rrsets {
		sigList, ok := sigIndex[key]
		if !ok {
			return false, errMissingSigned
		}
		var lastErr error
		verified := false
		for _, sig := range sigList {
			if err := verifyOneSig(keys, set, sig); err != nil {
				lastErr = err
				continue
			}
			verified = true
			break
		}
		if !verified {
			if lastErr == nil {
				lastErr = errMissingSigned
			}
			return false, lastErr
		}
	}

	return true, nil
}

// verifyOneSig returns nil when sig verifies set with any DNSKEY in
// keys that matches sig.KeyTag. RFC 4034 Appendix B.1 says key tags are
// not unique, so every candidate key with the same tag must be tried
// before giving up. Returns a descriptive error for every other
// outcome so the caller can surface the most informative failure when
// every candidate signature fails for an RRset.
func verifyOneSig(keys map[uint16][]*dns.DNSKEY, set []dns.RR, sig *dns.RRSIG) error {
	candidates, ok := keys[sig.KeyTag]
	if !ok || len(candidates) == 0 {
		return errMissingDNSKEY
	}
	var lastErr error = errMissingDNSKEY
	for _, k := range candidates {
		if !strings.EqualFold(sig.SignerName, k.Header().Name) {
			lastErr = errMissingDNSKEY
			continue
		}
		switch k.Algorithm {
		case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.RSAMD5:
			if !checkExponent(k.PublicKey) {
				// RSA exponent unsupported by Go crypto; treat as
				// no-valid-key rather than a silent pass.
				lastErr = errMissingDNSKEY
				continue
			}
		}
		if err := sig.Verify(k, set); err != nil {
			lastErr = err
			continue
		}
		if !sig.ValidityPeriod(time.Time{}) {
			lastErr = errInvalidSignaturePeriod
			continue
		}
		return nil
	}
	return lastErr
}

// isSynthesizedCNAME reports whether cname is the CNAME a resolver
// should have synthesised from one of the given DNAMEs (RFC 6672 §3.3).
// The match is: some dname is a *proper* ancestor of the CNAME owner,
// and applying the DNAME substitution (owner's labels above the DNAME
// owner, concatenated with the DNAME target) reproduces the CNAME
// target. Only then is it safe to skip the CNAME's own RRSIG check and
// rely on the DNAME signature plus correct synthesis.
func isSynthesizedCNAME(cname *dns.CNAME, dnames []*dns.DNAME) bool {
	owner := cname.Header().Name
	ownerLabels := dns.CountLabel(owner)
	for _, d := range dnames {
		dnameLabels := dns.CountLabel(d.Header().Name)
		if dnameLabels == 0 || ownerLabels <= dnameLabels {
			continue
		}
		n := dns.CompareDomainName(d.Header().Name, owner)
		if n != dnameLabels {
			continue
		}
		prev, _ := dns.PrevLabel(owner, n)
		expected := dns.Fqdn(owner[:prev] + d.Target)
		if strings.EqualFold(expected, dns.Fqdn(cname.Target)) {
			return true
		}
	}
	return false
}

// validateSigner checks that the signer claimed by an RRSIG is a
// plausible zone apex for qname — either qname itself or a proper
// ancestor. The check must run before the DS-chain lookup because
// RRSIG.SignerName is unauthenticated RDATA until a key verifies the
// signature: without it, an on-path attacker can rewrite SignerName to
// an unsigned sibling or descendant, then rely on findDS() returning an
// empty set to silently skip verifyDNSSEC() and downgrade a signed
// response to "insecure" instead of bogus.
func validateSigner(signer, qname string) error {
	if signer == "" {
		return errDSRecords
	}
	if !nameInZone(strings.ToLower(dns.Fqdn(qname)), strings.ToLower(dns.Fqdn(signer))) {
		return errDSRecords
	}
	return nil
}

// filterToZone returns the subset of rrs whose owner is in zone. For
// NSEC records the NextDomain field is also checked: a legitimate
// NSEC's NextDomain is always another owner in the same zone (the
// last NSEC wraps back to the zone apex), so an in-zone owner paired
// with an out-of-zone NextDomain is either a broken zone or an
// attacker-crafted record and must be discarded. Without this the
// structural coverage helpers would accept a forged NSEC whose
// NextDomain is picked to canonically straddle the qname.
func filterToZone(rrs []dns.RR, zone string) []dns.RR {
	z := strings.ToLower(dns.Fqdn(zone))
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		name := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if !nameInZone(name, z) {
			continue
		}
		if nsec, ok := rr.(*dns.NSEC); ok {
			next := strings.ToLower(dns.Fqdn(nsec.NextDomain))
			if !nameInZone(next, z) {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}

// nameInZone reports whether name is the zone apex or a descendant of
// zone. Both arguments are expected to be lowercase FQDNs.
func nameInZone(name, zone string) bool {
	if zone == "." || zone == "" {
		return true
	}
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func verifyNSEC(q dns.Question, nsecSet []dns.RR) (typeMatch bool) {
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		for _, t := range nsec.TypeBitMap {
			if t == q.Qtype {
				typeMatch = true
				break
			}
		}
	}

	return
}

func checkExponent(key string) bool {
	keybuf, err := fromBase64([]byte(key))
	if err != nil {
		return true
	}

	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return true
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 || explen == 0 || keybuf[keyoff] == 0 {
		// Exponent larger than supported by the crypto package,
		// empty, or contains prohibited leading zero.
		return false
	}

	return true
}

func sortnss(nss nameservers, qname string) []string {
	var list []string
	for name := range nss {
		list = append(list, name)
	}

	slices.Sort(list)
	slices.SortFunc(list, func(a, b string) int {
		return dns.CompareDomainName(qname, b) - dns.CompareDomainName(qname, a)
	})

	return list
}

// getDnameTarget returns the synthesized CNAME target for the question
// given a DNAME in msg.Answer, or "" if no redirect applies. Per RFC
// 6672 §2.3 the DNAME owner itself is *not* redirected, and only names
// strictly below the owner are substituted.
//
// dns.CompareDomainName counts matching trailing labels regardless of
// whether one name is actually an ancestor of the other, so a DNAME at
// sub.example.com. and a query for other.example.com. both share the
// two-label suffix example.com. — but sub.example.com. is a *sibling*
// of other.example.com., not an ancestor, and must not rewrite the
// query. Require the shared count to exactly equal the DNAME owner's
// label count (i.e. owner is a proper suffix sequence of qname), and
// that qname has strictly more labels (rules out exact match), before
// synthesizing.
func getDnameTarget(msg *dns.Msg) string {
	q := msg.Question[0]

	for _, r := range msg.Answer {
		dname, ok := r.(*dns.DNAME)
		if !ok {
			continue
		}
		ownerLabels := dns.CountLabel(dname.Header().Name)
		qLabels := dns.CountLabel(q.Name)
		if ownerLabels == 0 || qLabels <= ownerLabels {
			// Exact-owner (per RFC 6672 §2.3) or the owner has more
			// labels than qname — neither can apply.
			return ""
		}
		if dns.CompareDomainName(dname.Header().Name, q.Name) != ownerLabels {
			// Shared trailing-label count is less than the DNAME
			// owner's full name, meaning the owner is a cousin or
			// unrelated sibling, not an ancestor of qname.
			return ""
		}
		prev, _ := dns.PrevLabel(q.Name, ownerLabels)
		return q.Name[:prev] + dname.Target
	}

	return ""
}

var reqPool sync.Pool

// AcquireMsg returns an empty msg from pool.
func AcquireMsg() *dns.Msg {
	v, _ := reqPool.Get().(*dns.Msg)
	if v == nil {
		return &dns.Msg{}
	}

	return v
}

// ReleaseMsg returns req to pool.
func ReleaseMsg(req *dns.Msg) {
	req.Id = 0
	req.Response = false
	req.Opcode = 0
	req.Authoritative = false
	req.Truncated = false
	req.RecursionDesired = false
	req.RecursionAvailable = false
	req.Zero = false
	req.AuthenticatedData = false
	req.CheckingDisabled = false
	req.Rcode = 0
	req.Compress = false
	clear(req.Question)
	clear(req.Answer)
	clear(req.Ns)
	clear(req.Extra)
	req.Question = nil
	req.Answer = nil
	req.Ns = nil
	req.Extra = nil

	reqPool.Put(req)
}

var connPool sync.Pool

// AcquireConn returns an empty conn from pool.
func AcquireConn() *Conn {
	v, _ := connPool.Get().(*Conn)
	if v == nil {
		return &Conn{}
	}
	return v
}

// ReleaseConn returns req to pool.
func ReleaseConn(co *Conn) {
	if co.Conn != nil {
		_ = co.Close()
	}

	co.UDPSize = 0
	co.Conn = nil

	connPool.Put(co)
}
