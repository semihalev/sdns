package dnssec

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // RSASHA1 (algs 5 & 7) mandates SHA-1; required for DNSSEC interop, not used as a security primitive.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"math/big"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// maxStdlibRSAExponent is the largest RSA public exponent Go's crypto/rsa
// (and, mirroring it, miekg/dns' RRSIG.Verify) will process. Keys whose
// exponent exceeds it are rejected by the standard library with
// "public exponent too large", so they have to be verified by hand.
const maxStdlibRSAExponent = 1<<31 - 1

// rsaExponentExceedsStdlib reports whether the RFC 3110 RSA public key in
// pubkey carries an exponent that crypto/rsa cannot load. Such keys are
// rare but valid — e.g. mailbox.org's alg-7/alg-10 ZSKs use 2^32+1 — and
// must take the verifyRSAWideExponent path instead of sig.Verify. A key we
// cannot even parse returns false so the caller falls back to the normal
// path and surfaces the library's own error.
func rsaExponentExceedsStdlib(pubkey string) bool {
	keybuf, err := fromBase64([]byte(pubkey))
	if err != nil || len(keybuf) < 1 {
		return false
	}
	explen := int(keybuf[0])
	off := 1
	if explen == 0 {
		if len(keybuf) < 3 {
			return false
		}
		explen = int(keybuf[1])<<8 | int(keybuf[2])
		off = 3
	}
	if explen == 0 || len(keybuf) < off+explen {
		return false
	}
	if explen > 4 {
		return true
	}
	var e uint64
	for _, b := range keybuf[off : off+explen] {
		e = e<<8 | uint64(b)
	}
	return e > maxStdlibRSAExponent
}

// parseRSAPublicKey decodes an RFC 3110 RSA DNSKEY public key into its
// modulus and exponent. Unlike crypto/rsa it imposes no upper bound on the
// exponent — that is the whole point of this path.
func parseRSAPublicKey(pubkey string) (n, e *big.Int, ok bool) {
	keybuf, err := fromBase64([]byte(pubkey))
	if err != nil || len(keybuf) < 1 {
		return nil, nil, false
	}
	explen := int(keybuf[0])
	off := 1
	if explen == 0 {
		if len(keybuf) < 3 {
			return nil, nil, false
		}
		explen = int(keybuf[1])<<8 | int(keybuf[2])
		off = 3
	}
	modoff := off + explen
	if explen == 0 || len(keybuf) <= modoff {
		return nil, nil, false
	}
	// Reject non-canonical leading-zero exponent or modulus bytes, as
	// miekg/dns' publicKeyRSA does. A leading zero changes the key tag yet
	// leaves the value unchanged, and a conformant signer never emits one;
	// the key-tag checksum is also insensitive to an even number of inserted
	// zero bytes, so this must be checked explicitly rather than via the tag.
	if keybuf[off] == 0 || keybuf[modoff] == 0 {
		return nil, nil, false
	}
	e = new(big.Int).SetBytes(keybuf[off:modoff])
	n = new(big.Int).SetBytes(keybuf[modoff:])
	if n.Sign() == 0 || e.Sign() <= 0 {
		return nil, nil, false
	}
	return n, e, true
}

// RSA key bounds for the raw verification path. crypto/rsa rejects the
// exponents this path exists to accept, so it can't enforce these for us —
// without them an attacker-delegated zone could publish a DNSKEY with a
// pathologically large exponent or modulus and force ruinously expensive
// modular exponentiation on every validation attempt (CPU exhaustion).
// Measured cost of big.Int.Exp grows with exponent width × modulus width²
// (e.g. an 8192-bit modulus with an 8192-bit exponent is ~100ms/op), so the
// exponent cap below is the load-bearing limit.
const (
	minRSAModulusBits  = 1024 // mirrors crypto/rsa's weak-key floor
	maxRSAModulusBits  = 4096 // real DNSSEC RSA keys never exceed this
	maxRSAExponentBits = 64   // the wide-exponent target is 2^32+1 (33 bits); 64 leaves headroom
)

// usableRSAKey reports whether (n, e) is a sane RSA public key worth running
// a modexp against. It bounds the modulus to a safe range and requires the
// exponent to be a valid RSA exponent — odd, at least 3, and less than the
// modulus (RFC 8017 — e is chosen in (1, λ(n)) so e < n always holds) — and
// narrow enough that a single modexp stays sub-millisecond.
func usableRSAKey(n, e *big.Int) bool {
	if bits := n.BitLen(); bits < minRSAModulusBits || bits > maxRSAModulusBits {
		return false
	}
	if e.Bit(0) == 0 || e.Cmp(big.NewInt(3)) < 0 || e.Cmp(n) >= 0 || e.BitLen() > maxRSAExponentBits {
		return false
	}
	return true
}

// rsaHash maps an RSA DNSSEC algorithm to its hash and the ASN.1
// DigestInfo prefix used by EMSA-PKCS1-v1_5 (RFC 8017 §9.2). These prefixes
// are the same constants crypto/rsa uses internally.
func rsaHash(alg uint8) (hash.Hash, []byte, bool) {
	switch alg {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return sha1.New(), []byte{ //nolint:gosec // see import note: SHA-1 is mandated by these algorithms.
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
			0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
		}, true
	case dns.RSASHA256:
		return sha256.New(), []byte{
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
		}, true
	case dns.RSASHA512:
		return sha512.New(), []byte{
			0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
		}, true
	}
	return nil, nil, false
}

// verifyRSAWideExponent performs the RFC 4034 §3.1.8.1 RSA signature check
// for keys whose exponent crypto/rsa refuses to load. It reproduces miekg's
// canonical signed-data construction exactly (so it agrees with sig.Verify
// for every key the library can handle) and then does the modular
// exponentiation itself with math/big, bypassing the standard library's
// exponent ceiling. Returns nil on a valid signature.
func verifyRSAWideExponent(k *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) error {
	// Mirror miekg/dns RRSIG.Verify's preflight so this path is never more
	// permissive than the library it stands in for: bind the signature to
	// this exact key (RFC 4034 §3.1) and RRset (RFC 4035 §5.3.1) before
	// trusting any cryptographic result.
	if !dns.IsRRset(rrset) {
		return ErrMissingSigned
	}
	if k.Protocol != 3 || k.Flags&dns.ZONE == 0 {
		return ErrMissingDNSKEY
	}
	if sig.KeyTag != k.KeyTag() || sig.Algorithm != k.Algorithm || sig.Hdr.Class != k.Hdr.Class {
		return ErrMissingDNSKEY
	}
	if !strings.EqualFold(sig.SignerName, k.Hdr.Name) {
		return ErrMissingDNSKEY
	}
	signer := dns.CanonicalName(sig.SignerName)
	h0 := rrset[0].Header()
	if h0.Class != sig.Hdr.Class || h0.Rrtype != sig.TypeCovered ||
		dns.CountLabel(h0.Name) < int(sig.Labels) ||
		!strings.EqualFold(h0.Name, sig.Hdr.Name) ||
		!strings.HasSuffix(dns.CanonicalName(h0.Name), signer) {
		return ErrMissingSigned
	}

	n, e, ok := parseRSAPublicKey(k.PublicKey)
	if !ok {
		return ErrMissingDNSKEY
	}
	if !usableRSAKey(n, e) {
		return ErrMissingDNSKEY
	}

	h, prefix, ok := rsaHash(sig.Algorithm)
	if !ok {
		return ErrMissingDNSKEY
	}

	signed, err := rrsigSignedData(sig, rrset)
	if err != nil {
		return err
	}
	h.Write(signed)
	hashed := h.Sum(nil)

	sigbuf, err := fromBase64([]byte(sig.Signature))
	if err != nil {
		return ErrMissingSigned
	}

	return rsaVerifyPKCS1v15(n, e, prefix, hashed, sigbuf)
}

// rsaVerifyPKCS1v15 verifies a PKCS#1 v1.5 signature by raw modular
// exponentiation (m = sig^e mod n) and a constant-time comparison against
// the expected EMSA-PKCS1-v1_5 encoding of hashed.
func rsaVerifyPKCS1v15(n, e *big.Int, prefix, hashed, sig []byte) error {
	size := (n.BitLen() + 7) / 8
	if len(sig) != size {
		return dns.ErrSig
	}

	c := new(big.Int).SetBytes(sig)
	if c.Cmp(n) >= 0 {
		return dns.ErrSig
	}
	m := new(big.Int).Exp(c, e, n)
	em := m.Bytes()
	if len(em) > size {
		return dns.ErrSig
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T, where T = prefix || hashed and
	// PS is at least eight 0xFF octets (RFC 8017 §9.2).
	tLen := len(prefix) + len(hashed)
	if size < tLen+11 {
		return dns.ErrSig
	}
	expected := make([]byte, size)
	expected[1] = 0x01
	for i := 2; i < size-tLen-1; i++ {
		expected[i] = 0xff
	}
	copy(expected[size-tLen:], prefix)
	copy(expected[size-len(hashed):], hashed)

	// m.Bytes() drops leading zero octets; left-pad to compare full width.
	padded := make([]byte, size)
	copy(padded[size-len(em):], em)

	if subtle.ConstantTimeCompare(padded, expected) != 1 {
		return dns.ErrSig
	}
	return nil
}

// rrsigSignedData rebuilds the exact byte string an RRSIG signs:
// the RRSIG RDATA without the signature, followed by the canonical-form
// RRset (RFC 4034 §3.1.8.1 and §6). It mirrors miekg/dns' unexported
// packSigWire + rawSignatureData so this verifier stays bit-for-bit
// compatible with sig.Verify.
func rrsigSignedData(sig *dns.RRSIG, rrset []dns.RR) ([]byte, error) {
	buf := make([]byte, 0, 256)
	buf = binary.BigEndian.AppendUint16(buf, sig.TypeCovered)
	buf = append(buf, sig.Algorithm, sig.Labels)
	buf = binary.BigEndian.AppendUint32(buf, sig.OrigTtl)
	buf = binary.BigEndian.AppendUint32(buf, sig.Expiration)
	buf = binary.BigEndian.AppendUint32(buf, sig.Inception)
	buf = binary.BigEndian.AppendUint16(buf, sig.KeyTag)

	name := make([]byte, 256)
	off, err := dns.PackDomainName(dns.CanonicalName(sig.SignerName), name, 0, nil, false)
	if err != nil {
		return nil, err
	}
	buf = append(buf, name[:off]...)

	wire, err := canonicalRRset(rrset, sig)
	if err != nil {
		return nil, err
	}
	return append(buf, wire...), nil
}

// canonicalRRset returns the concatenated canonical wire form of rrset as
// required for signing/verification: each RR copied with its TTL set to the
// RRSIG's original TTL, wildcard owners restored, owner and (where RFC 4034
// §6.2 requires it) embedded names lowercased, then the records sorted and
// duplicate-collapsed. Faithful reproduction of miekg's rawSignatureData.
func canonicalRRset(rrset []dns.RR, s *dns.RRSIG) ([]byte, error) {
	wires := make([][]byte, len(rrset))
	for i, r := range rrset {
		r1 := dns.Copy(r)
		h := r1.Header()
		h.Ttl = s.OrigTtl
		labels := dns.SplitDomainName(h.Name)
		if len(labels) > int(s.Labels) {
			h.Name = "*." + strings.Join(labels[len(labels)-int(s.Labels):], ".") + "."
		}
		h.Name = dns.CanonicalName(h.Name)
		canonicalizeRdataNames(r1)

		wire := make([]byte, dns.Len(r1)+1)
		n, err := dns.PackRR(r1, wire, 0, nil, false)
		if err != nil {
			return nil, err
		}
		wires[i] = wire[:n]
	}

	sort.Slice(wires, func(i, j int) bool {
		return bytes.Compare(wires[i], wires[j]) < 0
	})

	var buf []byte
	for i, wire := range wires {
		if i > 0 && bytes.Equal(wire, wires[i-1]) {
			continue
		}
		buf = append(buf, wire...)
	}
	return buf, nil
}

// canonicalizeRdataNames lowercases the domain names embedded in the RDATA
// of the record types RFC 4034 §6.2 (as clarified by RFC 6840 §5.1) lists,
// matching miekg/dns' rawSignatureData switch.
func canonicalizeRdataNames(r dns.RR) {
	switch x := r.(type) {
	case *dns.NS:
		x.Ns = dns.CanonicalName(x.Ns)
	case *dns.MD:
		x.Md = dns.CanonicalName(x.Md)
	case *dns.MF:
		x.Mf = dns.CanonicalName(x.Mf)
	case *dns.CNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.SOA:
		x.Ns = dns.CanonicalName(x.Ns)
		x.Mbox = dns.CanonicalName(x.Mbox)
	case *dns.MB:
		x.Mb = dns.CanonicalName(x.Mb)
	case *dns.MG:
		x.Mg = dns.CanonicalName(x.Mg)
	case *dns.MR:
		x.Mr = dns.CanonicalName(x.Mr)
	case *dns.PTR:
		x.Ptr = dns.CanonicalName(x.Ptr)
	case *dns.MINFO:
		x.Rmail = dns.CanonicalName(x.Rmail)
		x.Email = dns.CanonicalName(x.Email)
	case *dns.MX:
		x.Mx = dns.CanonicalName(x.Mx)
	case *dns.RP:
		x.Mbox = dns.CanonicalName(x.Mbox)
		x.Txt = dns.CanonicalName(x.Txt)
	case *dns.AFSDB:
		x.Hostname = dns.CanonicalName(x.Hostname)
	case *dns.RT:
		x.Host = dns.CanonicalName(x.Host)
	case *dns.SIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	case *dns.PX:
		x.Map822 = dns.CanonicalName(x.Map822)
		x.Mapx400 = dns.CanonicalName(x.Mapx400)
	case *dns.NAPTR:
		x.Replacement = dns.CanonicalName(x.Replacement)
	case *dns.KX:
		x.Exchanger = dns.CanonicalName(x.Exchanger)
	case *dns.SRV:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.DNAME:
		x.Target = dns.CanonicalName(x.Target)
	}
}
