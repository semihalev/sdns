package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// signatureBinding is the preflight every RRSIG check shares: the signature
// must belong to this exact key (RFC 4034 §3.1) and to this exact RRset (RFC
// 4035 §5.3.1) before any cryptographic result means anything.
//
// It mirrors miekg/dns RRSIG.Verify's own preflight, so this package is never
// more permissive than the library it stands in for, and is stricter in the
// one place noted below.
func signatureBinding(k *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) error {
	if k == nil || sig == nil || !dns.IsRRset(rrset) {
		return ErrMissingSigned
	}
	if k.Protocol != 3 || k.Flags&dns.ZONE == 0 {
		return ErrMissingDNSKEY
	}
	if sig.KeyTag != KeyTag(k) || sig.Algorithm != k.Algorithm ||
		sig.Hdr.Class != k.Hdr.Class {
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
		// On a label boundary, not a string suffix. RFC 4035 §5.3.1 requires
		// the signer to name the zone containing the RRset, and a plain
		// suffix test reads evilexample.com. as inside example.com. The
		// library settles for the suffix — its own comment calls that the
		// best it can do without SOA context — and the resolver's zone
		// containment check catches it a layer up, but a check that means
		// something only in the presence of another one is worth fixing
		// where it is written.
		!dnsutil.NameInZone(dns.CanonicalName(h0.Name), signer) {
		return ErrMissingSigned
	}
	return nil
}

// verifySignature checks an RRSIG against a DNSKEY, returning nil when the
// signature is valid.
//
// The canonical signed data is this package's own — the construction the
// wide-exponent RSA path has always used — and the cryptography is the
// standard library's. What it avoids is the library's fixed 4096-octet
// signed-data buffer, allocated for every signature of every response, and
// re-deriving the key material and key tag on each one.
//
// It agrees with dns.RRSIG.Verify on the signatures a signer produces, and
// deliberately differs on two inputs no signer produces:
//
//   - An ECDSA signature whose r and s are not the fixed width RFC 6605 §4
//     gives them. The library splits whatever it is handed in half and lets
//     leading zeros pass; a 66-octet P-256 signature is not a P-256
//     signature, and is refused here.
//   - An RSA modulus outside usableRSAKey's bounds. Below 1024 bits both
//     refuse by default, but the library's floor is crypto/rsa's and lifts
//     under GODEBUG=rsa1024min=0, while this one is the package's own and
//     does not; above 4096 bits the library has no bound and this one
//     refuses. Both directions narrow what is accepted, and the wide-exponent
//     path is gated by the same bounds before it reaches the raw modular
//     exponentiation that bypasses crypto/rsa.
//
// An algorithm this does not implement is refused rather than guessed at;
// cryptoVerify keeps such keys on the library's path.
func verifySignature(k *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) error {
	if err := signatureBinding(k, sig, rrset); err != nil {
		return err
	}

	signed, err := rrsigSignedData(sig, rrset)
	if err != nil {
		return err
	}
	// A signature that does not decode, or does not have the shape its
	// algorithm requires, is a bad signature — the key it names is present
	// and fine. The distinction is wire-visible: it decides which EDE the
	// client is told.
	signature, err := fromBase64([]byte(sig.Signature))
	if err != nil {
		return dns.ErrSig
	}

	switch sig.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		return verifyRSASignature(k, sig.Algorithm, signed, signature)
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		return verifyECDSASignature(k, sig.Algorithm, signed, signature)
	case dns.ED25519:
		return verifyEd25519Signature(k, signed, signature)
	default:
		return ErrMissingDNSKEY
	}
}

// verifySignatureSupported reports whether verifySignature implements the
// algorithm, so the dispatcher can leave anything else where it was.
func verifySignatureSupported(algorithm uint8) bool {
	switch algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512,
		dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

func verifyRSASignature(k *dns.DNSKEY, algorithm uint8, signed, signature []byte) error {
	n, e, ok := parseRSAPublicKey(k.PublicKey)
	if !ok {
		return ErrMissingDNSKEY
	}
	if !usableRSAKey(n, e) {
		return ErrMissingDNSKEY
	}

	hasher, prefix, ok := rsaHash(algorithm)
	if !ok {
		return ErrMissingDNSKEY
	}
	hasher.Write(signed)
	hashed := hasher.Sum(nil)

	// An exponent crypto/rsa refuses to load still has to be checked, which
	// is what the raw modular exponentiation below is for; every other key
	// takes the standard library's own verification.
	if e.BitLen() <= 31 {
		public := &rsa.PublicKey{N: n, E: int(e.Int64())}
		cryptoHash, ok := rsaCryptoHash(algorithm)
		if !ok {
			return ErrMissingDNSKEY
		}
		if err := rsa.VerifyPKCS1v15(public, cryptoHash, hashed, signature); err != nil {
			return dns.ErrSig
		}
		return nil
	}
	return rsaVerifyPKCS1v15(n, e, prefix, hashed, signature)
}

func verifyECDSASignature(k *dns.DNSKEY, algorithm uint8, signed, signature []byte) error {
	curve, hasher, ok := ecdsaParameters(algorithm)
	if !ok {
		return ErrMissingDNSKEY
	}

	// RFC 6605 §4: the key is the two coordinates, the signature is r and s,
	// each of them a fixed-width unsigned integer for the curve.
	public, err := fromBase64([]byte(k.PublicKey))
	if err != nil {
		return ErrMissingDNSKEY
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(public) != 2*size {
		return ErrMissingDNSKEY
	}
	if len(signature) != 2*size {
		return dns.ErrSig
	}

	x := new(big.Int).SetBytes(public[:size])
	y := new(big.Int).SetBytes(public[size:])
	hasher.Write(signed)
	hashed := hasher.Sum(nil)

	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, hashed, r, s) {
		return dns.ErrSig
	}
	return nil
}

func verifyEd25519Signature(k *dns.DNSKEY, signed, signature []byte) error {
	// RFC 8080 §2: Ed25519 signs the message itself, not a digest of it.
	public, err := fromBase64([]byte(k.PublicKey))
	if err != nil || len(public) != ed25519.PublicKeySize {
		return ErrMissingDNSKEY
	}
	if len(signature) != ed25519.SignatureSize {
		return dns.ErrSig
	}
	if !ed25519.Verify(ed25519.PublicKey(public), signed, signature) {
		return dns.ErrSig
	}
	return nil
}

// ecdsaParameters returns the curve and digest RFC 6605 pairs with an
// algorithm. The pairing is fixed by the RFC: a mismatch is not a variant to
// support but a signature to refuse.
func ecdsaParameters(algorithm uint8) (elliptic.Curve, hash.Hash, bool) {
	switch algorithm {
	case dns.ECDSAP256SHA256:
		return elliptic.P256(), sha256.New(), true
	case dns.ECDSAP384SHA384:
		return elliptic.P384(), sha512.New384(), true
	}
	return nil, nil, false
}

// rsaCryptoHash is rsaHash's digest identity, which crypto/rsa needs to
// rebuild the PKCS#1 v1.5 prefix itself.
func rsaCryptoHash(algorithm uint8) (crypto.Hash, bool) {
	switch algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return crypto.SHA1, true
	case dns.RSASHA256:
		return crypto.SHA256, true
	case dns.RSASHA512:
		return crypto.SHA512, true
	}
	return 0, false
}
