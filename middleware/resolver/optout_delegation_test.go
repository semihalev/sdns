package resolver

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// makeZoneKeyRes generates a KSK for zone; signRRSetRes signs rrset
// with it using a now±6h validity window.
func makeZoneKeyRes(t *testing.T, zone string) (*dns.DNSKEY, crypto.PrivateKey) {
	t.Helper()

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("failed to generate zone key for %s: %s", zone, err)
	}
	return key, priv
}

func signRRSetRes(t *testing.T, key *dns.DNSKEY, priv crypto.PrivateKey, rrset []dns.RR) *dns.RRSIG {
	t.Helper()

	hdr := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdr.Ttl},
		TypeCovered: hdr.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)), //nolint:gosec // G115 - test names have few labels
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(time.Now().Add(6 * time.Hour).Unix()),  //nolint:gosec // G115 - RFC 4034 serial-arithmetic timestamp
		Inception:   uint32(time.Now().Add(-6 * time.Hour).Unix()), //nolint:gosec // G115 - RFC 4034 serial-arithmetic timestamp
		KeyTag:      key.KeyTag(),
		SignerName:  key.Header().Name,
	}
	if err := sig.Sign(priv.(crypto.Signer), rrset); err != nil {
		t.Fatalf("failed to sign %s %s: %s", hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}
	return sig
}

// cannedDNSSECStore serves pre-built DS / DNSKEY responses to
// subQuery so the delegation-proof helpers run without network.
type cannedDNSSECStore struct {
	byQtype map[uint16]*dns.Msg
}

func (s *cannedDNSSECStore) Get(req *dns.Msg) (*dns.Msg, bool) {
	if m, ok := s.byQtype[req.Question[0].Qtype]; ok {
		return m.Copy(), true
	}
	return nil, false
}

func (s *cannedDNSSECStore) SetFromResponse(resp *dns.Msg, keyCD bool) {}

// Test_provenInsecureDelegation_OptOutSpan reproduces issue #506
// (variant 1, tether.edge.apple): a signed parent zone that uses
// NSEC3 OPT-OUT and serves an unsigned child zone from the SAME
// nameservers, so no referral is crossed on the wire and answer()
// falls back to provenInsecureDelegation.
//
// In an opt-out zone an unsigned delegation has NO exact-match NSEC3
// by definition (RFC 5155 §6) — the authenticated DS-NODATA proof is
// the covering opt-out NSEC3. Wire shape captured live from
// c.ns.apple.com for "edge.apple. IN DS" (apex NSEC3, flags=1):
//
//	;; AUTHORITY: apple. SOA …
//	;;            TMJ4….apple. NSEC3 1 1 0 - 3FVF…  NS SOA TXT RRSIG DNSKEY NSEC3PARAM TYPE63
//	;;            TMJ4….apple. RRSIG NSEC3 … apple. …
//
// Conformant validators (Unbound, BIND, delv) treat names under an
// opt-out span as insecure, so provenInsecureDelegation must accept
// the proof. Requiring an exact match here can never succeed for an
// opt-out zone and turns every shared-authority answer under it into
// a false SERVFAIL.
func Test_provenInsecureDelegation_OptOutSpan(t *testing.T) {
	parent := "parent-optout.test."
	key, priv := makeZoneKeyRes(t, parent)
	parentDS := []dns.RR{key.ToDS(dns.SHA256)}

	apexHash := dns.HashName(parent, dns.SHA1, 0, "")

	// Pick a child label whose NSEC3 hash sorts after the apex hash so
	// the single apex NSEC3 (NextDomain at the top of the hash space)
	// covers the child's hash, mirroring the captured .apple response.
	var child string
	for _, label := range []string{"edge", "cdn", "img", "sub", "zone", "app", "dev", "net"} {
		h := dns.HashName(label+"."+parent, dns.SHA1, 0, "")
		if h > apexHash && h < strings.Repeat("V", 32) {
			child = label + "." + parent
			break
		}
	}
	if child == "" {
		t.Fatal("no candidate child label hashed into the covered span")
	}
	qname := "tether." + child

	apexNSEC3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: apexHash + "." + parent, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       dns.SHA1,
		Flags:      1, // opt-out
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: strings.Repeat("V", 32),
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
	}
	nsec3Sig := signRRSetRes(t, key, priv, []dns.RR{apexNSEC3})

	dsResp := new(dns.Msg)
	dsResp.SetQuestion(child, dns.TypeDS)
	dsResp.Response = true
	dsResp.Ns = []dns.RR{apexNSEC3, nsec3Sig}

	keyResp := new(dns.Msg)
	keyResp.SetQuestion(parent, dns.TypeDNSKEY)
	keyResp.Response = true
	keyResp.Answer = []dns.RR{key}

	r := &Resolver{}
	var store middleware.Store = &cannedDNSSECStore{byQtype: map[uint16]*dns.Msg{
		dns.TypeDS:     dsResp,
		dns.TypeDNSKEY: keyResp,
	}}
	r.store.Store(&store)

	if !r.provenInsecureDelegation(context.Background(), parent, qname, parentDS) {
		t.Fatalf("BUG REPRODUCED (issue #506 variant 1): the authenticated opt-out "+
			"NSEC3 proof of the insecure delegation %s was rejected — every "+
			"shared-authority answer under an opt-out parent zone becomes a false "+
			"SERVFAIL", child)
	}
}

// Test_provenInsecureDelegation_StrippedSignaturesStayBogus pins the
// downgrade guard the opt-out fix must NOT relax: for a name that
// exists as ordinary signed data in the parent zone (an attacker
// stripping RRSIGs off it), the DS NODATA proof carries an
// exact-match NSEC3 WITHOUT the NS bit — that is not a delegation,
// and provenInsecureDelegation must keep failing closed.
func Test_provenInsecureDelegation_StrippedSignaturesStayBogus(t *testing.T) {
	parent := "parent-optout.test."
	key, priv := makeZoneKeyRes(t, parent)
	parentDS := []dns.RR{key.ToDS(dns.SHA256)}

	child := "edge." + parent
	childHash := dns.HashName(child, dns.SHA1, 0, "")

	// Exact-match NSEC3 for the child: in-zone data (A/AAAA), no NS bit.
	exactNSEC3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: childHash + "." + parent, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       dns.SHA1,
		Flags:      1,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: strings.Repeat("V", 32),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG},
	}
	nsec3Sig := signRRSetRes(t, key, priv, []dns.RR{exactNSEC3})

	dsResp := new(dns.Msg)
	dsResp.SetQuestion(child, dns.TypeDS)
	dsResp.Response = true
	dsResp.Ns = []dns.RR{exactNSEC3, nsec3Sig}

	keyResp := new(dns.Msg)
	keyResp.SetQuestion(parent, dns.TypeDNSKEY)
	keyResp.Response = true
	keyResp.Answer = []dns.RR{key}

	r := &Resolver{}
	var store middleware.Store = &cannedDNSSECStore{byQtype: map[uint16]*dns.Msg{
		dns.TypeDS:     dsResp,
		dns.TypeDNSKEY: keyResp,
	}}
	r.store.Store(&store)

	if r.provenInsecureDelegation(context.Background(), parent, "tether."+child, parentDS) {
		t.Fatal("a non-delegation name with stripped signatures must stay bogus")
	}
}
