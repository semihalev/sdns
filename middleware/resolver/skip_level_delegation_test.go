package resolver

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

type cannedByQnameAndType struct {
	byKey map[string]*dns.Msg
}

func (s *cannedByQnameAndType) Get(req *dns.Msg) (*dns.Msg, bool) {
	k := fmt.Sprintf("%s:%d", strings.ToLower(req.Question[0].Name), req.Question[0].Qtype)
	if m, ok := s.byKey[k]; ok {
		return m.Copy(), true
	}
	return nil, false
}

func (s *cannedByQnameAndType) SetFromResponse(resp *dns.Msg, keyCD bool, cutUntil time.Time) {}

// Test_ValidateDelegation_SkipLevelInsecureCut tests the scenario where a
// signed parent zone (e.g. "uy.") receives a delegation for a multi-label
// grandchild (e.g. "elpais.com.uy.") whose intermediate cut (e.g. "com.uy.")
// is an insecure delegation proven by NSEC3 in the parent.
//
// validateDelegation must walk the candidate cuts from parent towards qname,
// prove the intermediate cut is insecure via NSEC3, and accept the delegation
// as insecure (parentDS = nil) without failing.
func Test_ValidateDelegation_SkipLevelInsecureCut(t *testing.T) {
	parent := "parent.test."
	key, priv := makeZoneKeyRes(t, parent)
	parentDS := []dns.RR{key.ToDS(dns.SHA256)}

	apexHash := dns.HashName(parent, dns.SHA1, 0, "")

	// Find child label covered by apex opt-out NSEC3
	var sub string
	for _, label := range []string{"com", "sub", "net", "org", "co"} {
		h := dns.HashName(label+"."+parent, dns.SHA1, 0, "")
		if h > apexHash && h < strings.Repeat("V", 32) {
			sub = label + "." + parent
			break
		}
	}
	if sub == "" {
		t.Fatal("no candidate sub label hashed into the covered span")
	}

	target := "target." + sub

	apexNSEC3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: apexHash + "." + parent, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       dns.SHA1,
		Flags:      1, // opt-out insecure delegation proof
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: strings.Repeat("V", 32),
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
	}
	nsec3Sig := signRRSetRes(t, key, priv, []dns.RR{apexNSEC3})

	// DS response for the intermediate cut (sub.parent.test.): returns NSEC3 proving insecure delegation
	subDSResp := new(dns.Msg)
	subDSResp.SetQuestion(sub, dns.TypeDS)
	subDSResp.Response = true
	subDSResp.Ns = []dns.RR{apexNSEC3, nsec3Sig}

	// DNSKEY response for parent.test.
	parentKeyResp := new(dns.Msg)
	parentKeyResp.SetQuestion(parent, dns.TypeDNSKEY)
	parentKeyResp.Response = true
	parentKeyResp.Answer = []dns.RR{key}

	r := &Resolver{}
	var store middleware.Store = &cannedByQnameAndType{byKey: map[string]*dns.Msg{
		fmt.Sprintf("%s:%d", sub, dns.TypeDS):         subDSResp,
		fmt.Sprintf("%s:%d", parent, dns.TypeDNSKEY): parentKeyResp,
	}}
	r.store.Store(&store)

	clientReq := new(dns.Msg)
	clientReq.SetQuestion("www."+target, dns.TypeA)

	// Delegation message from authority: returns NS for target.sub.parent.test. without RRSIG
	delegationResp := new(dns.Msg)
	delegationResp.SetReply(clientReq)
	delegationResp.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.target." + sub,
		},
	}

	q := dns.Question{Name: target, Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	newParentDS, err := r.validateDelegation(context.Background(), clientReq, delegationResp, q, parentDS, parent)
	if err != nil {
		t.Fatalf("validateDelegation failed on skip-level insecure delegation: %v", err)
	}
	if len(newParentDS) != 0 {
		t.Fatalf("expected newParentDS to be empty (insecure delegation), got %v", newParentDS)
	}
}

// Test_ValidateDelegation_SkipLevelBothSigned tests the scenario where both the
// intermediate cut and the grandchild have valid DS records.
func Test_ValidateDelegation_SkipLevelBothSigned(t *testing.T) {
	parent := "parent.test."
	parentKey, parentPriv := makeZoneKeyRes(t, parent)
	parentDS := []dns.RR{parentKey.ToDS(dns.SHA256)}

	sub := "sub." + parent
	subKey, subPriv := makeZoneKeyRes(t, sub)
	subDSRR := subKey.ToDS(dns.SHA256)
	subDSSig := signRRSetRes(t, parentKey, parentPriv, []dns.RR{subDSRR})

	target := "target." + sub
	targetKey, _ := makeZoneKeyRes(t, target)
	targetDSRR := targetKey.ToDS(dns.SHA256)
	targetDSSig := signRRSetRes(t, subKey, subPriv, []dns.RR{targetDSRR})

	// Parent responses
	parentKeyResp := new(dns.Msg)
	parentKeyResp.SetQuestion(parent, dns.TypeDNSKEY)
	parentKeyResp.Response = true
	parentKeyResp.Answer = []dns.RR{parentKey}

	subDSResp := new(dns.Msg)
	subDSResp.SetQuestion(sub, dns.TypeDS)
	subDSResp.Response = true
	subDSResp.Answer = []dns.RR{subDSRR, subDSSig}

	// Sub responses
	subKeyResp := new(dns.Msg)
	subKeyResp.SetQuestion(sub, dns.TypeDNSKEY)
	subKeyResp.Response = true
	subKeyResp.Answer = []dns.RR{subKey}

	targetDSResp := new(dns.Msg)
	targetDSResp.SetQuestion(target, dns.TypeDS)
	targetDSResp.Response = true
	targetDSResp.Answer = []dns.RR{targetDSRR, targetDSSig}

	r := &Resolver{}
	var store middleware.Store = &cannedByQnameAndType{byKey: map[string]*dns.Msg{
		fmt.Sprintf("%s:%d", parent, dns.TypeDNSKEY): parentKeyResp,
		fmt.Sprintf("%s:%d", sub, dns.TypeDS):         subDSResp,
		fmt.Sprintf("%s:%d", sub, dns.TypeDNSKEY):     subKeyResp,
		fmt.Sprintf("%s:%d", target, dns.TypeDS):      targetDSResp,
	}}
	r.store.Store(&store)

	clientReq := new(dns.Msg)
	clientReq.SetQuestion("www."+target, dns.TypeA)

	delegationResp := new(dns.Msg)
	delegationResp.SetReply(clientReq)
	delegationResp.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.target." + sub,
		},
	}

	q := dns.Question{Name: target, Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	newParentDS, err := r.validateDelegation(context.Background(), clientReq, delegationResp, q, parentDS, parent)
	if err != nil {
		t.Fatalf("validateDelegation failed on skip-level signed delegation: %v", err)
	}
	if len(newParentDS) != 1 {
		t.Fatalf("expected 1 DS for target, got %d", len(newParentDS))
	}
	if newParentDS[0].Header().Name != target {
		t.Fatalf("expected DS name %s, got %s", target, newParentDS[0].Header().Name)
	}
}

// Test_ValidateDelegation_SkipLevelForgedDenialFailsClosed tests that a tampered
// intermediate delegation without valid NSEC/NSEC3 proof fails closed.
func Test_ValidateDelegation_SkipLevelForgedDenialFailsClosed(t *testing.T) {
	parent := "parent.test."
	key, _ := makeZoneKeyRes(t, parent)
	parentDS := []dns.RR{key.ToDS(dns.SHA256)}

	sub := "sub." + parent
	target := "target." + sub

	parentKeyResp := new(dns.Msg)
	parentKeyResp.SetQuestion(parent, dns.TypeDNSKEY)
	parentKeyResp.Response = true
	parentKeyResp.Answer = []dns.RR{key}

	// Stripped DS response: NODATA with NO NSEC/NSEC3 records
	subDSResp := new(dns.Msg)
	subDSResp.SetQuestion(sub, dns.TypeDS)
	subDSResp.Response = true

	r := &Resolver{}
	var store middleware.Store = &cannedByQnameAndType{byKey: map[string]*dns.Msg{
		fmt.Sprintf("%s:%d", parent, dns.TypeDNSKEY): parentKeyResp,
		fmt.Sprintf("%s:%d", sub, dns.TypeDS):         subDSResp,
	}}
	r.store.Store(&store)

	clientReq := new(dns.Msg)
	clientReq.SetQuestion("www."+target, dns.TypeA)

	delegationResp := new(dns.Msg)
	delegationResp.SetReply(clientReq)
	delegationResp.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.target." + sub,
		},
	}

	q := dns.Question{Name: target, Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	_, err := r.validateDelegation(context.Background(), clientReq, delegationResp, q, parentDS, parent)
	if err == nil {
		t.Fatal("expected validateDelegation to fail closed on stripped DS denial, got nil")
	}
}
