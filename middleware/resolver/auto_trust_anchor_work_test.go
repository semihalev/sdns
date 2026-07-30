package resolver

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

func TestAutoTARefreshFailureCounter(t *testing.T) {
	workErr := &middleware.RecursionWorkLimitError{
		Kind:  middleware.RecursionWorkSignature,
		Limit: 1,
	}
	if got := autoTARefreshFailureCounter(workErr, taRefreshQueryError); got != taRefreshWorkBudget {
		t.Fatal("work-limit error was not classified as AutoTA work-budget failure")
	}
	if got := autoTARefreshFailureCounter(context.DeadlineExceeded, taRefreshQueryError); got != taRefreshTimeout {
		t.Fatal("deadline error was not classified as AutoTA timeout")
	}
	if got := autoTARefreshFailureCounter(errors.New("query failed"), taRefreshQueryError); got != taRefreshQueryError {
		t.Fatal("ordinary error did not preserve the caller's AutoTA fallback result")
	}
}

func TestStageRevocationSelfSignaturesContinuesAfterOrdinaryFailure(t *testing.T) {
	type keyPair struct {
		current *dns.DNSKEY
		revoked *dns.DNSKEY
		signer  crypto.Signer
	}
	newPair := func() keyPair {
		t.Helper()
		for {
			current := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   rootzone,
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Flags:     dns.ZONE | dns.SEP,
				Protocol:  3,
				Algorithm: dns.ED25519,
			}
			privateKey, err := current.Generate(256)
			if err != nil {
				t.Fatalf("Generate DNSKEY: %v", err)
			}
			signer, ok := privateKey.(crypto.Signer)
			if !ok {
				t.Fatalf("private key type = %T, want crypto.Signer", privateKey)
			}
			revoked := *current
			revoked.Flags |= DNSKEYFlagRevoke
			if uint32(revoked.KeyTag()) == uint32(current.KeyTag())+DNSKEYFlagRevoke {
				return keyPair{current: current, revoked: &revoked, signer: signer}
			}
		}
	}

	first := newPair()
	second := newPair()
	for first.revoked.KeyTag() == second.revoked.KeyTag() {
		second = newPair()
	}
	if first.revoked.KeyTag() > second.revoked.KeyTag() {
		first, second = second, first
	}

	signedRRset := []dns.RR{first.revoked, second.revoked}
	now := time.Now()
	validSig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rootzone,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   second.revoked.Algorithm,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // bounded test timestamp
		Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // bounded test timestamp
		KeyTag:      second.revoked.KeyTag(),
		SignerName:  rootzone,
	}
	if err := validSig.Sign(second.signer, signedRRset); err != nil {
		t.Fatalf("Sign DNSKEY RRset: %v", err)
	}
	rrs := []dns.RR{first.revoked, second.revoked, validSig}

	fetched := TrustAnchors{
		first.revoked.KeyTag():  {DNSKey: first.revoked, State: StateStart},
		second.revoked.KeyTag(): {DNSKey: second.revoked, State: StateStart},
	}
	current := TrustAnchors{
		first.current.KeyTag():  {DNSKey: first.current, State: StateValid},
		second.current.KeyTag(): {DNSKey: second.current, State: StateValid},
	}
	fetchedTags := []uint16{first.revoked.KeyTag(), second.revoked.KeyTag()}

	got, err := stageRevocationSelfSignatures(
		rrs,
		fetchedTags,
		fetched,
		current,
		make(Tombstones),
		nil,
	)
	if err != nil {
		t.Fatalf("stageRevocationSelfSignatures: %v", err)
	}
	if got[first.revoked.KeyTag()] {
		t.Fatal("unsigned first revocation accepted")
	}
	if !got[second.revoked.KeyTag()] {
		t.Fatal("valid revocation after ordinary failure was not accepted")
	}
}
