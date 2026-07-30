package dnssec

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

var (
	errCandidateLimit = errors.New("test DNSKEY candidate limit")
	errRRsetLimit     = errors.New("test RRset signature limit")
	errGraphLimit     = errors.New("test graph signature limit")
)

type countingVerifyWork struct {
	candidateLimit uint32
	rrsetLimit     uint32
	graphLimit     uint32

	signatures uint32
	digests    uint32
	releases   uint32
}

func (w *countingVerifyWork) CheckDNSKEYCandidate(used uint32) error {
	if w.candidateLimit > 0 && used >= w.candidateLimit {
		return errCandidateLimit
	}
	return nil
}

func (w *countingVerifyWork) CheckRRsetSignature(used uint32) error {
	if w.rrsetLimit > 0 && used >= w.rrsetLimit {
		return errRRsetLimit
	}
	return nil
}

func (w *countingVerifyWork) BeginSignature() (func(), error) {
	if w.graphLimit > 0 && w.signatures >= w.graphLimit {
		return nil, errGraphLimit
	}
	w.signatures++
	return func() { w.releases++ }, nil
}

func (w *countingVerifyWork) BeginDSDigest() (func(), error) {
	w.digests++
	return func() { w.releases++ }, nil
}

func TestVerifyRRSIGWorkStopsBeforeNinthRRsetOperation(t *testing.T) {
	// The fixture's final signature is valid. Keep only the one hundred
	// leading signatures, all of which cover different RDATA, so no successful
	// verification can end the test before the local RRset ceiling.
	fixture := newWorkFactorRRSIGFixture(t, 101, 1)
	msg := new(dns.Msg)
	msg.SetQuestion(fixture.rrset[0].Header().Name, dns.TypeA)
	msg.Answer = append(msg.Answer, fixture.rrset...)
	for _, sig := range fixture.signatures[:100] {
		msg.Answer = append(msg.Answer, sig)
	}

	work := &countingVerifyWork{
		candidateLimit: 4,
		rrsetLimit:     8,
		graphLimit:     32,
	}
	ok, err := VerifyRRSIGWithWork(workFactorZone, fixture.keys, msg, work)
	if ok || !IsWorkError(err) || !errors.Is(err, errRRsetLimit) {
		t.Fatalf("VerifyRRSIGWithWork = (%v, %v), want wrapped RRset limit", ok, err)
	}
	if work.signatures != 8 {
		t.Fatalf("signature operations = %d, want 8", work.signatures)
	}
	if work.releases != work.signatures {
		t.Fatalf("signature releases = %d, want %d", work.releases, work.signatures)
	}
}

func TestVerifyRRSIGWorkStopsBeforeFifthCandidate(t *testing.T) {
	fixture := newWorkFactorRRSIGFixture(t, 1, 5)
	work := &countingVerifyWork{
		candidateLimit: 4,
		rrsetLimit:     8,
		graphLimit:     32,
	}

	ok, err := verifyRRSIGWithWork(
		workFactorZone,
		fixture.keys,
		fixture.msg,
		func(*dns.DNSKEY, *dns.RRSIG, []dns.RR) error {
			return dns.ErrSig
		},
		work,
	)
	if ok || !IsWorkError(err) || !errors.Is(err, errCandidateLimit) {
		t.Fatalf("verifyRRSIGWithWork = (%v, %v), want wrapped candidate limit", ok, err)
	}
	if work.signatures != 4 {
		t.Fatalf("signature operations = %d, want 4", work.signatures)
	}
	if work.releases != work.signatures {
		t.Fatalf("signature releases = %d, want %d", work.releases, work.signatures)
	}
}

func TestVerifyRRSIGWorkRejectsThirtyThirdGraphOperation(t *testing.T) {
	fixture := newWorkFactorRRSIGFixture(t, 1, 4)
	work := &countingVerifyWork{
		candidateLimit: 4,
		rrsetLimit:     8,
		graphLimit:     32,
	}
	verify := func(*dns.DNSKEY, *dns.RRSIG, []dns.RR) error {
		return dns.ErrSig
	}

	for i := 0; i < 8; i++ {
		ok, err := verifyRRSIGWithWork(workFactorZone, fixture.keys, fixture.msg, verify, work)
		if ok || IsWorkError(err) {
			t.Fatalf("bounded verification %d = (%v, %v), want ordinary signature failure", i, ok, err)
		}
	}
	ok, err := verifyRRSIGWithWork(workFactorZone, fixture.keys, fixture.msg, verify, work)
	if ok || !IsWorkError(err) || !errors.Is(err, errGraphLimit) {
		t.Fatalf("thirty-third verification = (%v, %v), want wrapped graph limit", ok, err)
	}
	if work.signatures != 32 {
		t.Fatalf("signature operations = %d, want 32", work.signatures)
	}
	if work.releases != work.signatures {
		t.Fatalf("signature releases = %d, want %d", work.releases, work.signatures)
	}
}

func TestVerifyRRSIGCandidatesDeduplicateAndSortDeterministically(t *testing.T) {
	fixture := newWorkFactorRRSIGFixture(t, 1, 4)
	original := append([]*dns.DNSKEY(nil), fixture.keys[fixture.goodKey.KeyTag()]...)
	permuted := append([]*dns.DNSKEY(nil), original...)
	slices.Reverse(permuted)
	permuted = append(permuted, permuted...)

	run := func(candidates []*dns.DNSKEY) []string {
		t.Helper()
		keys := map[uint16][]*dns.DNSKEY{fixture.goodKey.KeyTag(): candidates}
		var order []string
		_, err := verifyRRSIGWithWork(
			workFactorZone,
			keys,
			fixture.msg,
			func(key *dns.DNSKEY, _ *dns.RRSIG, _ []dns.RR) error {
				order = append(order, key.PublicKey)
				return dns.ErrSig
			},
			nil,
		)
		if err == nil {
			t.Fatal("all-failing candidate fixture unexpectedly verified")
		}
		return order
	}

	want := run(original)
	got := run(permuted)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate order changed under permutation:\n got %q\nwant %q", got, want)
	}
	if len(got) != len(original) {
		t.Fatalf("candidate operations after duplicate injection = %d, want %d", len(got), len(original))
	}
}

func TestVerifyRRSIGSignaturesDeduplicateAndSortDeterministically(t *testing.T) {
	fixture := newWorkFactorRRSIGFixture(t, 5, 1)
	signatures := append([]*dns.RRSIG(nil), fixture.signatures[:4]...)

	makeMsg := func(sigs []*dns.RRSIG) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion(fixture.rrset[0].Header().Name, dns.TypeA)
		msg.Answer = append(msg.Answer, fixture.rrset...)
		for _, sig := range sigs {
			msg.Answer = append(msg.Answer, sig)
		}
		return msg
	}
	run := func(sigs []*dns.RRSIG) []string {
		t.Helper()
		var order []string
		_, err := verifyRRSIGWithWork(
			workFactorZone,
			fixture.keys,
			makeMsg(sigs),
			func(_ *dns.DNSKEY, sig *dns.RRSIG, _ []dns.RR) error {
				order = append(order, sig.Signature)
				return dns.ErrSig
			},
			nil,
		)
		if err == nil {
			t.Fatal("all-failing signature fixture unexpectedly verified")
		}
		return order
	}

	want := run(signatures)
	permuted := append([]*dns.RRSIG(nil), signatures...)
	slices.Reverse(permuted)
	permuted = append(permuted, permuted...)
	got := run(permuted)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("signature order changed under permutation:\n got %q\nwant %q", got, want)
	}
	if len(got) != len(signatures) {
		t.Fatalf("signature operations after duplicate injection = %d, want %d", len(got), len(signatures))
	}
}

func TestVerifyDSWorkStopsBeforeFifthCandidate(t *testing.T) {
	fixture := newWorkFactorDSFixture(t, 1, 5)
	work := &countingVerifyWork{candidateLimit: 4}

	unsupportedOnly, err := verifyDSWithWork(
		fixture.keys,
		fixture.parentDSSet,
		func(key *dns.DNSKEY, digestType uint8) *dns.DS {
			ds := key.ToDS(digestType)
			if ds != nil {
				ds.Digest = "00"
			}
			return ds
		},
		work,
	)
	if unsupportedOnly || !IsWorkError(err) || !errors.Is(err, errCandidateLimit) {
		t.Fatalf("verifyDSWithWork = (%v, %v), want unsupportedOnly=false and wrapped candidate limit",
			unsupportedOnly, err)
	}
	if work.digests != 4 {
		t.Fatalf("digest operations = %d, want 4", work.digests)
	}
	if work.releases != work.digests {
		t.Fatalf("digest releases = %d, want %d", work.releases, work.digests)
	}
}

func TestVerifyDSCandidatesDeduplicateAndSortDeterministically(t *testing.T) {
	fixture := newWorkFactorDSFixture(t, 1, 4)
	tag := fixture.parentDSSet[0].(*dns.DS).KeyTag
	original := append([]*dns.DNSKEY(nil), fixture.keys[tag]...)
	permuted := append([]*dns.DNSKEY(nil), original...)
	slices.Reverse(permuted)
	permuted = append(permuted, permuted...)

	run := func(candidates []*dns.DNSKEY) []string {
		t.Helper()
		keys := map[uint16][]*dns.DNSKEY{tag: candidates}
		var order []string
		_, err := verifyDSWithWork(
			keys,
			fixture.parentDSSet,
			func(key *dns.DNSKEY, digestType uint8) *dns.DS {
				order = append(order, key.PublicKey)
				ds := key.ToDS(digestType)
				if ds != nil {
					ds.Digest = "00"
				}
				return ds
			},
			nil,
		)
		if err == nil {
			t.Fatal("all-mismatching DS fixture unexpectedly verified")
		}
		return order
	}

	want := run(original)
	got := run(permuted)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DS candidate order changed under permutation:\n got %q\nwant %q", got, want)
	}
	if len(got) != len(original) {
		t.Fatalf("digest operations after duplicate injection = %d, want %d", len(got), len(original))
	}
}
