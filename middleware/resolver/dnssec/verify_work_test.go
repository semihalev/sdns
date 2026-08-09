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

func allFailingRRSIGCandidates(tb testing.TB, fixture workFactorRRSIGFixture) map[uint16][]*dns.DNSKEY {
	tb.Helper()
	if len(fixture.wrongSameTagKeys) == 0 {
		tb.Fatal("fixture has no failing same-tag DNSKEY candidates")
	}
	return map[uint16][]*dns.DNSKEY{
		fixture.goodKey.KeyTag(): append([]*dns.DNSKEY(nil), fixture.wrongSameTagKeys...),
	}
}

func mismatchingDSSet(tb testing.TB, records []dns.RR) []dns.RR {
	tb.Helper()
	if len(records) != 1 {
		tb.Fatalf("DS fixture has %d records, want 1", len(records))
	}
	ds, ok := records[0].(*dns.DS)
	if !ok {
		tb.Fatalf("DS fixture record has type %T", records[0])
	}
	mismatch := *ds
	// Keep every cheap compatibility field intact while ensuring no real
	// SHA-256 DNSKEY digest can match.
	mismatch.Digest = "00"
	return []dns.RR{&mismatch}
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
	// The signature was made by fixture.goodKey, but only five eligible
	// same-tag keys with different public material are offered. Real crypto
	// therefore fails four times and reaches the fifth-candidate guard.
	fixture := newWorkFactorRRSIGFixture(t, 1, 6)
	keys := allFailingRRSIGCandidates(t, fixture)
	work := &countingVerifyWork{
		candidateLimit: 4,
		rrsetLimit:     8,
		graphLimit:     32,
	}

	ok, err := VerifyRRSIGWithWork(workFactorZone, keys, fixture.msg, work)
	if ok || !IsWorkError(err) || !errors.Is(err, errCandidateLimit) {
		t.Fatalf("VerifyRRSIGWithWork = (%v, %v), want wrapped candidate limit", ok, err)
	}
	if work.signatures != 4 {
		t.Fatalf("signature operations = %d, want 4", work.signatures)
	}
	if work.releases != work.signatures {
		t.Fatalf("signature releases = %d, want %d", work.releases, work.signatures)
	}
}

func TestVerifyRRSIGWorkRejectsThirtyThirdGraphOperation(t *testing.T) {
	fixture := newWorkFactorRRSIGFixture(t, 1, 5)
	keys := allFailingRRSIGCandidates(t, fixture)
	work := &countingVerifyWork{
		candidateLimit: 4,
		rrsetLimit:     8,
		graphLimit:     32,
	}

	for i := 0; i < 8; i++ {
		ok, err := VerifyRRSIGWithWork(workFactorZone, keys, fixture.msg, work)
		if ok || IsWorkError(err) {
			t.Fatalf("bounded verification %d = (%v, %v), want ordinary signature failure", i, ok, err)
		}
	}
	ok, err := VerifyRRSIGWithWork(workFactorZone, keys, fixture.msg, work)
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
	fixture := newWorkFactorRRSIGFixture(t, 1, 5)
	original := append([]*dns.DNSKEY(nil), fixture.wrongSameTagKeys...)
	permuted := append([]*dns.DNSKEY(nil), original...)
	slices.Reverse(permuted)
	permuted = append(permuted, permuted...)

	wantOrder := uniqueSortedDNSKEYs(original)
	gotOrder := uniqueSortedDNSKEYs(permuted)
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("candidate order changed under permutation:\n got %v\nwant %v", gotOrder, wantOrder)
	}

	run := func(candidates []*dns.DNSKEY) uint32 {
		t.Helper()
		keys := map[uint16][]*dns.DNSKEY{fixture.goodKey.KeyTag(): candidates}
		work := &countingVerifyWork{}
		_, err := VerifyRRSIGWithWork(workFactorZone, keys, fixture.msg, work)
		if err == nil {
			t.Fatal("all-failing candidate fixture unexpectedly verified")
		}
		return work.signatures
	}

	wantOps := run(original)
	gotOps := run(permuted)
	if gotOps != wantOps {
		t.Fatalf("candidate operations changed under permutation+duplicates: got %d, want %d", gotOps, wantOps)
	}
	if int64(gotOps) != int64(len(original)) {
		t.Fatalf("candidate operations after duplicate injection = %d, want %d", gotOps, len(original))
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
	run := func(sigs []*dns.RRSIG) uint32 {
		t.Helper()
		work := &countingVerifyWork{}
		_, err := VerifyRRSIGWithWork(workFactorZone, fixture.keys, makeMsg(sigs), work)
		if err == nil {
			t.Fatal("all-failing signature fixture unexpectedly verified")
		}
		return work.signatures
	}

	permuted := append([]*dns.RRSIG(nil), signatures...)
	slices.Reverse(permuted)
	permuted = append(permuted, permuted...)

	wantOrder := uniqueSortedRRSIGs(signatures)
	gotOrder := uniqueSortedRRSIGs(permuted)
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("signature order changed under permutation:\n got %v\nwant %v", gotOrder, wantOrder)
	}

	wantOps := run(signatures)
	gotOps := run(permuted)
	if gotOps != wantOps {
		t.Fatalf("signature operations changed under permutation+duplicates: got %d, want %d", gotOps, wantOps)
	}
	if int64(gotOps) != int64(len(signatures)) {
		t.Fatalf("signature operations after duplicate injection = %d, want %d", gotOps, len(signatures))
	}
}

func TestVerifyDSWorkStopsBeforeFifthCandidate(t *testing.T) {
	fixture := newWorkFactorDSFixture(t, 1, 5)
	work := &countingVerifyWork{candidateLimit: 4}

	unsupportedOnly, err := VerifyDSWithWork(fixture.keys, mismatchingDSSet(t, fixture.parentDSSet), work)
	if unsupportedOnly || !IsWorkError(err) || !errors.Is(err, errCandidateLimit) {
		t.Fatalf("VerifyDSWithWork = (%v, %v), want unsupportedOnly=false and wrapped candidate limit",
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
	parentDSSet := mismatchingDSSet(t, fixture.parentDSSet)

	wantOrder := uniqueSortedDNSKEYs(original)
	gotOrder := uniqueSortedDNSKEYs(permuted)
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("DS candidate order changed under permutation:\n got %v\nwant %v", gotOrder, wantOrder)
	}

	run := func(candidates []*dns.DNSKEY) uint32 {
		t.Helper()
		keys := map[uint16][]*dns.DNSKEY{tag: candidates}
		work := &countingVerifyWork{}
		_, err := VerifyDSWithWork(keys, parentDSSet, work)
		if err == nil {
			t.Fatal("all-mismatching DS fixture unexpectedly verified")
		}
		return work.digests
	}

	wantOps := run(original)
	gotOps := run(permuted)
	if gotOps != wantOps {
		t.Fatalf("DS candidate operations changed under permutation+duplicates: got %d, want %d", gotOps, wantOps)
	}
	if int64(gotOps) != int64(len(original)) {
		t.Fatalf("digest operations after duplicate injection = %d, want %d", gotOps, len(original))
	}
}
