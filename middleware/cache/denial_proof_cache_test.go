package cache

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type denialProofTestFixture struct {
	msg       *dns.Msg
	soa       *dns.SOA
	soaSig    *dns.RRSIG
	proofs    []dns.RR
	proofSigs []*dns.RRSIG
}

func newDenialProofNSECFixture(
	tb testing.TB,
	now time.Time,
	qname string,
	qtype uint16,
	rcode int,
	zone string,
	intervals ...[2]string,
) *denialProofTestFixture {
	tb.Helper()

	zone = dns.Fqdn(zone)
	qname = dns.Fqdn(qname)
	const ttl = uint32(300)
	expiration := uint32(now.Add(2 * time.Hour).Unix()) //nolint:gosec // test epoch is safely representable by DNSSEC uint32 time

	request := new(dns.Msg)
	request.SetQuestion(qname, qtype)
	msg := new(dns.Msg)
	msg.SetReply(request)
	msg.Rcode = rcode
	msg.AuthenticatedData = true

	soa := denialProofTestSOA(zone, ttl)
	soaSig := denialProofTestSignature(
		zone,
		dns.TypeSOA,
		zone,
		dns.ClassINET,
		ttl,
		expiration,
	)
	fixture := &denialProofTestFixture{
		msg:    msg,
		soa:    soa,
		soaSig: soaSig,
	}
	msg.Ns = append(msg.Ns, soa, soaSig)

	for _, interval := range intervals {
		owner, next := dns.Fqdn(interval[0]), dns.Fqdn(interval[1])
		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			NextDomain: next,
			TypeBitMap: []uint16{
				dns.TypeA,
				dns.TypeRRSIG,
				dns.TypeNSEC,
			},
		}
		sig := denialProofTestSignature(
			owner,
			dns.TypeNSEC,
			zone,
			dns.ClassINET,
			ttl,
			expiration,
		)
		fixture.proofs = append(fixture.proofs, nsec)
		fixture.proofSigs = append(fixture.proofSigs, sig)
		msg.Ns = append(msg.Ns, nsec, sig)
	}
	return fixture
}

func newDenialProofNSEC3Fixture(
	tb testing.TB,
	now time.Time,
	qname string,
	zone string,
	salt string,
	flags uint8,
	iterations uint16,
) *denialProofTestFixture {
	tb.Helper()

	zone = dns.Fqdn(zone)
	qname = dns.Fqdn(qname)
	const ttl = uint32(300)
	expiration := uint32(now.Add(2 * time.Hour).Unix()) //nolint:gosec // test epoch is safely representable by DNSSEC uint32 time
	ownerHash := dns.HashName(qname, dns.SHA1, iterations, salt)

	request := new(dns.Msg)
	request.SetQuestion(qname, dns.TypeAAAA)
	msg := new(dns.Msg)
	msg.SetReply(request)
	msg.Rcode = dns.RcodeSuccess
	msg.AuthenticatedData = true

	soa := denialProofTestSOA(zone, ttl)
	soaSig := denialProofTestSignature(
		zone,
		dns.TypeSOA,
		zone,
		dns.ClassINET,
		ttl,
		expiration,
	)
	nsec3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   ownerHash + "." + zone,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: iterations,
		SaltLength: uint8(len(salt) / 2), //nolint:gosec // fixtures use short salts
		Salt:       salt,
		HashLength: 20,
		NextDomain: ownerHash,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3},
	}
	proofSig := denialProofTestSignature(
		nsec3.Hdr.Name,
		dns.TypeNSEC3,
		zone,
		dns.ClassINET,
		ttl,
		expiration,
	)
	msg.Ns = []dns.RR{soa, soaSig, nsec3, proofSig}
	return &denialProofTestFixture{
		msg:       msg,
		soa:       soa,
		soaSig:    soaSig,
		proofs:    []dns.RR{nsec3},
		proofSigs: []*dns.RRSIG{proofSig},
	}
}

func denialProofTestSOA(zone string, ttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      "ns1." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  ttl,
	}
}

func denialProofTestSignature(
	owner string,
	covered uint16,
	zone string,
	qclass uint16,
	ttl uint32,
	expiration uint32,
) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeRRSIG,
			Class:  qclass,
			Ttl:    ttl,
		},
		TypeCovered: covered,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(dns.CountLabel(owner)), //nolint:gosec // DNS wire names have a bounded label count
		OrigTtl:     ttl,
		Expiration:  expiration,
		Inception:   expiration - 10800,
		KeyTag:      1,
		SignerName:  zone,
		Signature:   "fixture",
	}
}

func newDenialProofTestCache(
	now *time.Time,
	maxEntries int,
	perZone int,
	maxTTL time.Duration,
) *denialProofCache {
	return newDenialProofCacheWithConfig(denialProofCacheConfig{
		MaxEntries:        maxEntries,
		MaxEntriesPerZone: perZone,
		MaxBytes:          denialProofDerivedBytes(maxEntries),
		MaxBytesPerZone:   denialProofDerivedBytes(perZone),
		MaxTTL:            maxTTL,
		Now: func() time.Time {
			return *now
		},
	})
}

func denialProofTestRequest(name string, qtype uint16, do bool) *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), qtype)
	request.Id = 4242
	if do {
		request.SetEdns0(1232, true)
	}
	return request
}

func denialProofCountType(records []dns.RR, rrtype uint16) int {
	count := 0
	for _, rr := range records {
		if rr.Header().Rrtype == rrtype {
			count++
		}
	}
	return count
}

func TestNewDenialProofCacheNormalizesHardLimits(t *testing.T) {
	cache := newDenialProofCache(0, 24*time.Hour)
	if cache.maxEntries != 1 ||
		cache.maxEntriesPerZone != 1 ||
		cache.maxBytes != maxDenialProofBundleBytes ||
		cache.maxBytesPerZone != maxDenialProofBundleBytes ||
		cache.maxTTL != maxDenialProofTTL {
		t.Fatalf(
			"normalized limits = entries %d/%d bytes %d/%d TTL %s",
			cache.maxEntries,
			cache.maxEntriesPerZone,
			cache.maxBytes,
			cache.maxBytesPerZone,
			cache.maxTTL,
		)
	}
}

func TestDenialProofCanonicalNameOrder(t *testing.T) {
	names := []string{
		"z.com.",
		"b.example.com.",
		".",
		"a.example.com.",
		"example.com.",
		"com.",
	}
	sort.Slice(names, func(i, j int) bool {
		return denialProofNameOrderFor(names[i]).compare(denialProofNameOrderFor(names[j])) < 0
	})
	want := []string{
		".",
		"com.",
		"example.com.",
		"a.example.com.",
		"b.example.com.",
		"z.com.",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("canonical order = %v, want %v", names, want)
	}
}

func TestDenialProofCacheNSECNODATAAndDOShaping(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSECFixture(
		t,
		now,
		"www.example.",
		dns.TypeAAAA,
		dns.RcodeSuccess,
		"example.",
		[2]string{"www.example.", "z.example."},
	)
	cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)

	if !cache.record(fixture.msg, "EXAMPLE", time.Time{}) {
		t.Fatal("validated NSEC NODATA proof was not admitted")
	}
	if got, want := cache.len(), 2; got != want {
		t.Fatalf("entry count = %d, want %d", got, want)
	}
	if cache.zones() != 1 || cache.bytes() <= 0 {
		t.Fatalf("counters after admission: zones=%d bytes=%d", cache.zones(), cache.bytes())
	}

	// Admission must own a deep copy; mutating the source cannot change the
	// cache's classification or replayed SOA.
	fixture.proofs[0].(*dns.NSEC).TypeBitMap = append(
		fixture.proofs[0].(*dns.NSEC).TypeBitMap,
		dns.TypeAAAA,
	)
	fixture.soa.Serial = 99

	doRequest := denialProofTestRequest("www.example.", dns.TypeAAAA, true)
	response, ok := cache.Lookup(doRequest, nil)
	if !ok {
		t.Fatal("DO=1 NSEC NODATA lookup missed")
	}
	if response.Id != doRequest.Id ||
		response.Rcode != dns.RcodeSuccess ||
		!response.AuthenticatedData ||
		response.Authoritative ||
		response.CheckingDisabled ||
		len(response.Answer) != 0 ||
		len(response.Extra) != 0 ||
		len(response.Question) != 1 ||
		response.Question[0] != doRequest.Question[0] {
		t.Fatalf("malformed synthesized response: %#v", response)
	}
	if denialProofCountType(response.Ns, dns.TypeSOA) != 1 ||
		denialProofCountType(response.Ns, dns.TypeNSEC) != 1 ||
		denialProofCountType(response.Ns, dns.TypeRRSIG) != 2 {
		t.Fatalf("DO=1 authority did not contain complete selected RRsets: %v", response.Ns)
	}
	for _, rr := range response.Ns {
		if rr.Header().Ttl != 300 {
			t.Fatalf("%s TTL = %d, want 300", dns.TypeToString[rr.Header().Rrtype], rr.Header().Ttl)
		}
	}
	if got := response.Ns[0].(*dns.SOA).Serial; got != 1 {
		t.Fatalf("cached SOA serial = %d, source mutation leaked", got)
	}

	do0Request := denialProofTestRequest("www.example.", dns.TypeAAAA, false)
	do0Response, kind, signerZone, _, ok := cache.lookupWithMeta(do0Request, nil)
	if !ok {
		t.Fatal("DO=0 NSEC NODATA lookup missed")
	}
	if kind != denialProofNSEC || signerZone != "example." {
		t.Fatalf("DO=0 metadata = kind %d zone %q", kind, signerZone)
	}
	if len(do0Response.Ns) != 1 ||
		do0Response.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("DO=0 authority leaked DNSSEC records: %v", do0Response.Ns)
	}

	cdRequest := denialProofTestRequest("www.example.", dns.TypeAAAA, true)
	cdRequest.CheckingDisabled = true
	if response, hit := cache.Lookup(cdRequest, nil); hit || response != nil {
		t.Fatalf("CD=1 request received aggressive answer: %#v", response)
	}
}

func TestDenialProofCacheNSECNXDOMAINUsesExactWitnesses(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSECFixture(
		t,
		now,
		"m.example.",
		dns.TypeA,
		dns.RcodeNameError,
		"example.",
		[2]string{"a.example.", "z.example."},
		[2]string{"example.", "a.example."},
	)
	cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
	if !cache.record(fixture.msg, "example.", now.Add(time.Hour)) {
		t.Fatal("validated NSEC NXDOMAIN proof was not admitted")
	}

	request := denialProofTestRequest("m.example.", dns.TypeA, true)
	response, ok := cache.Lookup(request, nil)
	if !ok || response.Rcode != dns.RcodeNameError {
		t.Fatalf("NXDOMAIN lookup = %#v, %v", response, ok)
	}
	if denialProofCountType(response.Ns, dns.TypeNSEC) != 2 ||
		denialProofCountType(response.Ns, dns.TypeRRSIG) != 3 {
		t.Fatalf("NXDOMAIN authority did not contain its two witnesses and signatures: %v", response.Ns)
	}
}

func TestDenialProofCacheStrictAbsoluteTTL(t *testing.T) {
	base := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		maxTTL    time.Duration
		configure func(*denialProofTestFixture) time.Time
		want      time.Duration
	}{
		{
			name:   "configured maximum",
			maxTTL: 25 * time.Second,
			want:   25 * time.Second,
		},
		{
			name:   "SOA TTL",
			maxTTL: maxDenialProofTTL,
			configure: func(f *denialProofTestFixture) time.Time {
				f.soa.Hdr.Ttl = 23
				return time.Time{}
			},
			want: 23 * time.Second,
		},
		{
			name:   "SOA MINIMUM",
			maxTTL: maxDenialProofTTL,
			configure: func(f *denialProofTestFixture) time.Time {
				f.soa.Minttl = 19
				return time.Time{}
			},
			want: 19 * time.Second,
		},
		{
			name:   "proof RR TTL",
			maxTTL: maxDenialProofTTL,
			configure: func(f *denialProofTestFixture) time.Time {
				f.proofs[0].Header().Ttl = 17
				return time.Time{}
			},
			want: 17 * time.Second,
		},
		{
			name:   "RRSIG header TTL",
			maxTTL: maxDenialProofTTL,
			configure: func(f *denialProofTestFixture) time.Time {
				f.proofSigs[0].Hdr.Ttl = 13
				return time.Time{}
			},
			want: 13 * time.Second,
		},
		{
			name:   "RRSIG original TTL",
			maxTTL: maxDenialProofTTL,
			configure: func(f *denialProofTestFixture) time.Time {
				f.proofSigs[0].OrigTtl = 11
				return time.Time{}
			},
			want: 11 * time.Second,
		},
		{
			name:   "absolute signature expiration",
			maxTTL: maxDenialProofTTL,
			configure: func(f *denialProofTestFixture) time.Time {
				f.proofSigs[0].Expiration = uint32(base.Add(7 * time.Second).Unix()) //nolint:gosec // fixed test epoch
				return time.Time{}
			},
			want: 7 * time.Second,
		},
		{
			name:   "delegation cut",
			maxTTL: maxDenialProofTTL,
			configure: func(*denialProofTestFixture) time.Time {
				return base.Add(5 * time.Second)
			},
			want: 5 * time.Second,
		},
		{
			name:   "hard three hour ceiling",
			maxTTL: 24 * time.Hour,
			configure: func(f *denialProofTestFixture) time.Time {
				const fourHours = uint32(4 * 60 * 60)
				f.soa.Hdr.Ttl = fourHours
				f.soa.Minttl = fourHours
				f.soaSig.Hdr.Ttl = fourHours
				f.soaSig.OrigTtl = fourHours
				f.soaSig.Expiration = uint32(base.Add(5 * time.Hour).Unix()) //nolint:gosec // fixed test epoch
				f.proofs[0].Header().Ttl = fourHours
				f.proofSigs[0].Hdr.Ttl = fourHours
				f.proofSigs[0].OrigTtl = fourHours
				f.proofSigs[0].Expiration = uint32(base.Add(5 * time.Hour).Unix()) //nolint:gosec // fixed test epoch
				return time.Time{}
			},
			want: maxDenialProofTTL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := base
			fixture := newDenialProofNSECFixture(
				t,
				now,
				"www.example.",
				dns.TypeAAAA,
				dns.RcodeSuccess,
				"example.",
				[2]string{"www.example.", "z.example."},
			)
			var cut time.Time
			if test.configure != nil {
				cut = test.configure(fixture)
			}
			cache := newDenialProofTestCache(&now, 8, 4, test.maxTTL)
			if !cache.record(fixture.msg, "example.", cut) {
				t.Fatal("proof was not admitted")
			}

			response, ok := cache.Lookup(
				denialProofTestRequest("www.example.", dns.TypeAAAA, true),
				nil,
			)
			if !ok {
				t.Fatal("fresh proof lookup missed")
			}
			wantTTL := uint32(test.want / time.Second) //nolint:gosec // table values are small positive durations
			for _, rr := range response.Ns {
				if rr.Header().Ttl != wantTTL {
					t.Fatalf("%s TTL = %d, want %d", dns.TypeToString[rr.Header().Rrtype], rr.Header().Ttl, wantTTL)
				}
			}

			now = base.Add(test.want + time.Nanosecond)
			if expired, hit := cache.Lookup(
				denialProofTestRequest("www.example.", dns.TypeAAAA, true),
				nil,
			); hit || expired != nil {
				t.Fatalf("expired proof returned a hit: %#v", expired)
			}
		})
	}
}

func TestDenialProofCacheRejectsUnsafeBundles(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		build func(testing.TB) *denialProofTestFixture
		edit  func(*denialProofTestFixture)
	}{
		{
			name: "missing proof signature",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSECFixture(
					tb, now, "www.example.", dns.TypeAAAA, dns.RcodeSuccess,
					"example.", [2]string{"www.example.", "z.example."},
				)
			},
			edit: func(f *denialProofTestFixture) {
				f.msg.Ns = f.msg.Ns[:len(f.msg.Ns)-1]
			},
		},
		{
			name: "NSEC crosses signer zone",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSECFixture(
					tb, now, "www.example.", dns.TypeAAAA, dns.RcodeSuccess,
					"example.", [2]string{"www.example.", "outside.invalid."},
				)
			},
		},
		{
			name: "mixed NSEC and NSEC3",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSECFixture(
					tb, now, "www.example.", dns.TypeAAAA, dns.RcodeSuccess,
					"example.", [2]string{"www.example.", "z.example."},
				)
			},
			edit: func(f *denialProofTestFixture) {
				nsec3Fixture := newDenialProofNSEC3Fixture(
					t, now, "www.example.", "example.", "", 0, 0,
				)
				f.msg.Ns = append(
					f.msg.Ns,
					nsec3Fixture.proofs[0],
					nsec3Fixture.proofSigs[0],
				)
			},
		},
		{
			name: "NSEC3 unknown flags",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSEC3Fixture(
					tb, now, "www.example.", "example.", "", 2, 0,
				)
			},
		},
		{
			name: "NSEC3 excessive iterations",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSEC3Fixture(
					tb, now, "www.example.", "example.", "", 0, 151,
				)
			},
		},
		{
			name: "NSEC3 owner is not one label below zone",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSEC3Fixture(
					tb, now, "www.example.", "example.", "", 0, 0,
				)
			},
			edit: func(f *denialProofTestFixture) {
				nsec3 := f.proofs[0].(*dns.NSEC3)
				nsec3.Hdr.Name = "extra." + nsec3.Hdr.Name
				f.proofSigs[0].Hdr.Name = nsec3.Hdr.Name
			},
		},
		{
			name: "oversized proof bundle",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSECFixture(
					tb, now, "www.example.", dns.TypeAAAA, dns.RcodeSuccess,
					"example.", [2]string{"www.example.", "z.example."},
				)
			},
			edit: func(f *denialProofTestFixture) {
				f.proofSigs[0].Signature = strings.Repeat("A", 16<<10)
			},
		},
		{
			name: "terminal response contains answer data",
			build: func(tb testing.TB) *denialProofTestFixture {
				return newDenialProofNSECFixture(
					tb, now, "www.example.", dns.TypeAAAA, dns.RcodeSuccess,
					"example.", [2]string{"www.example.", "z.example."},
				)
			},
			edit: func(f *denialProofTestFixture) {
				f.msg.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name: "www.example.", Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 60,
					},
				}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.build(t)
			if test.edit != nil {
				test.edit(fixture)
			}
			cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)
			if cache.record(fixture.msg, "example.", time.Time{}) {
				t.Fatal("unsafe proof bundle was admitted")
			}
			if cache.len() != 0 || cache.bytes() != 0 || cache.zones() != 0 {
				t.Fatalf(
					"rejected bundle changed cache: len=%d bytes=%d zones=%d",
					cache.len(),
					cache.bytes(),
					cache.zones(),
				)
			}
		})
	}
}

func TestDenialProofCacheExpectedKindUsesRetainedSignerZone(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSECFixture(
		t,
		now,
		"www.example.",
		dns.TypeAAAA,
		dns.RcodeSuccess,
		"example.",
		[2]string{"www.example.", "z.example."},
	)
	unrelated := newDenialProofNSEC3Fixture(
		t,
		now,
		"www.outside.",
		"outside.",
		"",
		0,
		0,
	)
	fixture.msg.Ns = append(
		fixture.msg.Ns,
		unrelated.proofs[0],
		unrelated.proofSigs[0],
	)

	accepted := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
	if !accepted.recordWithKind(
		fixture.msg,
		"example.",
		denialProofNSEC,
		time.Time{},
	) {
		t.Fatal("out-of-zone NSEC3 caused a false miss for retained NSEC")
	}

	rejected := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
	if rejected.recordWithKind(
		fixture.msg,
		"example.",
		denialProofNSEC3,
		time.Time{},
	) {
		t.Fatal("out-of-zone NSEC3 selected a family not retained from signer zone")
	}
	if rejected.len() != 0 {
		t.Fatalf("wrong-family admission changed cache: len=%d", rejected.len())
	}
}

type denialProofCountingWork struct {
	count atomic.Uint32
	err   error
}

func (w *denialProofCountingWork) BeginNSEC3Hash() (func(), error) {
	w.count.Add(1)
	if w.err != nil {
		return nil, w.err
	}
	return func() {}, nil
}

func TestDenialProofCacheNSEC3UsesBoundedEvaluatorWork(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSEC3Fixture(
		t,
		now,
		"www.example.",
		"example.",
		"CAFE",
		0,
		1,
	)
	cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
	if !cache.record(fixture.msg, "example.", time.Time{}) {
		t.Fatal("usable NSEC3 proof was not admitted")
	}

	work := new(denialProofCountingWork)
	response, kind, signerZone, _, ok := cache.lookupWithMeta(
		denialProofTestRequest("www.example.", dns.TypeAAAA, true),
		work,
	)
	if !ok || response.Rcode != dns.RcodeSuccess {
		t.Fatalf("NSEC3 NODATA lookup = %#v, %v", response, ok)
	}
	if work.count.Load() != 1 {
		t.Fatalf("NSEC3 hashes = %d, want one memoized exact-name hash", work.count.Load())
	}
	if kind != denialProofNSEC3 || signerZone != "example." {
		t.Fatalf("NSEC3 metadata = kind %d zone %q", kind, signerZone)
	}
	if denialProofCountType(response.Ns, dns.TypeNSEC3) != 1 ||
		denialProofCountType(response.Ns, dns.TypeRRSIG) != 2 {
		t.Fatalf("NSEC3 response lost selected RRsets: %v", response.Ns)
	}

	blocked := &denialProofCountingWork{err: errors.New("optional hash unavailable")}
	if response, hit := cache.Lookup(
		denialProofTestRequest("www.example.", dns.TypeAAAA, true),
		blocked,
	); hit || response != nil {
		t.Fatalf("work rejection did not fail open as a cache miss: %#v", response)
	}
}

func TestDenialProofCacheFIFOAndStrictBounds(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 4, 4, maxDenialProofTTL)

	record := func(name, zone string) {
		t.Helper()
		fixture := newDenialProofNSECFixture(
			t,
			now,
			name,
			dns.TypeAAAA,
			dns.RcodeSuccess,
			zone,
			[2]string{name, "z." + dns.Fqdn(zone)},
		)
		if !cache.record(fixture.msg, zone, time.Time{}) {
			t.Fatalf("record %s in %s failed", name, zone)
		}
		if cache.len() > 4 || cache.bytes() > cache.maxBytes {
			t.Fatalf("global bounds overshot: len=%d bytes=%d", cache.len(), cache.bytes())
		}
	}

	record("www.one.", "one.")
	record("www.two.", "two.")
	if _, hit := cache.Lookup(
		denialProofTestRequest("www.one.", dns.TypeAAAA, true),
		nil,
	); !hit {
		t.Fatal("first zone missed before eviction test")
	}
	record("www.three.", "three.")

	// A hit is intentionally not an LRU write. The oldest admission must
	// still be evicted after it was read.
	if response, hit := cache.Lookup(
		denialProofTestRequest("www.one.", dns.TypeAAAA, true),
		nil,
	); hit || response != nil {
		t.Fatalf("hit reordered FIFO; oldest zone survived: %#v", response)
	}
	for _, name := range []string{"www.two.", "www.three."} {
		if _, hit := cache.Lookup(
			denialProofTestRequest(name, dns.TypeAAAA, true),
			nil,
		); !hit {
			t.Fatalf("%s was unexpectedly evicted", name)
		}
	}
	if cache.len() != 4 || cache.zones() != 2 || cache.bytes() > cache.maxBytes {
		t.Fatalf(
			"bounded state = len %d zones %d bytes %d",
			cache.len(),
			cache.zones(),
			cache.bytes(),
		)
	}

	tiny := newDenialProofCacheWithConfig(denialProofCacheConfig{
		MaxEntries:        8,
		MaxEntriesPerZone: 8,
		MaxBytes:          1,
		MaxBytesPerZone:   1,
		MaxTTL:            time.Minute,
		Now:               func() time.Time { return now },
	})
	fixture := newDenialProofNSECFixture(
		t,
		now,
		"www.example.",
		dns.TypeAAAA,
		dns.RcodeSuccess,
		"example.",
		[2]string{"www.example.", "z.example."},
	)
	if tiny.record(fixture.msg, "example.", time.Time{}) {
		t.Fatal("bundle larger than the strict byte bound was admitted")
	}
	if tiny.len() != 0 || tiny.bytes() != 0 {
		t.Fatalf("byte-bound rejection changed cache: len=%d bytes=%d", tiny.len(), tiny.bytes())
	}
}

func TestDenialProofCachePerZoneAndNSEC3GroupBounds(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)

	perZone := newDenialProofTestCache(&now, 16, 3, maxDenialProofTTL)
	names := []string{"a.example.", "b.example.", "c.example."}
	nextNames := []string{"b.example.", "c.example.", "z.example."}
	for index, name := range names {
		fixture := newDenialProofNSECFixture(
			t,
			now,
			name,
			dns.TypeAAAA,
			dns.RcodeSuccess,
			"example.",
			[2]string{name, nextNames[index]},
		)
		if !perZone.record(fixture.msg, "example.", time.Time{}) {
			t.Fatalf("record %s failed", name)
		}
		if perZone.len() > 3 {
			t.Fatalf("per-zone entry bound overshot: %d", perZone.len())
		}
	}
	if response, hit := perZone.Lookup(
		denialProofTestRequest("a.example.", dns.TypeAAAA, true),
		nil,
	); hit || response != nil {
		t.Fatalf("oldest per-zone proof survived FIFO eviction: %#v", response)
	}
	for _, name := range []string{"b.example.", "c.example."} {
		if _, hit := perZone.Lookup(
			denialProofTestRequest(name, dns.TypeAAAA, true),
			nil,
		); !hit {
			t.Fatalf("%s was unexpectedly evicted from per-zone cache", name)
		}
	}

	nsec3Cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
	for index, name := range []string{"a.example.", "b.example.", "c.example."} {
		salt := fmt.Sprintf("%02X", index+1)
		fixture := newDenialProofNSEC3Fixture(
			t,
			now,
			name,
			"example.",
			salt,
			0,
			0,
		)
		if !nsec3Cache.record(fixture.msg, "example.", time.Time{}) {
			t.Fatalf("NSEC3 group %s failed admission", salt)
		}
	}
	key := denialProofZoneKey{zone: "example.", qclass: dns.ClassINET}
	nsec3Cache.mu.RLock()
	groupCount := len(nsec3Cache.zoneIndex[key].nsec3)
	nsec3Cache.mu.RUnlock()
	if groupCount != maxDenialProofNSEC3Groups {
		t.Fatalf("NSEC3 parameter groups = %d, want %d", groupCount, maxDenialProofNSEC3Groups)
	}
	if nsec3Cache.len() != 3 {
		t.Fatalf("NSEC3 bounded entries = %d, want SOA plus two groups", nsec3Cache.len())
	}
}

func TestDenialProofCachePurgeAndStop(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSECFixture(
		t,
		now,
		"www.example.",
		dns.TypeAAAA,
		dns.RcodeSuccess,
		"example.",
		[2]string{"www.example.", "z.example."},
	)
	cache := newDenialProofTestCache(&now, 8, 4, maxDenialProofTTL)
	if !cache.record(fixture.msg, "example.", time.Time{}) {
		t.Fatal("proof admission failed")
	}
	question := dns.Question{
		Name:   "www.example.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	}
	cache.purge(question)
	if response, hit := cache.Lookup(
		denialProofTestRequest("www.example.", dns.TypeAAAA, true),
		nil,
	); hit || response != nil {
		t.Fatalf("purged proof still synthesized: %#v", response)
	}
	if cache.len() != 1 {
		t.Fatalf("targeted purge removed %d entries, want to retain only SOA", 2-cache.len())
	}

	cache.stop()
	if cache.len() != 0 || cache.zones() != 0 || cache.bytes() != 0 {
		t.Fatalf(
			"stop did not clear cache: len=%d zones=%d bytes=%d",
			cache.len(),
			cache.zones(),
			cache.bytes(),
		)
	}
	if cache.record(fixture.msg, "example.", time.Time{}) {
		t.Fatal("stopped cache admitted a new proof")
	}
	if response, hit := cache.Lookup(
		denialProofTestRequest("www.example.", dns.TypeAAAA, true),
		nil,
	); hit || response != nil {
		t.Fatalf("stopped cache returned a response: %#v", response)
	}
}

func TestDenialProofCacheConcurrentCopyOnWrite(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	fixture := newDenialProofNSECFixture(
		t,
		now,
		"www.example.",
		dns.TypeAAAA,
		dns.RcodeSuccess,
		"example.",
		[2]string{"www.example.", "z.example."},
	)
	cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
	request := denialProofTestRequest("www.example.", dns.TypeAAAA, true)
	question := request.Question[0]

	var wait sync.WaitGroup
	for worker := range 8 {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := range 100 {
				switch (worker + iteration) % 3 {
				case 0:
					_ = cache.record(fixture.msg, "example.", time.Time{})
				case 1:
					_, _ = cache.Lookup(request, nil)
				case 2:
					cache.purge(question)
				}
			}
		}(worker)
	}
	wait.Wait()

	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if len(cache.byID) > cache.maxEntries ||
		cache.totalBytes > cache.maxBytes ||
		cache.fifo.Len() != len(cache.byID) {
		t.Fatalf(
			"concurrent global invariants: entries=%d/%d bytes=%d/%d FIFO=%d",
			len(cache.byID),
			cache.maxEntries,
			cache.totalBytes,
			cache.maxBytes,
			cache.fifo.Len(),
		)
	}
	var bytes int64
	for _, entry := range cache.byID {
		bytes += entry.wireBytes
	}
	if bytes != cache.totalBytes {
		t.Fatalf("entry byte sum = %d, counter = %d", bytes, cache.totalBytes)
	}
	for key, snapshot := range cache.zoneIndex {
		if len(cache.zoneEntries[key]) > cache.maxEntriesPerZone ||
			snapshot.wireBytes > cache.maxBytesPerZone {
			t.Fatalf(
				"zone %v invariants: entries=%d/%d bytes=%d/%d",
				key,
				len(cache.zoneEntries[key]),
				cache.maxEntriesPerZone,
				snapshot.wireBytes,
				cache.maxBytesPerZone,
			)
		}
	}
}
