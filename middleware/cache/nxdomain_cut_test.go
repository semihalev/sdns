package cache

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type nxDomainCutFixture struct {
	msg      *dns.Msg
	soa      *dns.SOA
	proof    dns.RR
	soaSig   *dns.RRSIG
	proofSig *dns.RRSIG
}

func newNXDomainCutFixture(
	tb testing.TB,
	deniedName string,
	zone string,
	qclass uint16,
) *nxDomainCutFixture {
	tb.Helper()

	deniedName = dns.Fqdn(deniedName)
	zone = dns.Fqdn(zone)
	const ttl = uint32(300)
	expiration := uint32(time.Now().Add(time.Hour).Unix()) //nolint:gosec // test time is safely inside the DNSSEC uint32 epoch

	req := new(dns.Msg)
	req.SetQuestion("alias."+zone, dns.TypeA)
	req.Question[0].Qclass = qclass
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = dns.RcodeNameError
	msg.AuthenticatedData = true

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  qclass,
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
	nsecOwner := "a." + zone
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   nsecOwner,
			Rrtype: dns.TypeNSEC,
			Class:  qclass,
			Ttl:    ttl,
		},
		NextDomain: "z." + zone,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	soaSig := nxDomainCutTestSignature(zone, dns.TypeSOA, zone, qclass, ttl, expiration)
	proofSig := nxDomainCutTestSignature(nsecOwner, dns.TypeNSEC, zone, qclass, ttl, expiration)

	// Alias and additional data deliberately accompany the terminal proof.
	// A cut response must never replay either section.
	msg.Answer = []dns.RR{&dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   "alias." + zone,
			Rrtype: dns.TypeCNAME,
			Class:  qclass,
			Ttl:    ttl,
		},
		Target: deniedName,
	}}
	msg.Ns = []dns.RR{soa, nsec, soaSig, proofSig}
	msg.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   "ns1." + zone,
			Rrtype: dns.TypeA,
			Class:  qclass,
			Ttl:    ttl,
		},
		A: []byte{192, 0, 2, 1},
	}}

	return &nxDomainCutFixture{
		msg:      msg,
		soa:      soa,
		proof:    nsec,
		soaSig:   soaSig,
		proofSig: proofSig,
	}
}

func nxDomainCutTestSignature(
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
		Labels:      uint8(dns.CountLabel(owner)), //nolint:gosec // DNS names have at most 127 labels
		OrigTtl:     ttl,
		Expiration:  expiration,
		Inception:   expiration - 7200,
		KeyTag:      1,
		SignerName:  zone,
		Signature:   "fixture",
	}
}

func newNXDomainCutNSEC3Fixture(
	tb testing.TB,
	deniedName string,
	zone string,
	flags uint8,
) *nxDomainCutFixture {
	tb.Helper()

	fixture := newNXDomainCutFixture(tb, deniedName, zone, dns.ClassINET)
	expiration := fixture.proofSig.Expiration
	nsec3Owner := "0123456789abcdefghijklmnopqrstuv." + dns.Fqdn(zone)
	nsec3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   nsec3Owner,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		SaltLength: 0,
		HashLength: 20,
		NextDomain: "11111111111111111111111111111111",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG},
	}
	proofSig := nxDomainCutTestSignature(
		nsec3Owner,
		dns.TypeNSEC3,
		dns.Fqdn(zone),
		dns.ClassINET,
		300,
		expiration,
	)
	fixture.msg.Ns = []dns.RR{fixture.soa, nsec3, fixture.soaSig, proofSig}
	fixture.proof = nsec3
	fixture.proofSig = proofSig
	return fixture
}

func TestNXDomainCutStrictTTLMinimum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxTTL    time.Duration
		configure func(*nxDomainCutFixture) time.Time
		wantTTL   time.Duration
		wantTime  func(*nxDomainCutFixture, time.Time) time.Time
	}{
		{
			name:   "SOA TTL",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.soa.Hdr.Ttl = 11
				return time.Time{}
			},
			wantTTL: 11 * time.Second,
		},
		{
			name:   "SOA MINIMUM",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.soa.Minttl = 12
				return time.Time{}
			},
			wantTTL: 12 * time.Second,
		},
		{
			name:   "denial proof TTL",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.proof.Header().Ttl = 13
				return time.Time{}
			},
			wantTTL: 13 * time.Second,
		},
		{
			name:   "SOA signature TTL",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.soaSig.Hdr.Ttl = 14
				return time.Time{}
			},
			wantTTL: 14 * time.Second,
		},
		{
			name:   "denial signature TTL",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.proofSig.Hdr.Ttl = 15
				return time.Time{}
			},
			wantTTL: 15 * time.Second,
		},
		{
			name:   "RRSIG original TTL",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.proofSig.OrigTtl = 17
				return time.Time{}
			},
			wantTTL: 17 * time.Second,
		},
		{
			name:   "absolute signature expiry",
			maxTTL: 10 * time.Minute,
			configure: func(f *nxDomainCutFixture) time.Time {
				f.proofSig.Expiration = uint32(time.Now().Add(20 * time.Second).Unix()) //nolint:gosec // test time is safely inside the DNSSEC uint32 epoch
				return time.Time{}
			},
			wantTime: func(f *nxDomainCutFixture, _ time.Time) time.Time {
				return time.Unix(int64(f.proofSig.Expiration), 0)
			},
		},
		{
			name:   "delegation cut",
			maxTTL: 10 * time.Minute,
			configure: func(_ *nxDomainCutFixture) time.Time {
				return time.Now().Add(21*time.Second + 125*time.Millisecond)
			},
			wantTime: func(_ *nxDomainCutFixture, cutUntil time.Time) time.Time {
				return cutUntil
			},
		},
		{
			name:   "cache maximum",
			maxTTL: 16 * time.Second,
			configure: func(_ *nxDomainCutFixture) time.Time {
				return time.Time{}
			},
			wantTTL: 16 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newNXDomainCutFixture(t, "missing.example.", "example.", dns.ClassINET)
			cutUntil := tt.configure(fixture)
			cut := newNXDomainCutCache(32, tt.maxTTL)
			t.Cleanup(cut.stop)
			if !cut.record(fixture.msg, "missing.example.", "example.", cutUntil) {
				t.Fatal("valid locally authenticated NXDOMAIN was not recorded")
			}

			entry, ok := cut.lookup(dns.Question{
				Name:   "missing.example.",
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			})
			if !ok {
				t.Fatal("recorded cut was not found")
			}
			if tt.wantTime != nil {
				want := tt.wantTime(fixture, cutUntil)
				if !entry.expires.Equal(want) {
					t.Fatalf("expires = %v, want strict absolute bound %v", entry.expires, want)
				}
				return
			}
			if got := entry.expires.Sub(entry.stored); got != tt.wantTTL {
				t.Fatalf("cut lifetime = %v, want strict minimum %v", got, tt.wantTTL)
			}
		})
	}
}

func TestNXDomainCutDoesNotApplyConfiguredMinTTL(t *testing.T) {
	t.Parallel()

	cfg := CacheConfig{
		Size:        1024,
		PositiveTTL: 10 * time.Minute,
		NegativeTTL: 10 * time.Minute,
		MinTTL:      time.Minute,
		MaxTTL:      10 * time.Minute,
	}
	metrics := &CacheMetrics{}
	store := NewStore(
		NewPositiveCache(cfg.Size/2, cfg.MinTTL, cfg.MaxTTL, metrics),
		NewNegativeCache(cfg.Size/2, cfg.MinTTL, cfg.NegativeTTL, metrics),
		cfg,
	)
	t.Cleanup(store.Stop)

	fixture := newNXDomainCutFixture(t, "short.example.", "example.", dns.ClassINET)
	for _, rr := range fixture.msg.Ns {
		rr.Header().Ttl = 2
	}
	fixture.soa.Minttl = 2

	if !store.RecordNXDomainCut(fixture.msg, "short.example.", "example.", time.Time{}) {
		t.Fatal("valid short-lived cut was not recorded")
	}
	entry, ok := store.LookupNXDomainCut(newQuestionMsg("short.example.", dns.TypeA, dns.ClassINET))
	if !ok {
		t.Fatal("short-lived cut was not found")
	}
	if got := entry.expires.Sub(entry.stored); got != 2*time.Second {
		t.Fatalf("configured MinTTL extended cut to %v, want proof minimum 2s", got)
	}
}

func TestNXDomainCutLookupBoundariesAndDimensions(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCache(32, time.Minute)
	t.Cleanup(cut.stop)
	fixture := newNXDomainCutFixture(t, "missing.example.", "example.", dns.ClassINET)
	if !cut.record(fixture.msg, "MiSsInG.ExAmPlE.", "ExAmPlE.", time.Time{}) {
		t.Fatal("mixed-case validated denial was not recorded")
	}

	hits := []dns.Question{
		{Name: "missing.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "CHILD.MISSING.EXAMPLE.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: "deep.child.missing.example.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
	}
	for _, q := range hits {
		if _, ok := cut.lookup(q); !ok {
			t.Errorf("lookup(%v) missed a matching QTYPE-independent cut", q)
		}
	}

	misses := []dns.Question{
		{Name: "example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "notmissing.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "missing.example.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "child.missing.example.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS},
	}
	for _, q := range misses {
		if entry, ok := cut.lookup(q); ok {
			t.Errorf("lookup(%v) crossed a label/class boundary: %#v", q, entry)
		}
	}
}

func TestNXDomainCutAdmissionRejectsSignerZoneApex(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCache(8, time.Minute)
	t.Cleanup(cut.stop)
	fixture := newNXDomainCutFixture(t, "example.", "example.", dns.ClassINET)

	// A zone apex cannot itself be absent while supplying its SOA and denial
	// proof. Compare after DNS canonicalisation so presentation case cannot
	// bypass this fail-closed admission invariant.
	if cut.record(fixture.msg, "ExAmPlE.", "eXaMpLe.", time.Time{}) {
		t.Fatal("signer-zone apex NXDOMAIN was admitted as a subtree cut")
	}
	if got := cut.len(); got != 0 {
		t.Fatalf("retained cuts = %d, want 0", got)
	}
}

func TestNXDomainCutAllowsExactDenialSignedByRoot(t *testing.T) {
	t.Parallel()

	const ttl = uint32(60)
	expiration := uint32(time.Now().Add(time.Hour).Unix()) //nolint:gosec // test time is safely inside the DNSSEC uint32 epoch
	req := newQuestionMsg("nonexistent.", dns.TypeA, dns.ClassINET)
	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeNameError)
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns:     "a.root-servers.net.",
			Mbox:   "hostmaster.root.",
			Serial: 1,
			Minttl: ttl,
		},
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "aaa.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: "zzz.",
			TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG},
		},
		nxDomainCutTestSignature(".", dns.TypeSOA, ".", dns.ClassINET, ttl, expiration),
		nxDomainCutTestSignature("aaa.", dns.TypeNSEC, ".", dns.ClassINET, ttl, expiration),
	}

	cut := newNXDomainCutCache(8, time.Minute)
	t.Cleanup(cut.stop)
	if !cut.record(msg, "nonexistent.", ".", time.Time{}) {
		t.Fatal("root-signed exact NXDOMAIN was not recorded")
	}
	if _, ok := cut.lookup(dns.Question{
		Name:   "child.nonexistent.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	}); !ok {
		t.Fatal("root-signed denied subtree did not cover its descendant")
	}
}

func TestNXDomainCutUsesDNSASCIICaseFolding(t *testing.T) {
	t.Parallel()

	const (
		kelvinDenied = "\u212A.example."
		asciiDenied  = "k.example."
	)
	cut := newNXDomainCutCache(8, time.Minute)
	t.Cleanup(cut.stop)
	fixture := newNXDomainCutFixture(t, kelvinDenied, "example.", dns.ClassINET)
	if !cut.record(fixture.msg, kelvinDenied, "example.", time.Time{}) {
		t.Fatal("validated non-ASCII octet name was not recorded")
	}

	if _, ok := cut.lookup(dns.Question{
		Name:   "child." + kelvinDenied,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}); !ok {
		t.Fatal("exact Kelvin-sign DNS name missed its cut")
	}
	if entry, ok := cut.lookup(dns.Question{
		Name:   "child." + asciiDenied,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}); ok {
		t.Fatalf("Unicode folding aliased Kelvin-sign and ASCII-k DNS names: %#v", entry)
	}
}

func TestNXDomainCutAdmissionRejectsIncompleteOrOptOutProof(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture func(testing.TB) *nxDomainCutFixture
		mutate  func(*nxDomainCutFixture)
		want    bool
	}{
		{
			name: "complete NSEC proof",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			want: true,
		},
		{
			name: "complete NSEC3 proof",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutNSEC3Fixture(tb, "missing.example.", "example.", 0)
			},
			want: true,
		},
		{
			name: "NSEC3 Opt-Out",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutNSEC3Fixture(tb, "missing.example.", "example.", 1)
			},
		},
		{
			name: "missing SOA",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.msg.Ns = []dns.RR{f.proof, f.soaSig, f.proofSig}
			},
		},
		{
			name: "missing all signatures",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.msg.Ns = []dns.RR{f.soa, f.proof}
			},
		},
		{
			name: "missing SOA signature",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.msg.Ns = []dns.RR{f.soa, f.proof, f.proofSig}
			},
		},
		{
			name: "missing denial signature",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.msg.Ns = []dns.RR{f.soa, f.proof, f.soaSig}
			},
		},
		{
			name: "question and proof class mismatch",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.msg.Question[0].Qclass = dns.ClassCHAOS
			},
		},
		{
			name: "NSEC next domain escapes signer zone",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.proof.(*dns.NSEC).NextDomain = "outside.test."
			},
		},
		{
			name: "checking disabled proof",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.msg.CheckingDisabled = true
			},
		},
		{
			name: "too many retained proof records",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				for i := range maxNXDomainCutProofRRs {
					owner := fmt.Sprintf("pad-%02d.example.", i)
					next := fmt.Sprintf("pad-%02d.example.", i+1)
					nsec := &dns.NSEC{
						Hdr: dns.RR_Header{
							Name:   owner,
							Rrtype: dns.TypeNSEC,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						NextDomain: next,
					}
					f.msg.Ns = append(
						f.msg.Ns,
						nsec,
						nxDomainCutTestSignature(
							owner,
							dns.TypeNSEC,
							"example.",
							dns.ClassINET,
							300,
							f.proofSig.Expiration,
						),
					)
				}
			},
		},
		{
			name: "retained proof exceeds byte cap",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				f.proofSig.Signature = strings.Repeat("A", maxNXDomainCutProofBytes*2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := tt.fixture(t)
			if tt.mutate != nil {
				tt.mutate(fixture)
			}
			cut := newNXDomainCutCache(8, time.Minute)
			t.Cleanup(cut.stop)
			if got := cut.record(fixture.msg, "missing.example.", "example.", time.Time{}); got != tt.want {
				t.Fatalf("record() = %v, want %v", got, tt.want)
			}
			if got := cut.len(); got != boolInt(tt.want) {
				t.Fatalf("retained cuts = %d, want %d", got, boolInt(tt.want))
			}
		})
	}
}

func TestNXDomainCutResponseMaterialization(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCache(32, time.Minute)
	t.Cleanup(cut.stop)
	fixture := newNXDomainCutFixture(t, "missing.example.", "example.", dns.ClassINET)
	if !cut.record(fixture.msg, "missing.example.", "example.", time.Time{}) {
		t.Fatal("valid cut was not recorded")
	}
	entry, ok := cut.lookup(dns.Question{
		Name:   "child.missing.example.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	})
	if !ok {
		t.Fatal("descendant lookup missed")
	}

	do0Req := newQuestionMsg("Child.Missing.Example.", dns.TypeAAAA, dns.ClassINET)
	do0Req.Id = 0x1234
	do0 := entry.response(do0Req)
	assertNXDomainCutResponse(t, do0Req, do0)
	if got := countAuthorityType(do0, dns.TypeSOA); got != 1 {
		t.Fatalf("DO=0 SOA count = %d, want 1", got)
	}
	for _, rrtype := range []uint16{dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG} {
		if got := countAuthorityType(do0, rrtype); got != 0 {
			t.Fatalf("DO=0 retained %d authority records of type %s", got, dns.TypeToString[rrtype])
		}
	}

	// Materializing a stripped response must not mutate the stored proof.
	do1Req := newQuestionMsg("deep.child.missing.example.", dns.TypeTXT, dns.ClassINET)
	do1Req.Id = 0x5678
	do1Req.SetEdns0(1232, true)
	do1 := entry.response(do1Req)
	assertNXDomainCutResponse(t, do1Req, do1)
	if got := countAuthorityType(do1, dns.TypeSOA); got != 1 {
		t.Fatalf("DO=1 SOA count = %d, want 1", got)
	}
	if got := countAuthorityType(do1, dns.TypeNSEC); got != 1 {
		t.Fatalf("DO=1 NSEC count = %d, want 1", got)
	}
	if got := countAuthorityType(do1, dns.TypeRRSIG); got != 2 {
		t.Fatalf("DO=1 RRSIG count = %d, want 2", got)
	}
}

func TestNXDomainCutExpiryAndPurge(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCache(32, time.Minute)
	t.Cleanup(cut.stop)
	fixture := newNXDomainCutFixture(t, "missing.example.", "example.", dns.ClassINET)
	if !cut.record(fixture.msg, "missing.example.", "example.", time.Time{}) {
		t.Fatal("valid cut was not recorded")
	}
	descendant := dns.Question{
		Name:   "child.missing.example.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	}
	entry, ok := cut.lookup(descendant)
	if !ok {
		t.Fatal("precondition: descendant lookup missed")
	}
	entry.expires = time.Now().Add(-time.Second)
	if expired, hit := cut.lookup(descendant); hit {
		t.Fatalf("expired cut was served: %#v", expired)
	}
	if got := cut.len(); got != 0 {
		t.Fatalf("expired cut was not removed, len = %d", got)
	}

	if !cut.record(fixture.msg, "missing.example.", "example.", time.Time{}) {
		t.Fatal("cut could not be re-recorded after expiry")
	}
	cut.purge(dns.Question{
		Name:   "DEEP.CHILD.MISSING.EXAMPLE.",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	})
	if purged, hit := cut.lookup(descendant); hit {
		t.Fatalf("purged ancestor cut was served: %#v", purged)
	}
	if got := cut.len(); got != 0 {
		t.Fatalf("purged cut was retained, len = %d", got)
	}
}

func TestNXDomainCutConcurrentResponseIsolation(t *testing.T) {
	t.Parallel()

	const responseCount = 128
	cut := newNXDomainCutCache(32, time.Minute)
	t.Cleanup(cut.stop)
	fixture := newNXDomainCutFixture(t, "missing.example.", "example.", dns.ClassINET)
	if !cut.record(fixture.msg, "missing.example.", "example.", time.Time{}) {
		t.Fatal("valid cut was not recorded")
	}
	entry, ok := cut.lookup(dns.Question{
		Name:   "missing.example.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	if !ok {
		t.Fatal("recorded cut was not found")
	}

	requests := make([]*dns.Msg, responseCount)
	responses := make([]*dns.Msg, responseCount)
	var wg sync.WaitGroup
	for i := range responses {
		i := i
		requests[i] = newQuestionMsg(
			fmt.Sprintf("host-%03d.missing.example.", i),
			dns.TypeA+uint16(i%2),
			dns.ClassINET,
		)
		requests[i].Id = uint16(i + 1) //nolint:gosec // responseCount is 128
		if i%2 == 0 {
			requests[i].SetEdns0(1232, true)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			responses[i] = entry.response(requests[i])
		}()
	}
	wg.Wait()

	seen := make(map[*dns.Msg]struct{}, responseCount)
	for i, resp := range responses {
		assertNXDomainCutResponse(t, requests[i], resp)
		if _, duplicate := seen[resp]; duplicate {
			t.Fatalf("response %d reused another request's dns.Msg pointer", i)
		}
		seen[resp] = struct{}{}
		wantProof := i%2 == 0
		if got := countAuthorityType(resp, dns.TypeRRSIG) > 0; got != wantProof {
			t.Fatalf("response %d proof presence = %v, want %v", i, got, wantProof)
		}
	}

	if responses[0].Ns[0] == responses[1].Ns[0] {
		t.Fatal("concurrent responses share authority RR pointers")
	}
	responses[0].Question[0].Name = "mutated.example."
	responses[0].Ns[0].Header().Name = "mutated.example."
	responses[0].Ns[0].Header().Ttl = 1
	if responses[1].Question[0] != requests[1].Question[0] {
		t.Fatalf("mutating response 0 changed response 1 question: %v", responses[1].Question[0])
	}
	if got := responses[1].Ns[0].Header().Name; got != "example." {
		t.Fatalf("mutating response 0 changed response 1 authority owner to %q", got)
	}
	if got := entry.msg.Ns[0].Header().Name; got != "example." {
		t.Fatalf("mutating a response changed stored proof owner to %q", got)
	}
}

func newQuestionMsg(name string, qtype, qclass uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.Question[0].Qclass = qclass
	return msg
}

func assertNXDomainCutResponse(tb testing.TB, req, resp *dns.Msg) {
	tb.Helper()
	if resp == nil {
		tb.Fatal("cut response is nil")
		return
	}
	if resp.Id != req.Id {
		tb.Fatalf("response ID = %d, want current request ID %d", resp.Id, req.Id)
	}
	if len(resp.Question) != 1 || resp.Question[0] != req.Question[0] {
		tb.Fatalf("response question = %v, want current request question %v", resp.Question, req.Question)
	}
	if resp.Rcode != dns.RcodeNameError {
		tb.Fatalf("response RCODE = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		tb.Fatalf("cut response replayed %d alias answers", len(resp.Answer))
	}
	if len(resp.Extra) != 0 {
		tb.Fatalf("cut response replayed %d additional records", len(resp.Extra))
	}
}

func countAuthorityType(msg *dns.Msg, rrtype uint16) int {
	count := 0
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == rrtype {
			count++
		}
	}
	return count
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
