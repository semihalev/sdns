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
			name: "same NSEC RRset mixes safe and escaping next domains",
			fixture: func(tb testing.TB) *nxDomainCutFixture {
				return newNXDomainCutFixture(tb, "missing.example.", "example.", dns.ClassINET)
			},
			mutate: func(f *nxDomainCutFixture) {
				safe := f.proof.(*dns.NSEC)
				escaping := dns.Copy(safe).(*dns.NSEC)
				escaping.NextDomain = "outside.test."
				// Both records share the one retained NSEC RRset and its
				// RRSIG. A record-level filter would replay a signature over
				// a different RRset, so the complete cut must be rejected.
				f.msg.Ns = append(f.msg.Ns, escaping)
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

func TestNXDomainCutBudgetDefaultsAndClamps(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCache(16_000, time.Minute)
	t.Cleanup(cut.stop)
	if cut.maxEntries != 16_000 ||
		cut.maxEntriesPerZone != 250 ||
		cut.maxBytes != 16_000*nxDomainCutBudgetBytesPerEntry ||
		cut.maxBytesPerZone != 250*nxDomainCutBudgetBytesPerEntry {
		t.Fatalf(
			"default limits = entries %d/%d bytes %d/%d, want 16000/250 and %d/%d",
			cut.maxEntries,
			cut.maxEntriesPerZone,
			cut.maxBytes,
			cut.maxBytesPerZone,
			16_000*nxDomainCutBudgetBytesPerEntry,
			250*nxDomainCutBudgetBytesPerEntry,
		)
	}

	small := newNXDomainCutCache(1, time.Minute)
	t.Cleanup(small.stop)
	if small.maxEntries != 1 || small.maxEntriesPerZone != 1 {
		t.Fatalf(
			"small entry limits = %d/%d, want 1/1",
			small.maxEntries,
			small.maxEntriesPerZone,
		)
	}
	if small.maxBytes != maxNXDomainCutProofBytes ||
		small.maxBytesPerZone != maxNXDomainCutProofBytes {
		t.Fatalf(
			"small byte limits = %d/%d, want one full proof %d/%d",
			small.maxBytes,
			small.maxBytesPerZone,
			maxNXDomainCutProofBytes,
			maxNXDomainCutProofBytes,
		)
	}

	clamped := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        2,
		MaxEntriesPerZone: 99,
		MaxBytes:          100,
		MaxBytesPerZone:   200,
		MaxTTL:            time.Minute,
	})
	t.Cleanup(clamped.stop)
	if clamped.maxEntriesPerZone != 2 || clamped.maxBytesPerZone != 100 {
		t.Fatalf(
			"clamped limits = entries/zone %d bytes/zone %d, want 2 and 100",
			clamped.maxEntriesPerZone,
			clamped.maxBytesPerZone,
		)
	}
}

func TestNXDomainCutGlobalEntryBudgetEvictsOldest(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        2,
		MaxEntriesPerZone: 2,
		MaxBytes:          1 << 20,
		MaxBytesPerZone:   1 << 20,
		MaxTTL:            time.Minute,
	})
	t.Cleanup(cut.stop)

	mustRecordNXDomainCut(t, cut, "one.alpha.test.", "alpha.test.")
	mustRecordNXDomainCut(t, cut, "two.bravo.test.", "bravo.test.")
	mustRecordNXDomainCut(t, cut, "three.charlie.test.", "charlie.test.")

	assertNXDomainCutLookup(t, cut, "one.alpha.test.", false)
	assertNXDomainCutLookup(t, cut, "two.bravo.test.", true)
	assertNXDomainCutLookup(t, cut, "three.charlie.test.", true)
	assertNXDomainCutAccounting(t, cut)
}

func TestNXDomainCutZoneEntryBudgetEvictsOwnOldestFirst(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        2,
		MaxEntriesPerZone: 1,
		MaxBytes:          1 << 20,
		MaxBytesPerZone:   1 << 20,
		MaxTTL:            time.Minute,
	})
	t.Cleanup(cut.stop)

	mustRecordNXDomainCut(t, cut, "missing.healthy.test.", "healthy.test.")
	mustRecordNXDomainCut(t, cut, "first.attack.test.", "attack.test.")
	// The global cache is full here. Enforcing the attacker's zone before the
	// global FIFO must remove first.attack, not missing.healthy.
	mustRecordNXDomainCut(t, cut, "second.attack.test.", "attack.test.")

	assertNXDomainCutLookup(t, cut, "missing.healthy.test.", true)
	assertNXDomainCutLookup(t, cut, "first.attack.test.", false)
	assertNXDomainCutLookup(t, cut, "second.attack.test.", true)
	assertNXDomainCutAccounting(t, cut)
}

func TestNXDomainCutWireByteBudgets(t *testing.T) {
	t.Parallel()

	t.Run("global", func(t *testing.T) {
		first := newNXDomainCutFixture(t, "one.alpha.test.", "alpha.test.", dns.ClassINET)
		second := newNXDomainCutFixture(t, "two.bravo.test.", "bravo.test.", dns.ClassINET)
		firstBytes := nxDomainCutFixtureWireBytes(t, first, "one.alpha.test.", "alpha.test.")
		secondBytes := nxDomainCutFixtureWireBytes(t, second, "two.bravo.test.", "bravo.test.")

		cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
			MaxEntries:        8,
			MaxEntriesPerZone: 8,
			MaxBytes:          firstBytes + secondBytes - 1,
			MaxBytesPerZone:   firstBytes + secondBytes,
			MaxTTL:            time.Minute,
		})
		t.Cleanup(cut.stop)

		if !cut.record(first.msg, "one.alpha.test.", "alpha.test.", time.Time{}) {
			t.Fatal("first global-byte fixture was not recorded")
		}
		if !cut.record(second.msg, "two.bravo.test.", "bravo.test.", time.Time{}) {
			t.Fatal("second global-byte fixture was not recorded")
		}
		assertNXDomainCutLookup(t, cut, "one.alpha.test.", false)
		assertNXDomainCutLookup(t, cut, "two.bravo.test.", true)
		assertNXDomainCutAccounting(t, cut)
	})

	t.Run("per zone preserves unrelated zone", func(t *testing.T) {
		first := newNXDomainCutFixture(t, "first.attack.test.", "attack.test.", dns.ClassINET)
		second := newNXDomainCutFixture(t, "second.attack.test.", "attack.test.", dns.ClassINET)
		firstBytes := nxDomainCutFixtureWireBytes(t, first, "first.attack.test.", "attack.test.")
		secondBytes := nxDomainCutFixtureWireBytes(t, second, "second.attack.test.", "attack.test.")

		cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
			MaxEntries:        8,
			MaxEntriesPerZone: 8,
			MaxBytes:          1 << 20,
			MaxBytesPerZone:   firstBytes + secondBytes - 1,
			MaxTTL:            time.Minute,
		})
		t.Cleanup(cut.stop)

		mustRecordNXDomainCut(t, cut, "missing.healthy.test.", "healthy.test.")
		if !cut.record(first.msg, "first.attack.test.", "attack.test.", time.Time{}) {
			t.Fatal("first per-zone-byte fixture was not recorded")
		}
		if !cut.record(second.msg, "second.attack.test.", "attack.test.", time.Time{}) {
			t.Fatal("second per-zone-byte fixture was not recorded")
		}

		assertNXDomainCutLookup(t, cut, "missing.healthy.test.", true)
		assertNXDomainCutLookup(t, cut, "first.attack.test.", false)
		assertNXDomainCutLookup(t, cut, "second.attack.test.", true)
		assertNXDomainCutAccounting(t, cut)
	})
}

func TestNXDomainCutOversizedReplacementPreservesCurrent(t *testing.T) {
	t.Parallel()

	const (
		deniedName = "missing.example."
		zone       = "example."
	)
	currentFixture := newNXDomainCutFixture(t, deniedName, zone, dns.ClassINET)
	currentBytes := nxDomainCutFixtureWireBytes(t, currentFixture, deniedName, zone)
	cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        8,
		MaxEntriesPerZone: 8,
		MaxBytes:          maxNXDomainCutProofBytes,
		MaxBytesPerZone:   currentBytes,
		MaxTTL:            time.Minute,
	})
	t.Cleanup(cut.stop)
	if !cut.record(currentFixture.msg, deniedName, zone, time.Time{}) {
		t.Fatal("current cut was not recorded")
	}
	current, ok := cut.lookup(dns.Question{
		Name: deniedName, Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})
	if !ok {
		t.Fatal("current cut missed before replacement")
	}

	replacement := newNXDomainCutFixture(t, deniedName, zone, dns.ClassINET)
	replacement.proofSig.Signature = strings.Repeat("A", 1024)
	replacementBytes := nxDomainCutFixtureWireBytes(t, replacement, deniedName, zone)
	if replacementBytes <= currentBytes || replacementBytes > maxNXDomainCutProofBytes {
		t.Fatalf(
			"replacement bytes = %d, want (%d, %d]",
			replacementBytes,
			currentBytes,
			maxNXDomainCutProofBytes,
		)
	}
	if cut.record(replacement.msg, deniedName, zone, time.Time{}) {
		t.Fatal("replacement exceeding the zone byte budget was admitted")
	}
	retained, ok := cut.lookup(dns.Question{
		Name: deniedName, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET,
	})
	if !ok || retained != current {
		t.Fatalf("oversized replacement displaced current cut: got %#v", retained)
	}
	assertNXDomainCutAccounting(t, cut)
}

func TestNXDomainCutReplacementMovesZoneAccounting(t *testing.T) {
	t.Parallel()

	const deniedName = "missing.child.example."
	cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        8,
		MaxEntriesPerZone: 8,
		MaxBytes:          1 << 20,
		MaxBytesPerZone:   1 << 20,
		MaxTTL:            time.Minute,
	})
	t.Cleanup(cut.stop)

	mustRecordNXDomainCut(t, cut, deniedName, "example.")
	mustRecordNXDomainCut(t, cut, deniedName, "child.example.")

	entry, ok := cut.lookup(dns.Question{
		Name: deniedName, Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})
	if !ok {
		t.Fatal("replacement cut missed")
	}
	if entry.zone != "child.example." {
		t.Fatalf("replacement signer zone = %q, want child.example.", entry.zone)
	}
	cut.mu.RLock()
	_, oldZoneRetained := cut.zones[nxDomainCutZoneKey{zone: "example.", qclass: dns.ClassINET}]
	cut.mu.RUnlock()
	if oldZoneRetained {
		t.Fatal("replacement left stale accounting for the previous signer zone")
	}
	assertNXDomainCutAccounting(t, cut)
}

func TestNXDomainCutConcurrentBudgetAccounting(t *testing.T) {
	t.Parallel()

	const workers = 32
	cut := newNXDomainCutCacheWithConfig(nxDomainCutCacheConfig{
		MaxEntries:        16,
		MaxEntriesPerZone: 8,
		MaxBytes:          64 << 10,
		MaxBytesPerZone:   32 << 10,
		MaxTTL:            time.Minute,
	})
	t.Cleanup(cut.stop)

	fixtures := make([]*nxDomainCutFixture, workers)
	deniedNames := make([]string, workers)
	for i := range workers {
		deniedNames[i] = fmt.Sprintf("host-%02d.attack.test.", i)
		fixtures[i] = newNXDomainCutFixture(t, deniedNames[i], "attack.test.", dns.ClassINET)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for round := range 8 {
				cut.record(fixtures[i].msg, deniedNames[i], "attack.test.", time.Time{})
				cut.lookup(dns.Question{
					Name:   "child." + deniedNames[i],
					Qtype:  dns.TypeA + uint16(round%2),
					Qclass: dns.ClassINET,
				})
				if round%3 == 0 {
					cut.purge(dns.Question{
						Name:   "child." + deniedNames[i],
						Qtype:  dns.TypeTXT,
						Qclass: dns.ClassINET,
					})
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	assertNXDomainCutAccounting(t, cut)
}

func TestNXDomainCutStopClearsStateAndRejectsAdmission(t *testing.T) {
	t.Parallel()

	cut := newNXDomainCutCache(8, time.Minute)
	mustRecordNXDomainCut(t, cut, "missing.example.", "example.")
	mustRecordNXDomainCut(t, cut, "missing.test.", "test.")

	cut.stop()
	assertNXDomainCutAccounting(t, cut)
	cut.mu.RLock()
	stopped := cut.stopped
	zoneCount := len(cut.zones)
	cut.mu.RUnlock()
	if !stopped || zoneCount != 0 {
		t.Fatalf("stop state = stopped:%v zones:%d, want true/0", stopped, zoneCount)
	}

	fixture := newNXDomainCutFixture(t, "after-stop.example.", "example.", dns.ClassINET)
	if cut.record(fixture.msg, "after-stop.example.", "example.", time.Time{}) {
		t.Fatal("stopped cut cache admitted a new entry")
	}
	assertNXDomainCutLookup(t, cut, "after-stop.example.", false)
	assertNXDomainCutAccounting(t, cut)
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
	assertNXDomainCutAccounting(t, cut)

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
	assertNXDomainCutAccounting(t, cut)
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

func mustRecordNXDomainCut(
	tb testing.TB,
	cut *nxDomainCutCache,
	deniedName string,
	zone string,
) {
	tb.Helper()
	fixture := newNXDomainCutFixture(tb, deniedName, zone, dns.ClassINET)
	if !cut.record(fixture.msg, deniedName, zone, time.Time{}) {
		tb.Fatalf("record(%q, %q) = false, want true", deniedName, zone)
	}
}

func nxDomainCutFixtureWireBytes(
	tb testing.TB,
	fixture *nxDomainCutFixture,
	deniedName string,
	zone string,
) int64 {
	tb.Helper()
	proof, _, ok := nxDomainCutProof(
		fixture.msg,
		dns.CanonicalName(deniedName),
		dns.CanonicalName(zone),
	)
	if !ok {
		tb.Fatalf("fixture proof for %q in %q was rejected", deniedName, zone)
	}
	return int64(proof.Len())
}

func assertNXDomainCutLookup(
	tb testing.TB,
	cut *nxDomainCutCache,
	name string,
	want bool,
) {
	tb.Helper()
	entry, ok := cut.lookup(dns.Question{
		Name:   name,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	if ok != want {
		tb.Fatalf("lookup(%q) = (%#v, %v), want hit=%v", name, entry, ok, want)
	}
}

func assertNXDomainCutAccounting(tb testing.TB, cut *nxDomainCutCache) {
	tb.Helper()
	cut.mu.RLock()
	defer cut.mu.RUnlock()

	if got, want := cut.fifo.Len(), len(cut.entries); got != want {
		tb.Fatalf("global FIFO length = %d, entries = %d", got, want)
	}
	if len(cut.entries) > cut.maxEntries {
		tb.Fatalf("entries = %d, global limit = %d", len(cut.entries), cut.maxEntries)
	}

	var (
		globalBytes int64
		globalSeen  = make(map[*nxDomainCutEntry]struct{}, len(cut.entries))
	)
	for element := cut.fifo.Front(); element != nil; element = element.Next() {
		entry, ok := element.Value.(*nxDomainCutEntry)
		if !ok || entry == nil {
			tb.Fatalf("global FIFO contains invalid entry %#v", element.Value)
		}
		if entry.globalElem != element {
			tb.Fatalf("entry %q has stale global FIFO pointer", entry.deniedName)
		}
		if cut.entries[entry.id] != entry {
			tb.Fatalf("global FIFO entry %q is not current", entry.deniedName)
		}
		if _, duplicate := globalSeen[entry]; duplicate {
			tb.Fatalf("global FIFO contains duplicate entry %q", entry.deniedName)
		}
		globalSeen[entry] = struct{}{}
		globalBytes += entry.wireBytes
	}
	if globalBytes != cut.totalBytes {
		tb.Fatalf("summed wire bytes = %d, totalBytes = %d", globalBytes, cut.totalBytes)
	}
	if cut.totalBytes > cut.maxBytes {
		tb.Fatalf("totalBytes = %d, global limit = %d", cut.totalBytes, cut.maxBytes)
	}

	zoneEntryCount := 0
	for key, zoneState := range cut.zones {
		if zoneState == nil || zoneState.fifo.Len() == 0 {
			tb.Fatalf("zone %v retained an empty state", key)
		}
		if zoneState.fifo.Len() > cut.maxEntriesPerZone {
			tb.Fatalf(
				"zone %v entries = %d, limit = %d",
				key,
				zoneState.fifo.Len(),
				cut.maxEntriesPerZone,
			)
		}
		var zoneBytes int64
		for element := zoneState.fifo.Front(); element != nil; element = element.Next() {
			entry, ok := element.Value.(*nxDomainCutEntry)
			if !ok || entry == nil {
				tb.Fatalf("zone %v FIFO contains invalid entry %#v", key, element.Value)
			}
			if entry.zoneKey != key || entry.zoneElem != element {
				tb.Fatalf("zone %v FIFO has stale entry %q", key, entry.deniedName)
			}
			if _, ok := globalSeen[entry]; !ok {
				tb.Fatalf("zone %v entry %q is missing globally", key, entry.deniedName)
			}
			zoneBytes += entry.wireBytes
			zoneEntryCount++
		}
		if zoneBytes != zoneState.wireBytes {
			tb.Fatalf(
				"zone %v summed bytes = %d, state bytes = %d",
				key,
				zoneBytes,
				zoneState.wireBytes,
			)
		}
		if zoneState.wireBytes > cut.maxBytesPerZone {
			tb.Fatalf(
				"zone %v bytes = %d, limit = %d",
				key,
				zoneState.wireBytes,
				cut.maxBytesPerZone,
			)
		}
	}
	if zoneEntryCount != len(cut.entries) {
		tb.Fatalf("zone entry count = %d, global entries = %d", zoneEntryCount, len(cut.entries))
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
