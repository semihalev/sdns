package resolver

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
	"github.com/semihalev/zlog/v2"
)

func Test_searchAddr(t *testing.T) {
	testDomain := "google.com."

	m := new(dns.Msg)
	m.SetQuestion(testDomain, dns.TypeA)

	m.SetEdns0(512, true)
	if !reflect.DeepEqual(isDO(m), true) {
		t.Errorf("true = %v, want %v", true, isDO(m))
	}

	m.Extra = []dns.RR{}
	if !reflect.DeepEqual(isDO(m), false) {
		t.Errorf("false = %v, want %v", false, isDO(m))
	}

	a1 := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		A: net.ParseIP("127.0.0.1")}

	m.Answer = append(m.Answer, a1)

	a2 := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		A: net.ParseIP("192.0.2.1")}

	m.Answer = append(m.Answer, a2)

	addrs, _, found := searchAddrs(m)
	if !reflect.DeepEqual(len(addrs), 1) {
		t.Errorf("1 = %v, want %v", 1, len(addrs))
	}
	if reflect.DeepEqual(addrs[0], netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("netip.MustParseAddr('127.0.0.1') = %v, want a different value", netip.MustParseAddr("127.0.0.1"))
	}
	if !reflect.DeepEqual(addrs[0], netip.MustParseAddr("192.0.2.1")) {
		t.Errorf("netip.MustParseAddr('192.0.2.1') = %v, want %v", netip.MustParseAddr("192.0.2.1"), addrs[0])
	}
	if !reflect.DeepEqual(found, true) {
		t.Errorf("true = %v, want %v", true, found)
	}
}

func Test_extractRRSet(t *testing.T) {
	var rr []dns.RR
	for i := 0; i < 3; i++ {
		a, _ := dns.NewRR(fmt.Sprintf("test.com. 5 IN A 127.0.0.%d", i))
		rr = append(rr, a)
	}

	rre := dnsutil.ExtractRRSet(rr, "test.com.", dns.TypeA)
	if len(rre) != 3 {
		t.Errorf("len(rre) = %d, want %d", len(rre), 3)
	}
}

func Test_extractRRSetMultipleTypes(t *testing.T) {
	var rr []dns.RR
	a, _ := dns.NewRR("test.com. 5 IN A 127.0.0.1")
	aaaa, _ := dns.NewRR("test.com. 5 IN AAAA ::1")
	mx, _ := dns.NewRR("test.com. 5 IN MX 10 mail.test.com.")
	rr = append(rr, a, aaaa, mx)

	// Test with multiple types
	rre := dnsutil.ExtractRRSet(rr, "test.com.", dns.TypeA, dns.TypeAAAA)
	if len(rre) != 2 {
		t.Errorf("len(rre) = %d, want %d", len(rre), 2)
	}

	// Test with empty input
	rre = dnsutil.ExtractRRSet(nil, "", dns.TypeA)
	if rre != nil {
		t.Errorf("rre = %v, want nil", rre)
	}

	// Test with name filter mismatch
	rre = dnsutil.ExtractRRSet(rr, "other.com.", dns.TypeA)
	if len(rre) != 0 {
		t.Errorf("len(rre) = %d, want %d", len(rre), 0)
	}
}

func Test_verifyNSEC(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA}

	// Create NSEC record with A type
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "next.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS},
	}

	// Should find A type
	typeMatch := dnssec.VerifyNSEC(q, []dns.RR{nsec})
	if !(typeMatch) {
		t.Errorf("typeMatch is false")
	}

	// Query for type not in bitmap
	q2 := dns.Question{Name: "example.com.", Qtype: dns.TypeMX}
	typeMatch = dnssec.VerifyNSEC(q2, []dns.RR{nsec})
	if typeMatch {
		t.Errorf("typeMatch is true")
	}
}

func Test_getDnameTarget(t *testing.T) {
	msg := &dns.Msg{}
	msg.Question = []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeA}}

	// No DNAME record
	target := dnsutil.DnameTarget(msg)
	if len(target) != 0 {
		t.Errorf("target not empty: %v", target)
	}

	// Exact-owner match: RFC 6672 §2.3, the DNAME owner itself is
	// *not* redirected, so no target is returned.
	dname := &dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "sub.example.com.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: "target.com.",
	}
	msg.Answer = []dns.RR{dname}
	target = dnsutil.DnameTarget(msg)
	if len(target) != 0 {
		t.Errorf("%s: target not empty: %v", "DNAME owner must not be redirected", target)
	}

	// Test with subdomain
	msg.Question = []dns.Question{{Name: "deep.sub.example.com.", Qtype: dns.TypeA}}
	dname2 := &dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "sub.example.com.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: "newtarget.com.",
	}
	msg.Answer = []dns.RR{dname2}
	target = dnsutil.DnameTarget(msg)
	if !reflect.DeepEqual("deep.newtarget.com.", target) {
		t.Errorf("target = %v, want %v", target, "deep.newtarget.com.")
	}

	// Cousin name: qname shares a suffix with the DNAME owner but is
	// not a descendant. dns.CompareDomainName reports the shared
	// trailing labels regardless of ancestry, so without the explicit
	// ancestor check the helper would rewrite unrelated names.
	msg.Question = []dns.Question{{Name: "other.example.com.", Qtype: dns.TypeA}}
	msg.Answer = []dns.RR{dname2} // DNAME owner is sub.example.com.
	target = dnsutil.DnameTarget(msg)
	if len(target) != 0 {
		t.Errorf("%s: target not empty: %v", "cousin of DNAME owner must not be redirected", target)
	}
}

// Test_verifyRRSIG_RejectsForeignPiggyback pins the defense that
// foreign unsigned RRsets next to signed in-zone data fail the
// validator. Without this, an attacker could piggyback junk foreign
// records on an otherwise-valid response and still get AD=true, in
// violation of RFC 4035 §3.2.3. Signature content is irrelevant, the
// check fires during record collection, before any crypto work.
func Test_verifyRRSIG_RejectsForeignPiggyback(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "irrelevant-test-value",
	}
	keys := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("1.2.3.4"),
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		SignerName:  "example.com.",
		KeyTag:      key.KeyTag(),
	}
	evil := &dns.TXT{
		Hdr: dns.RR_Header{Name: "evil.net.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"gotcha"},
	}
	msg := &dns.Msg{Answer: []dns.RR{a, sig, evil}}

	ok, err := dnssec.VerifyRRSIG("example.com.", keys, msg)
	if ok {
		t.Errorf("ok is true")
	}
	if !reflect.DeepEqual(dnssec.ErrMissingSigned, err) {
		t.Errorf("%s: err = %v, want %v", "foreign RRset must make the whole response bogus", err, dnssec.ErrMissingSigned)
	}
}

// Test_isSupportedDNSKEYAlgorithm_RSAMD5 locks in the RFC 8624 /
// miekg/dns reality that RSAMD5 is not verifiable: if the DS-level
// filter ever classifies it as supported again, an RSAMD5-only DS set
// would be treated as usable and then bogus at RRSIG.Verify time
// instead of downgraded to insecure.
func Test_isSupportedDNSKEYAlgorithm_RSAMD5(t *testing.T) {
	if dnssec.IsSupportedDNSKEYAlgorithm(dns.RSAMD5) {
		t.Errorf("%s: dnssec.IsSupportedDNSKEYAlgorithm(dns.RSAMD5) is true", "RSAMD5 must be treated as unsupported, miekg/dns RRSIG.Verify returns ErrAlg for it")
	}
	if !(dnssec.IsSupportedDNSKEYAlgorithm(dns.RSASHA256)) {
		t.Errorf("dnssec.IsSupportedDNSKEYAlgorithm(dns.RSASHA256) is false")
	}
	if !(dnssec.IsSupportedDNSKEYAlgorithm(dns.ECDSAP256SHA256)) {
		t.Errorf("dnssec.IsSupportedDNSKEYAlgorithm(dns.ECDSAP256SHA256) is false")
	}
	if !(dnssec.IsSupportedDNSKEYAlgorithm(dns.ED25519)) {
		t.Errorf("dnssec.IsSupportedDNSKEYAlgorithm(dns.ED25519) is false")
	}
}

// Test_filterToZone_NSECNextDomain pins the defense against the
// "in-zone owner with out-of-zone NextDomain" forgery: an attacker
// should not be able to satisfy the NSEC coverage check with an NSEC
// whose owner is inside the validated zone but whose NextDomain
// straddles a sibling zone, because a legitimate NSEC's NextDomain is
// always another owner in the same zone.
func Test_filterToZone_NSECNextDomain(t *testing.T) {
	crossZone := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
		NextDomain: "z.com.",
	}
	inZone := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "!.example.com.", Rrtype: dns.TypeNSEC},
		NextDomain: "zz.example.com.",
	}

	got := dnsutil.FilterRRsToZone([]dns.RR{crossZone, inZone}, "example.com.")
	if len(got) != 1 {
		t.Errorf("%s: len(got) = %d, want %d", "NSEC with cross-zone NextDomain must be filtered out", len(got), 1)
	}
	if !reflect.DeepEqual("!.example.com.", got[0].Header().Name) {
		t.Errorf("got[0].Header().Name = %v, want %v", got[0].Header().Name, "!.example.com.")
	}
}

func Test_debugLogEnabled(t *testing.T) {
	old := zlog.Default().GetLevel()
	defer zlog.SetLevel(old)

	zlog.SetLevel(zlog.LevelInfo)
	if debugLogEnabled() {
		t.Errorf("debugLogEnabled() is true")
	}
	zlog.SetLevel(zlog.LevelDebug)
	if !(debugLogEnabled()) {
		t.Errorf("debugLogEnabled() is false")
	}
}

// Test_debugLogEnabled_GuardAllocsNothing pins what the guard is for: with
// debug off, a guarded call site must not format the question or box the
// arguments. Unguarded, this pattern allocated on every query in production.
func Test_debugLogEnabled_GuardAllocsNothing(t *testing.T) {
	old := zlog.Default().GetLevel()
	defer zlog.SetLevel(old)
	zlog.SetLevel(zlog.LevelInfo)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	allocs := testing.AllocsPerRun(100, func() {
		if debugLogEnabled() {
			zlog.Debug("Query inserted", "query", dnsutil.FormatQuestion(q))
		}
	})
	if allocs != 0 {
		t.Errorf("%s: allocs = %v, want 0", "guarded debug call site must be free when debug is off", allocs)
	}
}
