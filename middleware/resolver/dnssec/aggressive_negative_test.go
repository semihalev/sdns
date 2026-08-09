package dnssec

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestEvaluateAggressiveNSECExactNODATAAndGuards(t *testing.T) {
	t.Parallel()

	exact := aggressiveTestNSEC(
		"example.",
		"z.example.",
		dns.TypeNS,
		dns.TypeSOA,
	)
	result, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{exact},
	)
	if err != nil {
		t.Fatalf("exact NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, exact)

	tests := []struct {
		name   string
		qtype  uint16
		bitmap []uint16
	}{
		{
			name:   "queried type exists",
			qtype:  dns.TypeA,
			bitmap: []uint16{dns.TypeA},
		},
		{
			name:   "CNAME exists",
			qtype:  dns.TypeA,
			bitmap: []uint16{dns.TypeCNAME},
		},
		{
			name:   "ANY never becomes NODATA",
			qtype:  dns.TypeANY,
			bitmap: nil,
		},
		{
			name:   "AXFR never becomes NODATA",
			qtype:  dns.TypeAXFR,
			bitmap: nil,
		},
		{
			name:   "child-side DS denial",
			qtype:  dns.TypeDS,
			bitmap: []uint16{dns.TypeSOA},
		},
		{
			name:   "non-DS query at a delegation",
			qtype:  dns.TypeA,
			bitmap: []uint16{dns.TypeNS},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := aggressiveTestNSEC("a.example.", "z.example.", tc.bitmap...)
			if _, err := EvaluateAggressiveNSEC(
				dns.Question{Name: "a.example.", Qtype: tc.qtype, Qclass: dns.ClassINET},
				"example.",
				[]dns.RR{record},
			); err == nil {
				t.Fatal("inapplicable exact NODATA proof was accepted")
			}
		})
	}

	parentDS := aggressiveTestNSEC("child.example.", "z.example.", dns.TypeNS)
	result, err = EvaluateAggressiveNSEC(
		dns.Question{Name: "child.example.", Qtype: dns.TypeDS, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{parentDS},
	)
	if err != nil {
		t.Fatalf("parent-side DS NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, parentDS)
}

func TestEvaluateAggressiveNSECENTWildcardAndNameError(t *testing.T) {
	t.Parallel()

	ent := aggressiveTestNSEC("a.example.", "x.y.example.", dns.TypeA)
	result, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "y.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{ent},
	)
	if err != nil {
		t.Fatalf("ENT NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, ent)

	qcover := aggressiveTestNSEC("a.example.", "c.example.", dns.TypeA)
	wildcardCover := aggressiveTestNSEC("example.", "a.example.", dns.TypeNS, dns.TypeSOA)
	result, err = EvaluateAggressiveNSEC(
		dns.Question{Name: "b.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{qcover, wildcardCover},
	)
	if err != nil {
		t.Fatalf("NXDOMAIN: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeNameError, qcover, wildcardCover)

	if _, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "b.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{qcover},
	); err == nil {
		t.Fatal("NXDOMAIN without wildcard denial was accepted")
	}

	wildcard := aggressiveTestNSEC("*.example.", "a.example.", dns.TypeA)
	result, err = EvaluateAggressiveNSEC(
		dns.Question{Name: "b.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{qcover, wildcard},
	)
	if err != nil {
		t.Fatalf("wildcard NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, qcover, wildcard)

	if _, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{qcover, wildcard},
	); !errors.Is(err, ErrNSECTypeExists) {
		t.Fatalf("wildcard type-exists error = %v, want %v", err, ErrNSECTypeExists)
	}

	wildcardENT := aggressiveTestNSEC("example.", "x.*.example.", dns.TypeNS, dns.TypeSOA)
	result, err = EvaluateAggressiveNSEC(
		dns.Question{Name: "b.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{qcover, wildcardENT},
	)
	if err != nil {
		t.Fatalf("wildcard ENT NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, qcover, wildcardENT)
}

func TestEvaluateAggressiveNSECRootWildcardDelegationAndCanonicalNames(t *testing.T) {
	t.Parallel()

	rootQCover := aggressiveTestNSEC("a.", "c.", dns.TypeA)
	if _, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "b.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		".",
		[]dns.RR{rootQCover},
	); err == nil {
		t.Fatal("root NXDOMAIN without proof for *. was accepted")
	}
	rootWildcardCover := aggressiveTestNSEC(".", "a.", dns.TypeNS, dns.TypeSOA)
	result, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "b.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		".",
		[]dns.RR{rootQCover, rootWildcardCover},
	)
	if err != nil {
		t.Fatalf("root wildcard proof: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeNameError, rootQCover, rootWildcardCover)

	for _, rrtype := range []uint16{dns.TypeNS, dns.TypeDNAME} {
		ancestor := aggressiveTestNSEC("deleg.example.", "z.example.", rrtype)
		if _, err := EvaluateAggressiveNSEC(
			dns.Question{Name: "x.deleg.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			"example.",
			[]dns.RR{ancestor},
		); !errors.Is(err, ErrNSECBadDelegation) {
			t.Fatalf("ancestor type %s error = %v, want delegation rejection",
				dns.Type(rrtype), err)
		}
	}

	boundary := aggressiveTestNSEC("a.example.", "c.example.", dns.TypeA)
	if _, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "c.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{boundary},
	); err == nil {
		t.Fatal("NSEC NextDomain boundary was treated as covered")
	}

	kelvinOwner := aggressiveTestNSEC("k.example.", "z.example.")
	if _, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "\u212A.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{kelvinOwner},
	); err == nil {
		t.Fatal("Unicode Kelvin sign aliased to ASCII k")
	}

	escapedASCII := aggressiveTestNSEC("K.example.", "z.example.")
	result, err = EvaluateAggressiveNSEC(
		dns.Question{Name: `\107.example.`, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{escapedASCII},
	)
	if err != nil {
		t.Fatalf("escaped ASCII canonical equality: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, escapedASCII)

	outOfZone := aggressiveTestNSEC("a.example.", "outside.")
	if _, err := EvaluateAggressiveNSEC(
		dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{outOfZone},
	); err == nil {
		t.Fatal("out-of-zone NSEC NextDomain was accepted")
	}
}

func TestEvaluateAggressiveNSEC3ExactAndNameError(t *testing.T) {
	t.Parallel()

	exact := aggressiveTestNSEC3Match(t, "host.example.", "example.", nil)
	result, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: "host.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{exact},
		nil,
	)
	if err != nil {
		t.Fatalf("NSEC3 exact NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, exact)

	for _, tc := range []struct {
		name   string
		qtype  uint16
		bitmap []uint16
	}{
		{name: "queried type", qtype: dns.TypeA, bitmap: []uint16{dns.TypeA}},
		{name: "CNAME", qtype: dns.TypeA, bitmap: []uint16{dns.TypeCNAME}},
		{name: "ANY", qtype: dns.TypeANY},
		{name: "child DS", qtype: dns.TypeDS, bitmap: []uint16{dns.TypeSOA}},
		{name: "delegation non-DS", qtype: dns.TypeA, bitmap: []uint16{dns.TypeNS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := aggressiveTestNSEC3Match(t, "host.example.", "example.", tc.bitmap)
			if _, err := EvaluateAggressiveNSEC3(
				dns.Question{Name: "host.example.", Qtype: tc.qtype, Qclass: dns.ClassINET},
				"example.",
				[]dns.RR{record},
				nil,
			); err == nil {
				t.Fatal("inapplicable NSEC3 exact NODATA proof was accepted")
			}
		})
	}

	qname := "x.a.example."
	closest, nextCover, wildcardCover := aggressiveTestNSEC3NameError(t, qname, "example.")
	result, err = EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{closest, nextCover, wildcardCover},
		nil,
	)
	if err != nil {
		t.Fatalf("NSEC3 NXDOMAIN: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeNameError, closest, nextCover, wildcardCover)

	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		[]dns.RR{closest, nextCover},
		nil,
	); err == nil {
		t.Fatal("NSEC3 NXDOMAIN without wildcard cover was accepted")
	}
}

func TestEvaluateAggressiveNSEC3WildcardOptOutAndClosestEncloserGuards(t *testing.T) {
	t.Parallel()

	const (
		qname = "x.a.example."
		zone  = "example."
	)
	closest, nextCover, _ := aggressiveTestNSEC3NameError(t, qname, zone)
	wildcard := aggressiveTestNSEC3Match(t, "*."+zone, zone, []uint16{dns.TypeA})

	result, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, wildcard},
		nil,
	)
	if err != nil {
		t.Fatalf("NSEC3 wildcard NODATA: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeSuccess, closest, nextCover, wildcard)

	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, wildcard},
		nil,
	); !errors.Is(err, ErrNSECTypeExists) {
		t.Fatalf("NSEC3 wildcard type-exists error = %v, want %v", err, ErrNSECTypeExists)
	}

	optOutNext := *nextCover
	optOutNext.Flags = 1
	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, &optOutNext, wildcard},
		nil,
	); !errors.Is(err, ErrNSECOptOut) {
		t.Fatalf("next-closer Opt-Out error = %v, want %v", err, ErrNSECOptOut)
	}

	_, nextCover, wildcardCover := aggressiveTestNSEC3NameError(t, qname, zone)
	optOutWildcard := *wildcardCover
	optOutWildcard.Flags = 1
	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, &optOutWildcard},
		nil,
	); !errors.Is(err, ErrNSECOptOut) {
		t.Fatalf("wildcard Opt-Out error = %v, want %v", err, ErrNSECOptOut)
	}

	for _, bitmap := range [][]uint16{
		{dns.TypeDNAME, dns.TypeSOA},
		{dns.TypeNS},
	} {
		badClosest := aggressiveTestNSEC3Match(t, zone, zone, bitmap)
		_, nextCover, wildcardCover := aggressiveTestNSEC3NameError(t, qname, zone)
		if _, err := EvaluateAggressiveNSEC3(
			dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
			zone,
			[]dns.RR{badClosest, nextCover, wildcardCover},
			nil,
		); !errors.Is(err, ErrNSECBadDelegation) {
			t.Fatalf("closest-encloser bitmap %v error = %v, want delegation rejection",
				bitmap, err)
		}
	}
}

func TestEvaluateAggressiveNSEC3TupleStructureRootAndWork(t *testing.T) {
	t.Parallel()

	const (
		qname = "x.a.example."
		zone  = "example."
	)
	closest, nextCover, wildcardCover := aggressiveTestNSEC3NameError(t, qname, zone)

	mixedSalt := *wildcardCover
	mixedSalt.Salt = "AA"
	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, &mixedSalt},
		nil,
	); err == nil {
		t.Fatal("mixed NSEC3 parameter tuples were accepted")
	}

	badFlags := *wildcardCover
	badFlags.Flags = 2
	if AggressiveNSEC3Usable(&badFlags) {
		t.Fatal("NSEC3 flags > 1 reported usable")
	}
	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, &badFlags},
		nil,
	); err == nil {
		t.Fatal("NSEC3 flags > 1 were accepted")
	}

	badOwner := *wildcardCover
	badOwner.Hdr.Name = "W0000000000000000000000000000000.example."
	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, &badOwner},
		nil,
	); err == nil {
		t.Fatal("invalid NSEC3 owner hash was accepted")
	}

	rootClosest, rootNext, rootWildcard := aggressiveTestNSEC3NameError(t, "x.", ".")
	result, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: "x.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		".",
		[]dns.RR{rootClosest, rootNext, rootWildcard},
		nil,
	)
	if err != nil {
		t.Fatalf("root NSEC3 wildcard proof: %v", err)
	}
	assertAggressiveResult(t, result, dns.RcodeNameError, rootClosest, rootNext, rootWildcard)

	work := &countingNSEC3Work{limit: 4}
	result, err = EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, wildcardCover},
		work,
	)
	if err != nil {
		t.Fatalf("NSEC3 proof at work boundary: %v", err)
	}
	if work.calls != 4 {
		t.Fatalf("NSEC3 hash debits = %d, want 4 unique names", work.calls)
	}
	assertAggressiveResult(t, result, dns.RcodeNameError, closest, nextCover, wildcardCover)

	limited := &countingNSEC3Work{limit: 3}
	if _, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone,
		[]dns.RR{closest, nextCover, wildcardCover},
		limited,
	); !IsWorkError(err) || !errors.Is(err, errTestWorkLimit) {
		t.Fatalf("work-limit error = %v, want wrapped %v", err, errTestWorkLimit)
	}
	if limited.calls != 3 {
		t.Fatalf("hashes completed before rejection = %d, want 3", limited.calls)
	}
}

func TestAggressiveCanonicalNSEC3HashUsesDNSASCIICaseFolding(t *testing.T) {
	t.Parallel()

	asciiLower := aggressiveTestNSEC3Hash(t, "k.example.", 0, "")
	asciiUpper := aggressiveTestNSEC3Hash(t, "K.example.", 0, "")
	escaped := aggressiveTestNSEC3Hash(t, `\107.example.`, 0, "")
	kelvin := aggressiveTestNSEC3Hash(t, "\u212A.example.", 0, "")

	if asciiLower != asciiUpper || asciiLower != escaped {
		t.Fatalf("DNS ASCII equivalents hash differently: lower=%s upper=%s escaped=%s",
			asciiLower, asciiUpper, escaped)
	}
	if kelvin == asciiLower {
		t.Fatal("Unicode Kelvin sign was folded to ASCII k in NSEC3 hashing")
	}
}

func TestEvaluateAggressiveNSEC3RFC5155Examples(t *testing.T) {
	t.Parallel()

	nameErrorRecords := zoneToRecords(t, `0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 0 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG
b4um86eghhds6nea196smvmlo4ors995.example. 3600 IN NSEC3 1 0 12 aabbccdd gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG
35mthgpgcu1qg68fab165klnsnk3dpvl.example. 3600 IN NSEC3 1 0 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG`)
	result, err := EvaluateAggressiveNSEC3(
		dns.Question{Name: "a.c.x.w.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		"example.",
		nameErrorRecords,
		nil,
	)
	if err != nil {
		t.Fatalf("RFC 5155 Appendix B.1 name error: %v", err)
	}
	if result.Rcode != dns.RcodeNameError || len(result.Proof) != 3 {
		t.Fatalf("RFC name-error result = rcode %s, proof %d; want NXDOMAIN and 3 records",
			dns.RcodeToString[result.Rcode], len(result.Proof))
	}

	wildcardNODATARecords := zoneToRecords(t, `k8udemvp1j2f7eg6jebps17vp3n8i58h.example. 3600 IN NSEC3 1 1 12 aabbccdd kohar7mbb8dc2ce8a9qvl8hon4k53uhi
q04jkcevqvmu85r014c7dkba38o0ji5r.example. 3600 IN NSEC3 1 1 12 aabbccdd r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG
r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 3600 IN NSEC3 1 1 12 aabbccdd t644ebqk9bibcna874givr6joj62mlhv`)
	result, err = EvaluateAggressiveNSEC3(
		dns.Question{Name: "a.z.w.example.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
		"example.",
		wildcardNODATARecords,
		nil,
	)
	if !errors.Is(err, ErrNSECOptOut) {
		t.Fatalf("RFC 5155 Appendix B.5 Opt-Out reuse error = %v, want %v",
			err, ErrNSECOptOut)
	}
	if result.Rcode != 0 || result.Proof != nil {
		t.Fatalf("Opt-Out rejection returned a non-zero result: %+v", result)
	}
}

func aggressiveTestNSEC(owner, next string, bitmap ...uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: next,
		TypeBitMap: bitmap,
	}
}

func aggressiveTestNSEC3Match(
	t *testing.T,
	name string,
	zone string,
	bitmap []uint16,
) *dns.NSEC3 {
	t.Helper()
	hash := aggressiveTestNSEC3Hash(t, name, 0, "")
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   aggressiveTestNSEC3Owner(hash, zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: 0,
		HashLength: 20,
		NextDomain: adjacentNSEC3Hash(t, hash, 1),
		TypeBitMap: bitmap,
	}
}

func aggressiveTestNSEC3Cover(
	t *testing.T,
	name string,
	zone string,
) *dns.NSEC3 {
	t.Helper()
	hash := aggressiveTestNSEC3Hash(t, name, 0, "")
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   aggressiveTestNSEC3Owner(adjacentNSEC3Hash(t, hash, -1), zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: 0,
		HashLength: 20,
		NextDomain: adjacentNSEC3Hash(t, hash, 1),
	}
}

func aggressiveTestNSEC3NameError(
	t *testing.T,
	qname string,
	zone string,
) (*dns.NSEC3, *dns.NSEC3, *dns.NSEC3) {
	t.Helper()
	qcanonical, err := newAggressiveCanonicalName(qname)
	if err != nil {
		t.Fatal(err)
	}
	zcanonical, err := newAggressiveCanonicalName(zone)
	if err != nil {
		t.Fatal(err)
	}
	if len(qcanonical.labels) <= len(zcanonical.labels) {
		t.Fatalf("qname %q must be below zone %q", qname, zone)
	}
	nextCloser := qcanonical.suffix(len(zcanonical.labels) + 1)
	nextCloserText := aggressiveTestNameText(nextCloser)
	wildcard := "*." + dns.Fqdn(zone)
	if dns.Fqdn(zone) == "." {
		wildcard = "*."
	}

	return aggressiveTestNSEC3Match(
			t,
			zone,
			zone,
			[]uint16{dns.TypeNS, dns.TypeSOA},
		),
		aggressiveTestNSEC3Cover(t, nextCloserText, zone),
		aggressiveTestNSEC3Cover(t, wildcard, zone)
}

func aggressiveTestNSEC3Owner(hash, zone string) string {
	if dns.Fqdn(zone) == "." {
		return hash + "."
	}
	return hash + "." + dns.Fqdn(zone)
}

func aggressiveTestNSEC3Hash(
	t *testing.T,
	name string,
	iterations uint16,
	salt string,
) string {
	t.Helper()
	canonical, err := newAggressiveCanonicalName(name)
	if err != nil {
		t.Fatal(err)
	}
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		t.Fatal(err)
	}
	hasher := aggressiveNSEC3Hasher{
		parameters: aggressiveNSEC3Parameters{
			hash:       dns.SHA1,
			iterations: iterations,
			salt:       saltBytes,
		},
		hashes: make(map[string][]byte),
	}
	hash, err := hasher.hash(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return aggressiveNSEC3Base32.EncodeToString(hash)
}

func aggressiveTestNameText(name aggressiveCanonicalName) string {
	if len(name.labels) == 0 {
		return "."
	}
	var result string
	for i, label := range name.labels {
		if i != 0 {
			result += "."
		}
		result += string(label)
	}
	return result + "."
}

func assertAggressiveResult(
	t *testing.T,
	result AggressiveNegativeResult,
	rcode int,
	proof ...dns.RR,
) {
	t.Helper()
	if result.Rcode != rcode {
		t.Fatalf("rcode = %s, want %s", dns.RcodeToString[result.Rcode], dns.RcodeToString[rcode])
	}
	if len(result.Proof) != len(proof) {
		t.Fatalf("proof length = %d, want %d", len(result.Proof), len(proof))
	}
	for i := range proof {
		if result.Proof[i] != proof[i] {
			t.Fatalf("proof[%d] = %p, want input record %p", i, result.Proof[i], proof[i])
		}
	}
}
