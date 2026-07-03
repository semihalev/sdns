package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func makeNSEC3(name, next string, optOut bool, types []uint16) *dns.NSEC3 {
	salt := ""
	flags := uint8(0)
	if optOut {
		flags |= 0x01
	}
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   dns.HashName(name, dns.SHA1, 0, salt) + ".com.",
			Class:  dns.ClassINET,
			Rrtype: dns.TypeNSEC3,
			Ttl:    10,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		SaltLength: 0,
		Salt:       salt,
		HashLength: 32,
		NextDomain: dns.HashName(next, dns.SHA1, 0, salt),
		TypeBitMap: types,
	}
}

func zoneToRecords(t *testing.T, z string) []dns.RR {
	records := []dns.RR{}
	tokens := dns.NewZoneParser(strings.NewReader(z), "", "")
	for x, ok := tokens.Next(); ok; x, ok = tokens.Next() {
		err := tokens.Err()
		if err != nil {
			t.Fatalf("Failed to parse test records: %s", err)
		}
		records = append(records, x)
	}
	return records
}

func Test_VerifyNameError(t *testing.T) {
	msg := new(dns.Msg)

	// Invalid name error: closest encloser only, no next-closer or
	// wildcard coverage (RFC 5155 §8.4 requires both).
	records := []dns.RR{
		makeNSEC3("example.com.", "com.", false, nil),
	}
	err := VerifyNameError(msg.SetQuestion("a.example.com.", dns.TypeA), records)
	if err == nil {
		t.Fatalf("VerifyNameError accepted an NXDOMAIN proof with no next-closer or wildcard coverage")
	}

	// Invalid name error, no CE
	records = []dns.RR{
		makeNSEC3("org.", "", false, nil),
	}
	err = VerifyNameError(msg.SetQuestion("a.example.com.", dns.TypeA), records)
	if err == nil {
		t.Fatalf("VerifyNameError didn't fail for invalid name error response without CE")
	}

	// Invalid name error, no source of synthesis coverer
	records = []dns.RR{
		makeNSEC3("com.", "", false, nil),
	}
	err = VerifyNameError(msg.SetQuestion("a.example.com.", dns.TypeA), records)
	if err == nil {
		t.Fatalf("VerifyNameError didn't fail for invalid name error response without source of synthesis coverer")
	}

	// RFC5155 Appendix B.1 example
	records = zoneToRecords(t, `0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 0 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG
b4um86eghhds6nea196smvmlo4ors995.example. 3600 IN NSEC3 1 0 12 aabbccdd gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG
35mthgpgcu1qg68fab165klnsnk3dpvl.example. 3600 IN NSEC3 1 0 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG`)
	err = VerifyNameError(msg.SetQuestion("a.c.x.w.example.", dns.TypeA), records)
	if err != nil {
		t.Fatalf("VerifyNameError failed with RFC5155 Appendix B.1 example: %s", err)
	}
}

func Test_VerifyNODATA(t *testing.T) {
	// Valid NODATA
	records := []dns.RR{
		makeNSEC3("example.com.", "", false, nil),
	}

	msg := new(dns.Msg)

	err := VerifyNODATA(msg.SetQuestion("example.com.", dns.TypeA), records)
	if err != nil {
		t.Fatalf("VerifyNODATA failed for valid NODATA: %s", err)
	}

	// Invalid NODATA, question type bit set
	records = []dns.RR{
		makeNSEC3("example.com.", "", false, []uint16{dns.TypeA}),
	}
	err = VerifyNODATA(msg.SetQuestion("example.com.", dns.TypeA), records)
	if err == nil {
		t.Fatal("VerifyNODATA didn't fail for invalid NODATA with question type bit set")
	}

	// Invalid NODATA, CNAME bit set
	records = []dns.RR{
		makeNSEC3("example.com.", "", false, []uint16{dns.TypeCNAME}),
	}
	err = VerifyNODATA(msg.SetQuestion("example.com.", dns.TypeA), records)
	if err == nil {
		t.Fatal("VerifyNODATA didn't fail for invalid NODATA with CNAME bit set")
	}

	// Valid NODATA, no matching record but covered NC
	/*records = []dns.RR{
		makeNSEC3("example.com.", "", true, nil),
	}
	err = VerifyNODATA(&dns.Question{Name: "a.example.com.", Qtype: dns.TypeDS}, records)
	if err != nil {
		t.Fatalf("VerifyNODATA failed for valid NODATA with covered NC: %s", err)
	}*/

	// Invalid NODATA, no matching record but covered NC with non-DS question type
	records = []dns.RR{
		makeNSEC3("example.com.", "", false, nil),
	}
	err = VerifyNODATA(msg.SetQuestion("a.example.com.", dns.TypeA), records)
	if err == nil {
		t.Fatalf("VerifyNODATA didn't fail for invalid NODATA with covered NC with non-DS question type")
	}

	// Invalid NODATA, no matching record or covered NC
	/*records = []dns.RR{
		makeNSEC3("com.", "", false, nil),
	}
	err = VerifyNODATA(msg.SetQuestion("a.example.com.", dns.TypeDS), records)
	if err == nil {
		t.Fatalf("VerifyNODATA didn't fail for invalid NODATA without covered NC")
	}*/

	// Invalid NODATA, no matching record or CE
	records = []dns.RR{
		makeNSEC3("org.", "", false, nil),
	}
	err = VerifyNODATA(msg.SetQuestion("example.com.", dns.TypeDS), records)
	if err == nil {
		t.Fatalf("VerifyNODATA didn't fail for invalid NODATA without CE")
	}

	// Invalid NODATA, no matching record but covered NC without opt-out set
	records = []dns.RR{
		makeNSEC3("example.com.", "", false, nil),
	}
	err = VerifyNODATA(msg.SetQuestion("a.example.com.", dns.TypeDS), records)
	if err == nil {
		t.Fatalf("VerifyNODATA didn't fail for invalid NODATA with covered NC without opt-out set")
	}

	// RFC5155 Appendix B.2 example
	records = zoneToRecords(t, `2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 3600 IN NSEC3 1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG`)
	err = VerifyNODATA(msg.SetQuestion("ns1.example.", dns.TypeMX), records)
	if err != nil {
		t.Fatalf("VerifyNODATA failed with RFC5155 Appendix B.2 example: %s", err)
	}

	// RFC5155 Appendix B.2.1 example
	records = zoneToRecords(t, `ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. 3600 IN NSEC3 1 1 12 aabbccdd k8udemvp1j2f7eg6jebps17vp3n8i58h`)
	err = VerifyNODATA(msg.SetQuestion("y.w.example.", dns.TypeA), records)
	if err != nil {
		t.Fatalf("VerifyNODATA failed with RFC5155 Appendix B.2.1 example: %s", err)
	}

	// RFC5155 Appendix B.5: wildcard NODATA for a.z.w.example. IN MX
	// needs the closest-encloser NSEC3, the next-closer cover, and
	// the wildcard NSEC3 whose bitmap omits MX.
	records = zoneToRecords(t, `k8udemvp1j2f7eg6jebps17vp3n8i58h.example. 3600 IN NSEC3 1 1 12 aabbccdd kohar7mbb8dc2ce8a9qvl8hon4k53uhi
q04jkcevqvmu85r014c7dkba38o0ji5r.example. 3600 IN NSEC3 1 1 12 aabbccdd r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG
r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 3600 IN NSEC3 1 1 12 aabbccdd t644ebqk9bibcna874givr6joj62mlhv`)
	err = VerifyNODATA(msg.SetQuestion("a.z.w.example.", dns.TypeMX), records)
	if err != nil {
		t.Fatalf("VerifyNODATA rejected RFC5155 Appendix B.5 wildcard NODATA: %s", err)
	}
}

func Test_VerifyDelegation(t *testing.T) {
	// Valid direct delegation
	records := []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, []uint16{dns.TypeNS}),
	}
	err := VerifyDelegation("a.b.com.", records)
	if err != nil {
		t.Fatalf("VerifyDelegation failed for a direct delegation match: %s", err)
	}

	// Invalid direct delegation, NS bit not set
	records = []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, nil),
	}
	err = VerifyDelegation("a.b.com.", records)
	if err == nil {
		t.Fatal("VerifyDelegation didn't fail for a direct delegation with NS bit not set")
	}

	// Invalid direct delegation, DS bit set
	records = []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, []uint16{dns.TypeNS, dns.TypeDS}),
	}
	err = VerifyDelegation("a.b.com.", records)
	if err == nil {
		t.Fatal("VerifyDelegation didn't fail for a direct delegation with DS bit set")
	}

	// Invalid direct delegation, SOA bit set
	records = []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, []uint16{dns.TypeNS, dns.TypeSOA}),
	}
	err = VerifyDelegation("a.b.com.", records)
	if err == nil {
		t.Fatal("VerifyDelegation didn't fail for a direct delegation with SOA bit set")
	}

	// Valid Opt-Out delegation
	records = []dns.RR{
		makeNSEC3("com.", "a.com.", false, []uint16{dns.TypeNS}),  // CE
		makeNSEC3("a.com.", "e.com.", true, []uint16{dns.TypeNS}), // NC coverer, e.com is a lucky hash, thats not how ordering works
	}
	err = VerifyDelegation("b.com.", records)
	if err != nil {
		t.Fatalf("VerifyDelegation failed for a opt-out delegation match: %s", err)
	}

	// Invalid Opt-Out delegation, no NC
	records = []dns.RR{
		makeNSEC3("com.", "a.com.", false, []uint16{dns.TypeNS}),
	}
	err = VerifyDelegation("b.com.", records)
	if err == nil {
		t.Fatal("VerifyDelegation didn't fail for a direct delegation with no Next Closer")
	}

	// Invalid Opt-Out delegation, opt-out bit not set on NC
	records = []dns.RR{
		makeNSEC3("com.", "a.com.", false, []uint16{dns.TypeNS}),
		makeNSEC3("a.com.", "e.com.", false, []uint16{dns.TypeNS}),
	}
	err = VerifyDelegation("b.com.", records)
	if err == nil {
		t.Fatal("VerifyDelegation didn't fail for a direct delegation with Opt-Out bit not set on NC")
	}

	// Invalid Opt-Out delegation, empty NSEC3 set
	records = []dns.RR{}
	err = VerifyDelegation("b.com.", records)
	if err == nil {
		t.Fatal("VerifyDelegation didn't fail for a direct delegation with empty NSEC3 set")
	}

	// RFC5155 Appendix B.3 example
	records = zoneToRecords(t, `35mthgpgcu1qg68fab165klnsnk3dpvl.example. 3600 IN NSEC3 1 1 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG`)
	err = VerifyDelegation("c.example.", records)
	if err != nil {
		t.Fatalf("VerifyDelegation failed with opt out delegation example from RFC5155: %s", err)
	}
}
