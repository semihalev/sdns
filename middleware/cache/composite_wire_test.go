package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

func wireTestRequest(t *testing.T, name string, qtype uint16, do bool) (*middleware.Request, *dns.Msg) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.SetEdns0(1232, do)
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	return req, q
}

// TestNXDomainCutWireServeParity pins the wire synthesis of a descendant
// NXDOMAIN against the Msg path's for the same cut, and its cost.
func TestNXDomainCutWireServeParity(t *testing.T) {
	c := newNXDomainCutCache(64, time.Hour)

	sig := func(owner string, covered uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: covered,
			Algorithm:   dns.RSASHA256,
			Labels:      2,
			OrigTtl:     300,
			Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test fixture
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test fixture
			KeyTag:      4242,
			SignerName:  "zone.test.",
			Signature:   "Tm90QVJlYWxTaWduYXR1cmVCdXRWYWxpZEJhc2U2NA==",
		}
	}
	proof := new(dns.Msg)
	proof.SetQuestion("gone.zone.test.", dns.TypeA)
	proof.Rcode = dns.RcodeNameError
	proof.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "zone.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns.zone.test.",
			Mbox:    "hostmaster.zone.test.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		},
		sig("zone.test.", dns.TypeSOA),
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "glib.zone.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "help.zone.test.",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		},
		sig("glib.zone.test.", dns.TypeNSEC),
	}
	if !c.record(proof, "gone.zone.test.", "zone.test.", time.Time{}) {
		t.Fatal("cut refused")
	}

	req, q := wireTestRequest(t, "a.b.GONE.zone.test.", dns.TypeA, true)
	entry, ok := c.lookupWire(req.WireName(), dns.ClassINET)
	if !ok {
		t.Fatal("wire lookup missed the covering cut")
	}
	if entry.deniedName != "gone.zone.test." {
		t.Fatalf("wrong cut: %s", entry.deniedName)
	}
	// A signed proof retains three bodies: the decoded proof and two wire
	// templates. The budget must be charged for all of them.
	wantBytes := int64(entry.msg.Len()) + int64(len(entry.wireFull)) + int64(len(entry.wireStripped))
	if len(entry.wireFull) == 0 || len(entry.wireStripped) == 0 ||
		&entry.wireStripped[0] == &entry.wireFull[0] {
		t.Fatal("fixture expected distinct full and stripped templates")
	}
	if entry.wireBytes != wantBytes {
		t.Fatalf("wireBytes %d does not cover retained bodies (want %d)", entry.wireBytes, wantBytes)
	}

	dst := make([]byte, 0, 1024)
	body, built := entry.serveWireInto(dst, req, true)
	if !built {
		t.Fatal("wire synthesis refused")
	}
	wireResp := new(dns.Msg)
	if err := wireResp.Unpack(body); err != nil {
		t.Fatalf("synthesized body unpack: %v", err)
	}

	msgResp := entry.response(q)
	if msgResp == nil {
		t.Fatal("msg synthesis refused")
	}

	if wireResp.Rcode != dns.RcodeNameError || msgResp.Rcode != wireResp.Rcode {
		t.Fatalf("rcode diverges: wire %d msg %d", wireResp.Rcode, msgResp.Rcode)
	}
	if !wireResp.AuthenticatedData || !msgResp.AuthenticatedData ||
		!wireResp.RecursionAvailable || wireResp.Authoritative {
		t.Fatalf("flags diverge: wire %+v", wireResp.MsgHdr)
	}
	if len(wireResp.Question) != 1 || wireResp.Question[0].Name != "a.b.GONE.zone.test." {
		t.Fatalf("question not echoed: %v", wireResp.Question)
	}
	if len(wireResp.Answer) != 0 || len(wireResp.Extra) != 0 {
		t.Fatalf("unexpected sections: %v %v", wireResp.Answer, wireResp.Extra)
	}
	if len(wireResp.Ns) != len(msgResp.Ns) {
		t.Fatalf("authority diverges: wire %v msg %v", wireResp.Ns, msgResp.Ns)
	}
	for i := range wireResp.Ns {
		a, b := dns.Copy(wireResp.Ns[i]), dns.Copy(msgResp.Ns[i])
		a.Header().Ttl, b.Header().Ttl = 0, 0
		if a.String() != b.String() {
			t.Fatalf("authority record %d diverges:\n wire: %v\n msg:  %v", i, a, b)
		}
	}

	// The DO=0 audience gets the stripped proof, mirroring ClearDNSSEC.
	reqNoDO, qNoDO := wireTestRequest(t, "c.gone.zone.test.", dns.TypeAAAA, false)
	bodyNoDO, built := entry.serveWireInto(dst, reqNoDO, false)
	if !built {
		t.Fatal("stripped wire synthesis refused")
	}
	strippedResp := new(dns.Msg)
	if err := strippedResp.Unpack(bodyNoDO); err != nil {
		t.Fatalf("stripped body unpack: %v", err)
	}
	msgNoDO := entry.response(qNoDO)
	if len(strippedResp.Ns) != len(msgNoDO.Ns) || len(strippedResp.Ns) != 1 {
		t.Fatalf("stripped authority diverges: wire %v msg %v", strippedResp.Ns, msgNoDO.Ns)
	}
	if strippedResp.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("stripped authority kept %v", strippedResp.Ns[0])
	}

	// An explicit RRSIG query names the DNSSEC type it wants: at DO=0 it
	// keeps the signatures and loses the NSEC that came along (RFC 4035
	// §3.2.1). Neither wire template holds that shape — the stripped one
	// was cut behind a SOA question — so the wire path declines and the
	// Msg path shapes it.
	reqRRSIG, qRRSIG := wireTestRequest(t, "d.gone.zone.test.", dns.TypeRRSIG, false)
	if _, built := entry.serveWireInto(dst, reqRRSIG, false); built {
		t.Fatal("explicit-RRSIG DO=0 question served as bytes; it has no template")
	}
	msgRRSIG := entry.response(qRRSIG)
	var soa, rrsig, nsec int
	for _, rr := range msgRRSIG.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			soa++
		case dns.TypeRRSIG:
			rrsig++
		case dns.TypeNSEC:
			nsec++
		}
	}
	if soa != 1 || rrsig != 2 || nsec != 0 {
		t.Fatalf("explicit RRSIG query at DO=0: soa=%d rrsig=%d nsec=%d, want the SOA and its two signatures: %v", soa, rrsig, nsec, msgRRSIG.Ns)
	}

	if allocs := testing.AllocsPerRun(200, func() {
		entry, ok := c.lookupWire(req.WireName(), dns.ClassINET)
		if !ok {
			t.Fatal("lookup missed")
		}
		if _, built := entry.serveWireInto(dst, req, true); !built {
			t.Fatal("synthesis refused")
		}
	}); allocs != 0 {
		t.Fatalf("wire cut serve allocated %.2f objects per lookup+synthesis", allocs)
	}
}

// TestFailureCacheLookupWireParity pins the wire lookup against the Msg
// one for both failure kinds, case folding included, and its cost.
func TestFailureCacheLookupWireParity(t *testing.T) {
	c, err := NewFailureCache(FailureCacheConfig{Size: 128})
	if err != nil {
		t.Fatal(err)
	}
	qKey := FailureQuestionKey{
		Question: dns.Question{Name: "down.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	c.RecordQuestion(qKey, FailureProvenance("response"), nil)
	c.RecordZone(FailureZoneKey{Zone: "lame.test.", Qclass: dns.ClassINET}, FailureProvenance("authority"), nil)

	// Exact question, spelled differently.
	reqExact, _ := wireTestRequest(t, "DOWN.test.", dns.TypeA, false)
	msgHit, msgOK := c.Lookup(FailureQuestionKey{
		Question: dns.Question{Name: "DOWN.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	})
	wireHit, wireOK := c.LookupWire(reqExact.WireName(), dns.TypeA, dns.ClassINET, false)
	if !msgOK || !wireOK || msgHit.Kind != wireHit.Kind {
		t.Fatalf("exact parity broke: msg(%v,%v) wire(%v,%v)", msgHit.Kind, msgOK, wireHit.Kind, wireOK)
	}

	// A random name below the failed zone resolves through the zone walk.
	reqZone, _ := wireTestRequest(t, "xyz.abc.lame.test.", dns.TypeAAAA, false)
	msgZoneHit, msgZoneOK := c.Lookup(FailureQuestionKey{
		Question: dns.Question{Name: "xyz.abc.lame.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	})
	wireZoneHit, wireZoneOK := c.LookupWire(reqZone.WireName(), dns.TypeAAAA, dns.ClassINET, false)
	if !msgZoneOK || !wireZoneOK || msgZoneHit.Kind != wireZoneHit.Kind {
		t.Fatalf("zone parity broke: msg(%v,%v) wire(%v,%v)",
			msgZoneHit.Kind, msgZoneOK, wireZoneHit.Kind, wireZoneOK)
	}

	// A name with no failure state misses on both.
	reqMiss, _ := wireTestRequest(t, "fine.test.", dns.TypeA, false)
	if _, ok := c.LookupWire(reqMiss.WireName(), dns.TypeA, dns.ClassINET, false); ok {
		t.Fatal("wire lookup fabricated a hit")
	}

	if allocs := testing.AllocsPerRun(200, func() {
		if _, ok := c.LookupWire(reqZone.WireName(), dns.TypeAAAA, dns.ClassINET, false); !ok {
			t.Fatal("lookup missed")
		}
	}); allocs != 0 {
		t.Fatalf("wire failure lookup allocated %.2f objects per call", allocs)
	}
}
