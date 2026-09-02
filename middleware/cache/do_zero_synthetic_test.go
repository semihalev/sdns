package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestSynthesizedDenialKeepsOnlyTheTypeAskedFor pins the aggressive-cache
// synthesis to ClearDNSSEC's DO=0 shape: the one authenticating type the
// question named stays, every other goes (RFC 4035 §3.2.1). The manual
// filter it carried knew only the RRSIG exception, so a DO=0 question for
// NSEC lost the very records it asked for while the RRSIG question kept the
// proof it did not.
func TestSynthesizedDenialKeepsOnlyTheTypeAskedFor(t *testing.T) {
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

	for _, tc := range []struct {
		name                         string
		qtype                        uint16
		wantNSEC, wantRRSIG, wantSOA int
	}{
		{"an ordinary question gets the SOA alone", dns.TypeA, 0, 0, 1},
		{"a question for NSEC keeps the NSEC witnesses", dns.TypeNSEC, 2, 0, 1},
		{"a question for RRSIG keeps the signatures", dns.TypeRRSIG, 0, 3, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := denialProofTestRequest("m.example.", tc.qtype, false)
			response, ok := cache.Lookup(request, nil)
			if !ok || response.Rcode != dns.RcodeNameError {
				t.Fatalf("DO=0 NXDOMAIN lookup = %#v, %v", response, ok)
			}
			if got := denialProofCountType(response.Ns, dns.TypeNSEC); got != tc.wantNSEC {
				t.Errorf("%d NSEC records, want %d: %v", got, tc.wantNSEC, response.Ns)
			}
			if got := denialProofCountType(response.Ns, dns.TypeRRSIG); got != tc.wantRRSIG {
				t.Errorf("%d RRSIG records, want %d: %v", got, tc.wantRRSIG, response.Ns)
			}
			if got := denialProofCountType(response.Ns, dns.TypeSOA); got != tc.wantSOA {
				t.Errorf("%d SOA records, want %d: %v", got, tc.wantSOA, response.Ns)
			}
		})
	}
}

// TestNXDomainCutWireDeclinesExplicitDNSSECQuestionsAtDOZero pins the cut's
// wire template against the same rule. The stripped template was cut behind
// a SOA question and holds no authenticating record at all, so a DO=0
// question for RRSIG, NSEC or NSEC3, which keeps the one type it named,
// is handed to the Msg path, where ClearDNSSEC shapes it. Ordinary DO=0
// questions and every DO=1 question still serve as bytes.
func TestNXDomainCutWireDeclinesExplicitDNSSECQuestionsAtDOZero(t *testing.T) {
	cut := newNXDomainCutCache(32, time.Hour)
	sig := func(owner string, covered uint16) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: covered, Algorithm: dns.RSASHA256, Labels: 2, OrigTtl: 300, KeyTag: 4242,
			SignerName: "zone.test.", Signature: "Tm90QVJlYWxTaWduYXR1cmVCdXRWYWxpZEJhc2U2NA==",
			Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test fixture
			Inception:  uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test fixture
		}
	}
	proof := new(dns.Msg)
	proof.SetQuestion("gone.zone.test.", dns.TypeA)
	proof.Rcode = dns.RcodeNameError
	proof.Ns = []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{Name: "zone.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:  "ns.zone.test.", Mbox: "hostmaster.zone.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
		},
		sig("zone.test.", dns.TypeSOA),
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "glib.zone.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "help.zone.test.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		},
		sig("glib.zone.test.", dns.TypeNSEC),
	}
	if !cut.record(proof, "gone.zone.test.", "zone.test.", time.Time{}) {
		t.Fatal("cut refused")
	}
	probe, _ := wireTestRequest(t, "sub.gone.zone.test.", dns.TypeA, true)
	entry, ok := cut.lookupWire(probe.WireName(), dns.ClassINET)
	if !ok {
		t.Fatal("wire lookup missed the covering cut")
	}
	if entry.wireFull == nil {
		t.Fatal("fixture is wrong: the cut has no wire template")
	}

	for _, tc := range []struct {
		name  string
		qtype uint16
		do    bool
		want  bool
	}{
		{"A at DO=0 serves as bytes", dns.TypeA, false, true},
		{"A at DO=1 serves as bytes", dns.TypeA, true, true},
		{"NSEC at DO=0 goes to the Msg path", dns.TypeNSEC, false, false},
		{"NSEC3 at DO=0 goes to the Msg path", dns.TypeNSEC3, false, false},
		{"RRSIG at DO=0 goes to the Msg path", dns.TypeRRSIG, false, false},
		{"NSEC at DO=1 serves as bytes", dns.TypeNSEC, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := wireTestRequest(t, "sub.gone.zone.test.", tc.qtype, tc.do)
			_, served := entry.serveWireInto(make([]byte, 0, 4096), req, tc.do)
			if served != tc.want {
				t.Fatalf("served as bytes = %v, want %v", served, tc.want)
			}
		})
	}
}

// leaseSpy is a udp transport that counts the wire leases taken from it:
// the chain writer's BeginWire leases from the transport when it offers
// storage, so a lease here is a BeginWire the precheck let through.
type leaseSpy struct {
	*mock.Writer
	leases int
}

func (s *leaseSpy) LeaseWire(need int) []byte {
	s.leases++
	return make([]byte, 0, need)
}

// TestCutPrecheckDeclinesExplicitDNSSECBeforeLeasing pins the cut's wire
// precheck through the wrapper the live chain calls: a DO=0 question for
// RRSIG, NSEC or NSEC3 is the Msg path's by design, so it is declined
// before any lease is taken, counted as a DNSSEC-shape skip, never as a
// build failure, while an ordinary DO=0 question leases once and serves.
func TestCutPrecheckDeclinesExplicitDNSSECBeforeLeasing(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	sig := func(owner string, covered uint16) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: covered, Algorithm: dns.RSASHA256, Labels: 2, OrigTtl: 300, KeyTag: 4242,
			SignerName: "zone.test.", Signature: "Tm90QVJlYWxTaWduYXR1cmVCdXRWYWxpZEJhc2U2NA==",
			Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test fixture
			Inception:  uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test fixture
		}
	}
	proof := new(dns.Msg)
	proof.SetQuestion("gone.zone.test.", dns.TypeA)
	proof.Rcode = dns.RcodeNameError
	proof.Ns = []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{Name: "zone.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:  "ns.zone.test.", Mbox: "hostmaster.zone.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
		},
		sig("zone.test.", dns.TypeSOA),
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "glib.zone.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "help.zone.test.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		},
		sig("glib.zone.test.", dns.TypeNSEC),
	}
	if !c.store.RecordNXDomainCut(proof, "gone.zone.test.", "zone.test.", time.Time{}) {
		t.Fatal("cut refused")
	}

	serve := func(t *testing.T, qtype uint16) (served bool, leases int, dnssecSkips, buildSkips int64) {
		t.Helper()
		req, _ := wireTestRequest(t, "sub.gone.zone.test.", qtype, false)
		cut, ok := c.store.LookupNXDomainCutWire(req.WireName(), dns.ClassINET)
		if !ok {
			t.Fatal("wire lookup missed the covering cut")
		}
		spy := &leaseSpy{Writer: mock.NewWriter("udp", "198.51.100.77:40000")}
		ch := middleware.NewChain(nil)
		ch.ResetWire(spy, req)
		ch.AllowDirectPack()
		d0, b0 := wireSkipDNSSEC.Value(), wireSkipBuild.Value()
		served = c.serveCutHitFromWire(context.Background(), ch, cut)
		return served, spy.leases, wireSkipDNSSEC.Value() - d0, wireSkipBuild.Value() - b0
	}

	for _, qtype := range []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3} {
		t.Run(dns.TypeToString[qtype]+" at DO=0 is declined before the lease", func(t *testing.T) {
			served, leases, dnssecSkips, buildSkips := serve(t, qtype)
			if served {
				t.Fatal("served as bytes")
			}
			if leases != 0 {
				t.Errorf("%d wire leases taken for a question the composer refuses", leases)
			}
			if dnssecSkips != 1 || buildSkips != 0 {
				t.Errorf("skip counters: dnssec +%d build +%d, want dnssec +1 build +0", dnssecSkips, buildSkips)
			}
		})
	}
	t.Run("A at DO=0 leases once and serves", func(t *testing.T) {
		served, leases, dnssecSkips, buildSkips := serve(t, dns.TypeA)
		if !served {
			t.Fatal("not served as bytes")
		}
		if leases != 1 || dnssecSkips != 0 || buildSkips != 0 {
			t.Errorf("leases %d, skips dnssec +%d build +%d; want one lease and no skips", leases, dnssecSkips, buildSkips)
		}
	})
}
