package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/localroot"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// localRootTestResolver wires a resolver to a verified test root copy: the
// zone chains to its own CSK, whose DS the manager treats as the anchor set.
func localRootTestResolver(t *testing.T) (*Resolver, *roottest.Zone) {
	t.Helper()
	z, err := roottest.Build(localroot.ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}
	r := newWiredTestResolver(makeTestConfig())
	mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
	if err := mgr.Load(z.RRs); err != nil {
		t.Fatalf("manager load: %v", err)
	}
	r.localRoot.Store(mgr)
	return r, z
}

func localRootState(name string, qtype uint16, cd bool) *resolveState {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.CheckingDisabled = cd
	return &resolveState{req: req, isRoot: true, depth: 10}
}

// TestLocalRootReferralBranch pins the referral shape: the walk is pointed
// at the TLD's glue with the DS set as parentDS, the delegation lands in
// the delegations cache, and no answer is synthesized.
func TestLocalRootReferralBranch(t *testing.T) {
	r, _ := localRootTestResolver(t)
	rs := localRootState("www.example.com.", dns.TypeA, false)

	answer, handled := r.consultLocalRoot(context.Background(), rs)
	if handled || answer != nil {
		t.Fatalf("referral consult returned an answer (handled=%v)", handled)
	}
	if rs.level != 1 || rs.isRoot {
		t.Fatalf("walk not advanced to the TLD: level=%d isRoot=%v", rs.level, rs.isRoot)
	}
	if rs.servers == nil || rs.servers.Zone != "com." {
		t.Fatalf("servers zone = %v, want com.", rs.servers)
	}
	rs.servers.RLock()
	endpoints := len(rs.servers.List)
	rs.servers.RUnlock()
	if endpoints == 0 {
		t.Fatal("referral installed no glue endpoints")
	}
	if len(rs.parentDS) != 1 {
		t.Fatalf("parentDS carries %d records, want com.'s DS", len(rs.parentDS))
	}
	if rs.cutDeadline.IsZero() {
		t.Fatal("referral did not bound the walk with a lease")
	}

	key := cache.Key(dns.Question{Name: "com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)
	if _, err := r.delegations.Get(key); err != nil {
		t.Fatalf("delegation not stored: %v", err)
	}

	// A second consult must reuse the stored Servers identity, so RTT
	// evidence accumulates instead of resetting per query.
	first := rs.servers
	rs2 := localRootState("mail.example.com.", dns.TypeMX, false)
	if _, handled := r.consultLocalRoot(context.Background(), rs2); handled {
		t.Fatal("second referral consult synthesized an answer")
	}
	if rs2.servers != first {
		t.Fatal("second consult built a new Servers identity")
	}
}

// TestLocalRootDenialBranch pins the NXDOMAIN synthesis: signed proof from
// the copy, AD for a validating client, and validated-denial provenance
// marked so the RFC 8020/8198 stores can fill from it.
func TestLocalRootDenialBranch(t *testing.T) {
	r, _ := localRootTestResolver(t)

	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	rs := localRootState("foo.nonexistent.", dns.TypeA, false)

	answer, handled := r.consultLocalRoot(ctx, rs)
	if !handled || answer == nil {
		t.Fatal("an absent TLD did not synthesize a denial")
	}
	if answer.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[answer.Rcode])
	}
	if !answer.AuthenticatedData {
		t.Fatal("a verified denial served without AD")
	}
	var soa, nsec, sigs int
	for _, rr := range answer.Ns {
		switch rr.(type) {
		case *dns.SOA:
			soa++
		case *dns.NSEC:
			nsec++
		case *dns.RRSIG:
			sigs++
		}
	}
	if soa != 1 || nsec == 0 || sigs == 0 {
		t.Fatalf("denial authority carries soa=%d nsec=%d rrsig=%d", soa, nsec, sigs)
	}
	negative, ok := middleware.ValidatedNegativeProofForResponse(ctx, answer)
	if !ok {
		t.Fatal("denial carries no validated provenance")
	}
	if negative.Zone != "." || negative.Kind != middleware.ValidatedNegativeProofNSEC {
		t.Fatalf("provenance = zone %q kind %d, want the root NSEC proof", negative.Zone, negative.Kind)
	}

	// CD leaves validation to the client: same proof, no AD, no provenance.
	cdCtx := middleware.WithResponseMeta(context.Background(), &middleware.ResponseMeta{})
	cdRS := localRootState("foo.nonexistent.", dns.TypeA, true)
	cdAnswer, handled := r.consultLocalRoot(cdCtx, cdRS)
	if !handled || cdAnswer.AuthenticatedData {
		t.Fatalf("CD denial: handled=%v ad=%v, want handled without AD", handled, cdAnswer.AuthenticatedData)
	}
}

// TestLocalRootDSBranch pins the parent-side DS answers: the signed DS set
// for a signed delegation, the NSEC NODATA proof for an unsigned one.
func TestLocalRootDSBranch(t *testing.T) {
	r, _ := localRootTestResolver(t)

	rs := localRootState("com.", dns.TypeDS, false)
	answer, handled := r.consultLocalRoot(context.Background(), rs)
	if !handled || answer == nil || answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("com. DS consult: handled=%v answer=%v", handled, answer)
	}
	if len(answer.Answer) != 2 { // DS + RRSIG
		t.Fatalf("com. DS answer carries %d records, want DS+RRSIG", len(answer.Answer))
	}
	if !answer.AuthenticatedData {
		t.Fatal("a verified DS answer served without AD")
	}

	rs = localRootState("org.", dns.TypeDS, false)
	answer, handled = r.consultLocalRoot(context.Background(), rs)
	if !handled || answer == nil {
		t.Fatal("org. DS consult not handled")
	}
	if len(answer.Answer) != 0 || len(answer.Ns) == 0 {
		t.Fatalf("org. DS answer = %d answers %d authority, want a NODATA proof", len(answer.Answer), len(answer.Ns))
	}
}

// TestLocalRootAnswersCarryTheClientRequest pins what a directly returned
// answer must keep: this reply skips the exchange path's normalization, so
// the transaction ID, the question and RD have to come from the live
// request or a client discards the answer as unsolicited.
func TestLocalRootAnswersCarryTheClientRequest(t *testing.T) {
	r, _ := localRootTestResolver(t)

	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"signed DS", "com.", dns.TypeDS},
		{"unsigned DS", "org.", dns.TypeDS},
		{"denial", "foo.nonexistent.", dns.TypeA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := middleware.WithResponseMeta(context.Background(), &middleware.ResponseMeta{})
			rs := localRootState(tc.qname, tc.qtype, false)
			rs.req.Id = 0x4242
			rs.req.RecursionDesired = true

			answer, handled := r.consultLocalRoot(ctx, rs)
			if !handled || answer == nil {
				t.Fatal("consult not handled")
			}
			if answer.Id != rs.req.Id {
				t.Fatalf("answer ID = %#x, want the client's %#x", answer.Id, rs.req.Id)
			}
			if !answer.Response {
				t.Fatal("answer is not marked as a response")
			}
			if !answer.RecursionDesired {
				t.Fatal("answer dropped the client's RD bit")
			}
			if len(answer.Question) != 1 || answer.Question[0] != rs.req.Question[0] {
				t.Fatalf("answer question = %v, want the client's %v", answer.Question, rs.req.Question)
			}
		})
	}
}

// TestLocalRootDenialRequiresCoverage pins the evaluator gate: a copy whose
// NSEC chain does not actually prove the name absent must fall back to the
// real roots rather than synthesize an authenticated denial. The zone here
// is sealed and verified, its chain is simply too short to cover, which is
// exactly the case a structural covering search can miss.
func TestLocalRootDenialRequiresCoverage(t *testing.T) {
	// The chain stops at com.: the apex NSEC spans (., com.) and com. has
	// no NSEC of its own, so nothing proves anything about names sorting
	// after com. A structural "greatest owner below the name" search still
	// hands back the apex NSEC, whose span does not reach, which is
	// precisely the shape the evaluator has to catch.
	lines := []string{
		". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
		". 518400 IN NS a.root-servers.test.",
		". 86400 IN NSEC com. NS SOA RRSIG NSEC DNSKEY ZONEMD",
		"com. 172800 IN NS ns.com.",
		"ns.com. 172800 IN A 198.51.100.1",
	}
	z, err := roottest.BuildZone(localroot.ComputeDigest, lines, roottest.Serial)
	if err != nil {
		t.Fatalf("build gapped zone: %v", err)
	}
	r := newWiredTestResolver(makeTestConfig())
	mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
	if err := mgr.Load(z.RRs); err != nil {
		t.Fatalf("load gapped zone: %v", err)
	}
	r.localRoot.Store(mgr)

	ctx := middleware.WithResponseMeta(context.Background(), &middleware.ResponseMeta{})
	rs := localRootState("foo.nonexistent.", dns.TypeA, false)
	answer, handled := r.consultLocalRoot(ctx, rs)
	if handled || answer != nil {
		t.Fatal("a denial was synthesized from a chain that does not cover the name")
	}
	if rs.level != 0 || !rs.isRoot {
		t.Fatal("the failed denial disturbed the walk")
	}
}

// TestLocalRootReferralLeaseBoundedByCopy pins that nothing derived from the
// copy outlives it: the delegation lease cannot exceed the snapshot's own
// horizon, however long the zone's NS TTL is.
func TestLocalRootReferralLeaseBoundedByCopy(t *testing.T) {
	r, _ := localRootTestResolver(t)
	rs := localRootState("www.example.com.", dns.TypeA, false)

	if _, handled := r.consultLocalRoot(context.Background(), rs); handled {
		t.Fatal("referral consult synthesized an answer")
	}
	snap := r.localRoot.Load().Active()
	if rs.cutDeadline.After(snap.ValidUntil()) {
		t.Fatalf("lease %v outlives the copy's horizon %v", rs.cutDeadline, snap.ValidUntil())
	}
	// The test zone's NS TTL is 172800s against a one-hour signature
	// window, so the horizon must be what bounded it.
	if rs.cutDeadline.After(time.Now().Add(2 * time.Hour)) {
		t.Fatalf("lease %v ignores the signature window", rs.cutDeadline)
	}
}

// TestLocalRootHandlerRestoresRD drives the production path. The handler
// clears RD before resolution and setTags restores it on the way out, but a
// local-root answer returns early and misses that restoration, a client
// receiving RD=0 on its own recursive query may discard it. Calling
// consultLocalRoot directly cannot see this; the handler must.
func TestLocalRootHandlerRestoresRD(t *testing.T) {
	z, err := roottest.Build(localroot.ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}

	cfg := makeTestConfig()
	cfg.IPv6Access = false
	handler := New(cfg)
	mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
	if err := mgr.Load(z.RRs); err != nil {
		t.Fatalf("manager load: %v", err)
	}
	handler.resolver.localRoot.Store(mgr)

	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
		rcode int
	}{
		{"signed DS", "com.", dns.TypeDS, dns.RcodeSuccess},
		{"unsigned DS", "org.", dns.TypeDS, dns.RcodeSuccess},
		{"denial", "foo.nonexistent.", dns.TypeA, dns.RcodeNameError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, tc.qtype)
			m.RecursionDesired = true
			m.Id = 0x1234

			resp := handler.handle(context.Background(), m)
			if resp == nil {
				t.Fatal("handler returned no response")
			}
			if resp.Rcode != tc.rcode {
				t.Fatalf("rcode = %s, want %s",
					dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
			if !resp.RecursionDesired {
				t.Fatal("the client's RD bit did not survive the handler path")
			}
			if !resp.RecursionAvailable {
				t.Fatal("RA missing on a recursive answer")
			}
			if resp.Id != m.Id {
				t.Fatalf("answer ID = %#x, want the client's %#x", resp.Id, m.Id)
			}
		})
	}
}

// TestLocalRootNonINQueryFallsBack pins the class gate. The copy is an IN
// zone and every record built from it is IN; answering a CHAOS question
// from it would pair the client's class with another class's records.
func TestLocalRootNonINQueryFallsBack(t *testing.T) {
	r, _ := localRootTestResolver(t)

	for _, qclass := range []uint16{dns.ClassCHAOS, dns.ClassHESIOD, dns.ClassANY} {
		rs := localRootState("foo.nonexistent.", dns.TypeA, false)
		rs.req.Question[0].Qclass = qclass
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if handled || answer != nil {
			t.Fatalf("class %d answered from the IN copy", qclass)
		}
		if rs.level != 0 || !rs.isRoot {
			t.Fatalf("class %d disturbed the walk", qclass)
		}
	}
}

// TestLocalRootReferralTakesTheWinningDelegationWhole pins the race
// readback. When another walk wins the delegation store, this call must
// adopt that entry's servers, DS set and lease together: taking the
// winner's servers while keeping this copy's DS chain would validate
// answers from one delegation against another's keys.
func TestLocalRootReferralTakesTheWinningDelegationWhole(t *testing.T) {
	r, _ := localRootTestResolver(t)

	// A delegation for com. published by "another walk", with servers and
	// a DS set that differ from the copy's.
	key := cache.Key(dns.Question{Name: "com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)
	rival := &authority.Servers{Zone: "com."}
	rival.List = append(rival.List, authority.NewServer("203.0.113.9:53", authority.IPv4))
	rivalDS, err := dns.NewRR("com. 86400 IN DS 999 13 2 " +
		"0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("rival DS: %v", err)
	}
	rivalDeadline := time.Now().Add(3 * time.Minute)
	r.delegations.SetUntilIfAbsent(key, []dns.RR{rivalDS}, rival, rivalDeadline)

	rs := localRootState("www.example.com.", dns.TypeA, false)
	if _, handled := r.consultLocalRoot(context.Background(), rs); handled {
		t.Fatal("referral consult synthesized an answer")
	}

	if rs.servers != rival {
		t.Fatal("the walk did not adopt the winning servers")
	}
	if len(rs.parentDS) != 1 || rs.parentDS[0].(*dns.DS).KeyTag != 999 {
		t.Fatalf("parentDS = %v, want the winning delegation's DS, a mixed "+
			"delegation validates one zone's answers against another's keys", rs.parentDS)
	}
	if !rs.cutDeadline.Equal(rivalDeadline) {
		t.Fatalf("lease = %v, want the winning entry's %v", rs.cutDeadline, rivalDeadline)
	}
}

// unprovableDSZoneLines is a sealed zone whose org. delegation carries an
// NSEC with the SOA bit, the child apex's own NSEC, which cannot testify
// about its delegation's DS. The zone verifies; only the DS proof is
// unusable, which is the shape both new tests below need.
func unprovableDSZoneLines() []string {
	return []string{
		". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
		". 518400 IN NS a.root-servers.test.",
		". 86400 IN NSEC org. NS SOA RRSIG NSEC DNSKEY ZONEMD",
		"org. 172800 IN NS ns.org.",
		"org. 86400 IN NSEC . NS SOA RRSIG NSEC",
		"ns.org. 172800 IN A 198.51.100.2",
	}
}

// TestLocalRootUnprovableDSFallsBackOnTheWire pins the fallback contract at
// the handler, where it matters: a copy that cannot prove the DS answer
// must send the query to the real roots, not turn its own gap into a
// client-visible SERVFAIL. The root here is a loopback authority that
// counts what reaches the wire, so "fell back" is observable rather than
// inferred.
func TestLocalRootUnprovableDSFallsBackOnTheWire(t *testing.T) {
	orgDS, err := dns.NewRR("org. 86400 IN DS 4321 13 2 " +
		"1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	addr, queries, stop := startTestAuthority(t, map[string][]dns.RR{
		"org.": {orgDS},
	})
	defer stop()

	z, err := roottest.BuildZone(localroot.ComputeDigest, unprovableDSZoneLines(), roottest.Serial)
	if err != nil {
		t.Fatalf("build zone: %v", err)
	}

	cfg := makeTestConfig()
	cfg.RootServers = []string{addr}
	cfg.Root6Servers = nil
	cfg.IPv6Access = false
	cfg.DNSSEC = "off"
	handler := New(cfg)
	mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
	if err := mgr.Load(z.RRs); err != nil {
		t.Fatalf("manager load: %v", err)
	}
	handler.resolver.localRoot.Store(mgr)

	m := new(dns.Msg)
	m.SetQuestion("org.", dns.TypeDS)
	m.RecursionDesired = true
	resp := handler.handle(context.Background(), m)

	if resp == nil {
		t.Fatal("handler returned no response")
	}
	if resp.Rcode == dns.RcodeServerFailure {
		t.Fatal("an unprovable DS became a SERVFAIL instead of falling back to the roots")
	}
	if queries("org.") == 0 {
		t.Fatal("the query never reached the wire, the copy answered from a proof it does not have")
	}
}

// TestLocalRootDSNODATARequiresParentSideProof pins the bitmap rule the
// resolver's own VerifyNODATANSEC enforces: DS non-existence is provable
// only on the parent side, so an NSEC carrying SOA, the child apex's own,
// cannot serve as the NODATA proof however well the zone verifies.
//
// Both entries into the copy are covered, because they reach the same
// unproven claim by different doors: the DS question asks for the proof
// outright, while an ordinary name under the delegation gets there quietly,
// installing an empty DS set that declares the child insecure.
func TestLocalRootDSNODATARequiresParentSideProof(t *testing.T) {
	z, err := roottest.BuildZone(localroot.ComputeDigest, unprovableDSZoneLines(), roottest.Serial)
	if err != nil {
		t.Fatalf("build zone: %v", err)
	}
	newResolver := func(t *testing.T) *Resolver {
		t.Helper()
		r := newWiredTestResolver(makeTestConfig())
		mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
		if err := mgr.Load(z.RRs); err != nil {
			t.Fatalf("manager load: %v", err)
		}
		r.localRoot.Store(mgr)
		return r
	}

	t.Run("the DS question", func(t *testing.T) {
		r := newResolver(t)
		rs := localRootState("org.", dns.TypeDS, false)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if handled || answer != nil {
			t.Fatalf("a child-apex NSEC was served as a DS NODATA proof (handled=%v)", handled)
		}
		if rs.level != 0 || !rs.isRoot {
			t.Fatal("the refused DS answer disturbed the walk")
		}
	})

	t.Run("an ordinary name under the delegation", func(t *testing.T) {
		r := newResolver(t)
		rs := localRootState("www.example.org.", dns.TypeA, false)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if handled || answer != nil {
			t.Fatalf("consult answered (handled=%v)", handled)
		}
		if rs.level != 0 || !rs.isRoot {
			t.Fatal("a delegation was installed with an empty DS set on a proof " +
				"the copy does not hold, the child would be treated as insecure")
		}
	})
}

// TestLocalRootInsecureDelegationNeedsTheNSBit pins the other half of the
// RFC 4035 §5.2 proof. An NSEC without the NS bit is not the parent's word
// about a delegation, so treating it as one is the downgrade
// VerifyDelegationNSEC exists to refuse: a stripped-DS bitmap would become
// evidence that a signed child is insecure. In a local copy it is also an
// internal contradiction, the owner's real NS RRset is right there, which
// is how the referral was found in the first place.
func TestLocalRootInsecureDelegationNeedsTheNSBit(t *testing.T) {
	z, err := roottest.BuildZone(localroot.ComputeDigest, []string{
		". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
		". 518400 IN NS a.root-servers.test.",
		". 86400 IN NSEC org. NS SOA RRSIG NSEC DNSKEY ZONEMD",
		"org. 172800 IN NS ns.org.",
		// The delegation's own NSEC omits NS: no DS is asserted, but
		// neither is the delegation.
		"org. 86400 IN NSEC . RRSIG NSEC",
		"ns.org. 172800 IN A 198.51.100.2",
	}, roottest.Serial)
	if err != nil {
		t.Fatalf("build zone: %v", err)
	}
	newResolver := func(t *testing.T) *Resolver {
		t.Helper()
		r := newWiredTestResolver(makeTestConfig())
		mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
		if err := mgr.Load(z.RRs); err != nil {
			t.Fatalf("manager load: %v", err)
		}
		r.localRoot.Store(mgr)
		return r
	}

	t.Run("an ordinary name under the delegation", func(t *testing.T) {
		r := newResolver(t)
		rs := localRootState("www.example.org.", dns.TypeA, false)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if handled || answer != nil {
			t.Fatalf("consult answered (handled=%v)", handled)
		}
		if rs.level != 0 || !rs.isRoot {
			t.Fatal("a delegation was installed as insecure on an NSEC that does " +
				"not claim the delegation, a stripped DS would read as unsigned")
		}
	})

	t.Run("the DS question", func(t *testing.T) {
		r := newResolver(t)
		rs := localRootState("org.", dns.TypeDS, false)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if handled || answer != nil {
			t.Fatalf("an NSEC without the NS bit was served as a DS NODATA proof (handled=%v)", handled)
		}
	})
}

// TestLocalRootLeaseBoundedBySecurityEvidence pins the bound the ordinary
// delegation path applies and this one was missing: a delegation may be
// held only as long as the evidence for its DNSSEC status lives. A DS with
// a short TTL beside a long NS TTL must not let a withdrawn key be trusted
// for the NS set's life; the same holds for the NSEC that evidences an
// unsigned delegation, and a delegation with no evidence at all is not
// installed from the copy at all.
func TestLocalRootLeaseBoundedBySecurityEvidence(t *testing.T) {
	load := func(t *testing.T, lines []string) *Resolver {
		t.Helper()
		z, err := roottest.BuildZone(localroot.ComputeDigest, lines, roottest.Serial)
		if err != nil {
			t.Fatalf("build zone: %v", err)
		}
		r := newWiredTestResolver(makeTestConfig())
		mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
		if err := mgr.Load(z.RRs); err != nil {
			t.Fatalf("manager load: %v", err)
		}
		r.localRoot.Store(mgr)
		return r
	}

	t.Run("a short DS TTL bounds a long NS TTL", func(t *testing.T) {
		r := load(t, []string{
			". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
			". 518400 IN NS a.root-servers.test.",
			". 86400 IN NSEC com. NS SOA RRSIG NSEC DNSKEY ZONEMD",
			"com. 172800 IN NS ns.com.",
			"com. 60 IN DS 12345 13 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE58AB7A66C82AABE7A9E10F53",
			"com. 86400 IN NSEC . NS DS RRSIG NSEC",
			"ns.com. 172800 IN A 198.51.100.1",
		})

		rs := localRootState("www.example.com.", dns.TypeA, false)
		if _, handled := r.consultLocalRoot(context.Background(), rs); handled {
			t.Fatal("referral consult synthesized an answer")
		}
		if got := time.Until(rs.cutDeadline); got > 61*time.Second {
			t.Fatalf("lease runs %v, want the DS RRset's 60s, a withdrawn key "+
				"must not be trusted for the NS set's longer life", got.Round(time.Second))
		}
	})

	t.Run("an unsigned delegation is bounded by its denying NSEC", func(t *testing.T) {
		r := load(t, []string{
			". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
			". 518400 IN NS a.root-servers.test.",
			". 86400 IN NSEC org. NS SOA RRSIG NSEC DNSKEY ZONEMD",
			"org. 172800 IN NS ns.org.",
			"org. 90 IN NSEC . NS RRSIG NSEC",
			"ns.org. 172800 IN A 198.51.100.2",
		})

		rs := localRootState("www.example.org.", dns.TypeA, false)
		if _, handled := r.consultLocalRoot(context.Background(), rs); handled {
			t.Fatal("referral consult synthesized an answer")
		}
		if got := time.Until(rs.cutDeadline); got > 91*time.Second {
			t.Fatalf("lease runs %v, want the denying NSEC's 90s", got.Round(time.Second))
		}
	})

	t.Run("no evidence means no local delegation", func(t *testing.T) {
		// A delegation with neither a DS nor an NSEC: the copy cannot say
		// whether it is signed, so it must not assert either.
		r := load(t, []string{
			". 86400 IN SOA a.root-servers.test. nstld.test. 2026082401 1800 900 604800 86400",
			". 518400 IN NS a.root-servers.test.",
			". 86400 IN NSEC net. NS SOA RRSIG NSEC DNSKEY ZONEMD",
			"net. 172800 IN NS ns.net.",
			"ns.net. 172800 IN A 198.51.100.3",
		})

		rs := localRootState("www.example.net.", dns.TypeA, false)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if handled || answer != nil {
			t.Fatal("a delegation with no security evidence was answered from the copy")
		}
		if rs.level != 0 || !rs.isRoot {
			t.Fatal("the refused referral disturbed the walk")
		}
	})
}

// TestLocalRootFallbacks pins every path that must leave the walk exactly
// as it was: no manager, no active copy, the apex itself.
func TestLocalRootFallbacks(t *testing.T) {
	t.Run("no manager", func(t *testing.T) {
		r := newWiredTestResolver(makeTestConfig())
		rs := localRootState("www.example.com.", dns.TypeA, false)
		if _, handled := r.consultLocalRoot(context.Background(), rs); handled || rs.level != 0 {
			t.Fatal("a nil manager touched the walk")
		}
	})
	t.Run("no active copy", func(t *testing.T) {
		r := newWiredTestResolver(makeTestConfig())
		r.localRoot.Store(localroot.New(nil, func() []dns.RR { return nil }))
		rs := localRootState("www.example.com.", dns.TypeA, false)
		if _, handled := r.consultLocalRoot(context.Background(), rs); handled || rs.level != 0 {
			t.Fatal("an empty manager touched the walk")
		}
	})
	t.Run("an apex type the copy cannot evidence", func(t *testing.T) {
		// The copy answers the apex from what it holds; a type it can
		// neither produce nor deny goes to the real roots. ANY is that
		// case by construction, it needs a composition this does not
		// attempt, so it stands in for the general shape here.
		r, _ := localRootTestResolver(t)
		rs := localRootState(".", dns.TypeANY, false)
		if _, handled := r.consultLocalRoot(context.Background(), rs); handled || rs.level != 0 {
			t.Fatal("a question the copy cannot answer was taken from it anyway")
		}
	})
}

// TestLocalRootApexAnswers pins what the copy does with questions asked at
// the root's own name. Holding a verified copy of the root zone and then
// asking a root server for the root's own NS set is the contradiction this
// closes: the records are right here, signed, and were verified before
// anything was built from them.
func TestLocalRootApexAnswers(t *testing.T) {
	r, _ := localRootTestResolver(t)

	t.Run("types the apex holds are answered from it", func(t *testing.T) {
		for _, qtype := range []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeDNSKEY} {
			name := dns.TypeToString[qtype]
			rs := localRootState(".", qtype, false)
			rs.req.Id = 0x5151
			rs.req.RecursionDesired = true

			answer, handled := r.consultLocalRoot(context.Background(), rs)
			if !handled || answer == nil {
				t.Fatalf(". %s was not answered from the copy", name)
			}
			if answer.Rcode != dns.RcodeSuccess {
				t.Fatalf(". %s rcode = %s, want NOERROR", name, dns.RcodeToString[answer.Rcode])
			}
			var records, sigs int
			for _, rr := range answer.Answer {
				if rr.Header().Rrtype == dns.TypeRRSIG {
					sigs++
					continue
				}
				if rr.Header().Rrtype != qtype {
					t.Fatalf(". %s answer carries a %s record", name, dns.TypeToString[rr.Header().Rrtype])
				}
				records++
			}
			if records == 0 || sigs == 0 {
				t.Fatalf(". %s answer = %d records %d signatures, want both", name, records, sigs)
			}
			if !answer.AuthenticatedData {
				t.Fatalf(". %s served without AD", name)
			}
			if answer.Id != rs.req.Id || !answer.RecursionDesired {
				t.Fatalf(". %s lost the client's request identity", name)
			}
			if rs.level != 0 || !rs.isRoot {
				t.Fatalf(". %s disturbed the walk", name)
			}
		}
	})

	t.Run("a type the apex lacks is denied from its own NSEC", func(t *testing.T) {
		// The test root's apex NSEC lists NS, SOA, RRSIG, NSEC, DNSKEY and
		// ZONEMD, so MX is absent and provably so.
		rs := localRootState(".", dns.TypeMX, false)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if !handled || answer == nil {
			t.Fatal(". MX was not answered from the copy")
		}
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
			t.Fatalf(". MX = %s with %d answers, want NODATA",
				dns.RcodeToString[answer.Rcode], len(answer.Answer))
		}
		var soa, nsec, sigs int
		for _, rr := range answer.Ns {
			switch rr.Header().Rrtype {
			case dns.TypeSOA:
				soa++
			case dns.TypeNSEC:
				nsec++
			case dns.TypeRRSIG:
				sigs++
			}
		}
		if soa != 1 || nsec != 1 || sigs == 0 {
			t.Fatalf(". MX authority = soa:%d nsec:%d rrsig:%d, want a signed NODATA proof", soa, nsec, sigs)
		}
		if !answer.AuthenticatedData {
			t.Fatal(". MX NODATA served without AD")
		}
	})

	t.Run("CD leaves validation to the client", func(t *testing.T) {
		rs := localRootState(".", dns.TypeNS, true)
		answer, handled := r.consultLocalRoot(context.Background(), rs)
		if !handled || answer == nil {
			t.Fatal(". NS with CD was not answered from the copy")
		}
		if answer.AuthenticatedData {
			t.Fatal("a CD query was answered with AD set")
		}
	})
}

// TestLocalRootAnswersBoundedByCopyHorizon pins RFC 4035 §5.3.3 at the copy's
// seam: an authenticated record must not be served with more TTL than the
// signature over it has life left. The copy's horizon is the earliest RRSIG
// expiration anywhere in the zone, so bounding by it satisfies the rule for
// every RRset the copy serves.
func TestLocalRootAnswersBoundedByCopyHorizon(t *testing.T) {
	r, _ := localRootTestResolver(t)
	mgr := r.localRoot.Load()
	snap := mgr.Active()
	if snap == nil {
		t.Fatal("no active copy to serve from")
	}
	horizon := uint32(time.Until(snap.ValidUntil())/time.Second) + 1 //nolint:gosec // test window is an hour.

	// The test zone signs with a one-hour window while its shortest published
	// TTL is a day, so every record served here has to be clamped for the
	// assertions below to hold, without this the test could pass on a zone
	// whose TTLs were already short enough.
	if horizon >= 86400 {
		t.Fatalf("copy horizon %ds does not bite against the zone's TTLs; the test proves nothing", horizon)
	}

	for _, tc := range []struct {
		name    string
		qname   string
		qtype   uint16
		section func(*dns.Msg) []dns.RR
	}{
		{"apex", ".", dns.TypeNS, func(m *dns.Msg) []dns.RR { return m.Answer }},
		{"apex glue", ".", dns.TypeNS, func(m *dns.Msg) []dns.RR { return m.Extra }},
		{"ds", "com.", dns.TypeDS, func(m *dns.Msg) []dns.RR { return m.Answer }},
		{"denial", "dev.", dns.TypeA, func(m *dns.Msg) []dns.RR { return m.Ns }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer, handled := r.consultLocalRoot(context.Background(), localRootState(tc.qname, tc.qtype, false))
			if !handled || answer == nil {
				t.Fatalf("%s %s was not answered from the copy", tc.qname, dns.TypeToString[tc.qtype])
			}
			records := tc.section(answer)
			if len(records) == 0 {
				t.Fatalf("%s %s answered with no records to bound", tc.qname, dns.TypeToString[tc.qtype])
			}
			for _, rr := range records {
				if rr.Header().Ttl > horizon {
					t.Fatalf("%s %s: %s TTL %d outlives the copy horizon %d",
						tc.qname, dns.TypeToString[tc.qtype],
						dns.TypeToString[rr.Header().Rrtype], rr.Header().Ttl, horizon)
				}
			}
		})
	}
}

// TestLocalRootAnswersDoNotAliasTheCopy pins that an answer carries copies of
// the zone's records rather than the records themselves. The Snapshot is
// immutable and read by every goroutine serving from the copy, while
// downstream TTL rewrites, clampTTLsToCut is one, and it writes in place,
// would otherwise reach through an answer into the live copy and change what
// every later answer says, from an arbitrary request goroutine.
func TestLocalRootAnswersDoNotAliasTheCopy(t *testing.T) {
	r, _ := localRootTestResolver(t)

	for _, tc := range []struct {
		name    string
		qname   string
		qtype   uint16
		section func(*dns.Msg) []dns.RR
	}{
		{"apex", ".", dns.TypeNS, func(m *dns.Msg) []dns.RR { return m.Answer }},
		{"apex glue", ".", dns.TypeNS, func(m *dns.Msg) []dns.RR { return m.Extra }},
		{"ds", "com.", dns.TypeDS, func(m *dns.Msg) []dns.RR { return m.Answer }},
		{"denial", "dev.", dns.TypeA, func(m *dns.Msg) []dns.RR { return m.Ns }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, handled := r.consultLocalRoot(context.Background(), localRootState(tc.qname, tc.qtype, false))
			if !handled || first == nil {
				t.Fatalf("%s %s was not answered from the copy", tc.qname, dns.TypeToString[tc.qtype])
			}
			records := tc.section(first)
			if len(records) == 0 {
				t.Fatalf("%s %s answered with no records", tc.qname, dns.TypeToString[tc.qtype])
			}
			before := records[0].Header().Ttl
			if before <= 1 {
				t.Fatalf("%s %s served TTL %d, too short to detect an overwrite",
					tc.qname, dns.TypeToString[tc.qtype], before)
			}
			// Stand in for any downstream rewrite of the served message.
			for _, rr := range records {
				rr.Header().Ttl = 1
			}

			second, handled := r.consultLocalRoot(context.Background(), localRootState(tc.qname, tc.qtype, false))
			if !handled || second == nil {
				t.Fatalf("%s %s was not answered a second time", tc.qname, dns.TypeToString[tc.qtype])
			}
			for _, rr := range tc.section(second) {
				// The horizon shrinks by the time between the two calls, so
				// the second answer may be a little shorter, but not by the
				// overwrite above.
				if rr.Header().Ttl+5 < before {
					t.Fatalf("%s %s: a rewrite of the served answer reached the shared copy, "+
						"%s came back with TTL %d, was %d",
						tc.qname, dns.TypeToString[tc.qtype],
						dns.TypeToString[rr.Header().Rrtype], rr.Header().Ttl, before)
				}
			}
		})
	}
}

// TestLocalRootApexNSCarriesPrimingGlue pins the additional section of the
// copy's answer to ". NS". A root server answers a priming query with the
// addresses of the servers it names (RFC 9609), and the resolver's own
// 12-hourly checkPriming reads addresses from Extra and nowhere else, so an
// answer without them leaves the root server list unrefreshed for the life of
// the process, and a client asking ". NS" gets names it cannot reach.
func TestLocalRootApexNSCarriesPrimingGlue(t *testing.T) {
	r, _ := localRootTestResolver(t)

	answer, handled := r.consultLocalRoot(context.Background(), localRootState(".", dns.TypeNS, false))
	if !handled || answer == nil {
		t.Fatal(". NS was not answered from the copy")
	}

	named := make(map[string]bool)
	for _, rr := range answer.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			named[dns.CanonicalName(ns.Ns)] = true
		}
	}
	if len(named) == 0 {
		t.Fatal(". NS answered without naming any server")
	}

	reachable := make(map[string]bool)
	for _, rr := range answer.Extra {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
		default:
			t.Fatalf("additional section carries a %s record", dns.TypeToString[rr.Header().Rrtype])
		}
		owner := dns.CanonicalName(rr.Header().Name)
		if !named[owner] {
			t.Fatalf("additional section carries an address for %s, which . NS does not name", owner)
		}
		reachable[owner] = true
	}
	if len(reachable) == 0 {
		t.Fatal(". NS carried no glue, root priming would find no addresses and abort")
	}
}

// TestLocalRootAnswersBindTheRequestToTheCopy pins that every answer served
// from the copy bounds the request tree at the copy's horizon. Bounding the
// wire TTLs is not enough on its own: the answer cache applies a five-second
// floor to any shorter TTL, so an answer taken at the edge of the horizon
// would otherwise be served from cache after the copy had been withdrawn.
func TestLocalRootAnswersBindTheRequestToTheCopy(t *testing.T) {
	r, _ := localRootTestResolver(t)
	horizon := r.localRoot.Load().Active().ValidUntil()

	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"apex", ".", dns.TypeNS},
		{"ds", "com.", dns.TypeDS},
		{"denial", "dev.", dns.TypeA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var meta middleware.ResponseMeta
			ctx := middleware.WithResponseMeta(context.Background(), &meta)

			answer, handled := r.consultLocalRoot(ctx, localRootState(tc.qname, tc.qtype, false))
			if !handled || answer == nil {
				t.Fatalf("%s %s was not answered from the copy", tc.qname, dns.TypeToString[tc.qtype])
			}
			cut, _ := meta.Cut()
			if cut.IsZero() {
				t.Fatalf("%s %s left the request tree unbounded", tc.qname, dns.TypeToString[tc.qtype])
			}
			if cut.After(horizon) {
				t.Fatalf("%s %s bound the tree to %v, past the copy horizon %v",
					tc.qname, dns.TypeToString[tc.qtype], cut, horizon)
			}
		})
	}

	// A consult the copy does not answer must leave the tree alone: the real
	// roots' answer has its own lifetime and the copy has no claim on it.
	t.Run("fallback binds nothing", func(t *testing.T) {
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)

		if _, handled := r.consultLocalRoot(ctx, localRootState(".", dns.TypeZONEMD, false)); handled {
			t.Fatal(". ZONEMD was answered from the copy")
		}
		if cut, _ := meta.Cut(); !cut.IsZero() {
			t.Fatalf("a fallback bound the request tree to %v", cut)
		}
	})
}
