package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
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
	t.Run("the apex stays with the real roots", func(t *testing.T) {
		r, _ := localRootTestResolver(t)
		rs := localRootState(".", dns.TypeNS, false)
		if _, handled := r.consultLocalRoot(context.Background(), rs); handled || rs.level != 0 {
			t.Fatal("an apex query was taken from the real roots")
		}
	})
}
