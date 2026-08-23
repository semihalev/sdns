package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// walkMinimize plays out the step the budget exists to bound: a minimized
// query lands on an empty non-terminal, so the next one resumes from the
// labels this one exposed. It returns the label count of every name put on
// the wire, the last being the full name the cap gives up to.
func walkMinimize(r *Resolver, qname string) []int {
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)

	var sent []int
	for level, steps := 0, 0; ; steps++ {
		out, exposed, min := r.minimize(req, level, steps, false)
		sent = append(sent, dns.CountLabel(out.Question[0].Name))
		if !min {
			return sent
		}
		level = exposed
	}
}

// TestMinimizeBudgetCountsProbesNotDepth pins the unit RFC 9156 section 2.3
// asks for: the cap bounds the queries one request spends, not how deep the
// closest cached delegation happens to sit. Capping on depth charged the
// budget for labels that were never exposed, so the warmer the cache the less
// a resolution minimized — stopping exactly where the labels still hidden are
// the private ones.
func TestMinimizeBudgetCountsProbesNotDepth(t *testing.T) {
	r := &Resolver{qnameMinCount: 3, qnameMinOneLabel: 3}

	req := new(dns.Msg)
	req.SetQuestion("secret.corp.dept.example.com.", dns.TypeA)

	// A cached dept.example.com. delegation arrives as level 3 having spent no
	// probes. The next query belongs to the delegation below it.
	got, exposed, min := r.minimize(req, 3, 0, false)
	if !min {
		t.Fatal("warm delegation: minimized=false, want the request shortened")
	}
	if got.Question[0].Name != "corp.dept.example.com." {
		t.Fatalf("warm delegation: name = %q, want corp.dept.example.com.", got.Question[0].Name)
	}
	if exposed != 4 {
		t.Fatalf("warm delegation: exposed = %d, want 4", exposed)
	}

	// Spending the probes still stops it, at that same depth.
	if _, _, min := r.minimize(req, 3, 3, false); min {
		t.Fatal("spent budget: minimized=true, want the full name")
	}
}

// TestMinimizeOneLabelAtATime covers the shallow names that carry the traffic:
// below the grouping threshold every query adds exactly one label, and the cap
// is what ends the walk.
func TestMinimizeOneLabelAtATime(t *testing.T) {
	r := &Resolver{qnameMinCount: 3, qnameMinOneLabel: 3}

	cases := []struct {
		qname string
		want  []int
	}{
		{"www.example.com.", []int{1, 2, 3}},
		{"secret.corp.dept.example.com.", []int{1, 2, 3, 5}},
	}

	for _, tc := range cases {
		got := walkMinimize(r, tc.qname)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: label counts %v, want %v", tc.qname, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: query %d exposed %d labels, want %d", tc.qname, i, got[i], tc.want[i])
			}
		}
	}
}

// TestMinimizeProbesWithA pins the probe's query type. RFC 9156 section 2.1
// allows only types whose authority lies below the zone cut, which rules out
// DS, NSEC, NSEC3, ANY, AXFR, IXFR and the rest; A is the type it recommends,
// and one A probe serves clients of every type instead of one per type.
//
// This drifted once already: the probe was built with A in 2020, changed to the
// client's type in 2023 with no reason recorded, and a later refactor removed
// the line entirely because Copy() already carried the type — so nothing showed
// the change. The old test asked its question as A, which made it pass either
// way. This one does not.
func TestMinimizeProbesWithA(t *testing.T) {
	r := &Resolver{qnameMinCount: 10, qnameMinOneLabel: 4}

	for _, qtype := range []uint16{dns.TypeMX, dns.TypePTR, dns.TypeDS, dns.TypeNSEC} {
		req := new(dns.Msg)
		req.SetQuestion("www.deep.example.com.", qtype)

		got, _, min := r.minimize(req, 1, 0, false)
		if !min {
			t.Fatalf("%s: no probe produced", dns.TypeToString[qtype])
		}
		if got.Question[0].Qtype != dns.TypeA {
			t.Errorf("%s: probe type = %s, want A",
				dns.TypeToString[qtype], dns.TypeToString[got.Question[0].Qtype])
		}
		// The client's own question is untouched: its type rides the final
		// query, which is the one that is not minimized.
		if req.Question[0].Qtype != qtype {
			t.Errorf("%s: client question rewritten to %s",
				dns.TypeToString[qtype], dns.TypeToString[req.Question[0].Qtype])
		}
	}
}

// TestMinimizeTakesUnderscoreLabelsTogether covers RFC 9156 section 2.3's
// underscore rule with the example the RFC itself gives: no zone cut hides
// behind a service tag, so probing _tcp on its own and then _25 spends a query
// to hide nothing.
func TestMinimizeTakesUnderscoreLabelsTogether(t *testing.T) {
	r := &Resolver{qnameMinCount: 10, qnameMinOneLabel: 4}

	req := new(dns.Msg)
	req.SetQuestion("_25._tcp.mail.example.org.", dns.TypeA)

	// mail.example.org. is known, so the step would ordinarily expose _tcp
	// alone. Both underscore labels belong to the same query, which is the
	// full name — so there is nothing left to minimize.
	got, exposed, min := r.minimize(req, 3, 1, false)
	if min {
		t.Fatalf("minimized to %q, want the run of underscore labels to reach the query itself",
			got.Question[0].Name)
	}
	if exposed != 3 {
		t.Fatalf("exposed = %d, want the level unchanged at 3", exposed)
	}

	// A non-underscore label above them still gets its own step: the rule is
	// about service tags, not about giving up on the walk.
	req.SetQuestion("sel._domainkey.example.com.", dns.TypeA)
	got, _, min = r.minimize(req, 2, 1, false)
	if !min || got.Question[0].Name != "_domainkey.example.com." {
		t.Fatalf("minimized name = %q minimized=%v, want _domainkey.example.com.",
			got.Question[0].Name, min)
	}
}

// TestMinimizeGroupsRemainingLabels reproduces the worked example in RFC 9156
// section 2.3: 18 labels under MAX_MINIMISE_COUNT 10 and MINIMISE_ONE_LAB 4
// are added 1,1,1,1,2,2,2,2,3,3. Without the grouping the resolver spends the
// first four probes and then hands the whole name over at once.
func TestMinimizeGroupsRemainingLabels(t *testing.T) {
	r := &Resolver{qnameMinCount: 10, qnameMinOneLabel: 4}

	sent := walkMinimize(r, "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.")
	if len(sent) != 10 {
		t.Fatalf("sent %d queries (%v), want 10", len(sent), sent)
	}

	want := []int{1, 1, 1, 1, 2, 2, 2, 2, 3, 3}
	prev := 0
	for i, labels := range sent {
		if labels-prev != want[i] {
			t.Fatalf("query %d added %d labels, want %d (sequence %v)", i, labels-prev, want[i], sent)
		}
		prev = labels
	}

	if prev != 18 {
		t.Fatalf("last query carried %d labels, want the full 18", prev)
	}
}
