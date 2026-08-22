package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// walkMinimize plays out the step the budget exists to bound: a probe finds no
// cut, so the next one resumes from the labels this one exposed. It returns the
// label count of every name asked about, and false once the walk hands over to
// the real query.
func walkMinimize(r *Resolver, qname string) []int {
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)

	var asked []int
	for level, steps := 0, 0; ; steps++ {
		child, exposed, ok := r.minimize(req, level, steps, false)
		if !ok {
			return asked
		}
		asked = append(asked, dns.CountLabel(child))
		level = exposed
	}
}

// TestMinimizeStopsAsking covers the cases where there is nothing to hide, or
// no budget left to hide it with. Each has to hand the caller the real query
// rather than another probe.
func TestMinimizeStopsAsking(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("www.deep.example.com.", dns.TypeA)

	cases := []struct {
		name         string
		resolver     *Resolver
		level, steps int
		nomin        bool
	}{
		{"minimization off", &Resolver{}, 0, 0, false},
		{"this resolution gave up", &Resolver{qnameMinCount: 5, qnameMinOneLabel: 4}, 0, 0, true},
		{"budget spent", &Resolver{qnameMinCount: 5, qnameMinOneLabel: 4}, 0, 5, false},
		{"nothing left hidden", &Resolver{qnameMinCount: 5, qnameMinOneLabel: 4}, 4, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			child, _, ok := tc.resolver.minimize(req, tc.level, tc.steps, tc.nomin)
			if ok {
				t.Fatalf("asked about %q, want the real query", child)
			}
		})
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
	// probes. The next question belongs to the delegation below it.
	child, exposed, ok := r.minimize(req, 3, 0, false)
	if !ok {
		t.Fatal("warm delegation: handed over to the real query, want a probe")
	}
	if child != "corp.dept.example.com." {
		t.Fatalf("warm delegation: probe = %q, want corp.dept.example.com.", child)
	}
	if exposed != 4 {
		t.Fatalf("warm delegation: exposed = %d, want 4", exposed)
	}

	// Spending the probes still stops it, at that same depth.
	if _, _, ok := r.minimize(req, 3, 3, false); ok {
		t.Fatal("spent budget: probed again, want the real query")
	}
}

// TestMinimizeOneLabelAtATime covers the shallow names that carry the traffic:
// below the grouping threshold every probe adds exactly one label, and the cap
// is what ends the walk.
func TestMinimizeOneLabelAtATime(t *testing.T) {
	r := &Resolver{qnameMinCount: 3, qnameMinOneLabel: 3}

	cases := []struct {
		qname string
		want  []int
	}{
		{"www.example.com.", []int{1, 2}},
		{"secret.corp.dept.example.com.", []int{1, 2, 3}},
	}

	for _, tc := range cases {
		got := walkMinimize(r, tc.qname)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: probe label counts %v, want %v", tc.qname, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: probe %d asked about %d labels, want %d", tc.qname, i, got[i], tc.want[i])
			}
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
	// alone. Both underscore labels belong to the same query.
	child, exposed, ok := r.minimize(req, 3, 1, false)
	if ok {
		t.Fatalf("probed %q, want the run of underscore labels to reach the query itself", child)
	}
	if exposed != 3 {
		t.Fatalf("exposed = %d, want the level unchanged at 3", exposed)
	}

	// A non-underscore label above them still gets its own step: the rule is
	// about service tags, not about giving up on the walk.
	req.SetQuestion("sel._domainkey.example.com.", dns.TypeA)
	child, _, ok = r.minimize(req, 2, 1, false)
	if !ok || child != "_domainkey.example.com." {
		t.Fatalf("probe = %q ok=%v, want _domainkey.example.com.", child, ok)
	}
}

// TestMinimizeGroupsRemainingLabels reproduces the worked example in RFC 9156
// section 2.3: 18 labels under MAX_MINIMISE_COUNT 10 and MINIMISE_ONE_LAB 4 are
// added 1,1,1,1,2,2,2,2,3,3. Without the grouping a resolution spends its first
// four probes and then hands the whole name over at once.
func TestMinimizeGroupsRemainingLabels(t *testing.T) {
	r := &Resolver{qnameMinCount: 10, qnameMinOneLabel: 4}

	asked := walkMinimize(r, "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.")

	// The tenth step reaches the full name, which is the query itself and not
	// a probe, so nine probes are asked.
	want := []int{1, 1, 1, 1, 2, 2, 2, 2, 3}
	if len(asked) != len(want) {
		t.Fatalf("asked %d probes (%v), want %d", len(asked), asked, len(want))
	}
	prev := 0
	for i, labels := range asked {
		if labels-prev != want[i] {
			t.Fatalf("probe %d added %d labels, want %d (sequence %v)", i, labels-prev, want[i], asked)
		}
		prev = labels
	}
	if prev != 15 {
		t.Fatalf("last probe carried %d labels, want 15 before the 18-label query", prev)
	}
}
