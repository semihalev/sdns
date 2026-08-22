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
