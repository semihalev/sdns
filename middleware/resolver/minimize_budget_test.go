package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// TestMinimizeBudgetCountsProbesNotDepth pins the unit RFC 9156 section 2.3
// asks for: the cap bounds the queries one request spends, not how deep the
// closest cached delegation happens to sit. Capping on depth charged the
// budget for labels that were never exposed, so the warmer the cache the less
// a resolution minimized — stopping exactly where the labels still hidden are
// the private ones.
func TestMinimizeBudgetCountsProbesNotDepth(t *testing.T) {
	r := &Resolver{qnameMinLevel: 3}

	req := new(dns.Msg)
	req.SetQuestion("secret.corp.dept.example.com.", dns.TypeA)

	// A cached dept.example.com. delegation arrives as level 3 having spent no
	// probes. The next query belongs to the delegation below it.
	got, min := r.minimize(req, 3, 0, false)
	if !min {
		t.Fatal("warm delegation: minimized=false, want the request shortened")
	}
	if got.Question[0].Name != "corp.dept.example.com." {
		t.Fatalf("warm delegation: name = %q, want corp.dept.example.com.", got.Question[0].Name)
	}

	// Spending the probes still stops it, at that same depth.
	if _, min := r.minimize(req, 3, 3, false); min {
		t.Fatal("spent budget: minimized=true, want the full name")
	}
}

// TestMinimizeColdSequence walks the names a cold resolution puts on the wire,
// modelling the step the budget exists to bound: a minimized query that lands
// on an empty non-terminal and advances one label. The last entry is the full
// name, and reaching it is what the cap trades away.
func TestMinimizeColdSequence(t *testing.T) {
	cases := []struct {
		qname string
		want  []string
	}{
		{
			"www.example.com.",
			[]string{"com.", "example.com.", "www.example.com."},
		},
		{
			"secret.corp.dept.example.com.",
			[]string{"com.", "example.com.", "dept.example.com.", "secret.corp.dept.example.com."},
		},
	}

	for _, tc := range cases {
		r := &Resolver{qnameMinLevel: 3}
		req := new(dns.Msg)
		req.SetQuestion(tc.qname, dns.TypeA)

		var got []string
		for level, steps := 0, 0; ; level++ {
			out, min := r.minimize(req, level, steps, false)
			got = append(got, out.Question[0].Name)
			if !min {
				break
			}
			steps++
		}

		if len(got) != len(tc.want) {
			t.Fatalf("%s: sent %v, want %v", tc.qname, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: query %d = %q, want %q", tc.qname, i, got[i], tc.want[i])
			}
		}
	}
}
