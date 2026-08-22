package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// TestMinimizeCopiesOnlyWhenMinimizing pins the ownership contract behind
// groupLookup's owned flag: every outcome that does not shorten the name
// hands back the caller's request itself, and the one that does returns a
// private copy with the original untouched.
func TestMinimizeCopiesOnlyWhenMinimizing(t *testing.T) {
	r := &Resolver{qnameMinCount: 5, qnameMinOneLabel: 4}

	req := new(dns.Msg)
	req.SetQuestion("www.deep.example.com.", dns.TypeA)

	// Disabled and nomin entries pass through.
	if got, _, min := (&Resolver{}).minimize(req, 0, 0, false); got != req || min {
		t.Fatalf("disabled: got %p minimized=%v, want the request itself", got, min)
	}
	if got, _, min := r.minimize(req, 0, 0, true); got != req || min {
		t.Fatalf("nomin: got %p minimized=%v, want the request itself", got, min)
	}

	// Budget spent: no copy, however shallow the delegation still is.
	if got, _, min := r.minimize(req, 0, 5, false); got != req || min {
		t.Fatalf("spent budget: got %p minimized=%v, want the request itself", got, min)
	}

	// A level that cannot shorten the name (past its label count): no copy.
	if got, _, min := r.minimize(req, 4, 0, false); got != req || min {
		t.Fatalf("unshortenable: got %p minimized=%v, want the request itself", got, min)
	}

	// The real minimization: private copy, shortened name, original intact.
	got, _, min := r.minimize(req, 1, 0, false)
	if !min || got == req {
		t.Fatalf("level 1: minimized=%v same=%v, want a private copy", min, got == req)
	}
	if got.Question[0].Name != "example.com." {
		t.Fatalf("minimized name = %q, want example.com.", got.Question[0].Name)
	}
	if got.Question[0].Qtype != dns.TypeA || req.Question[0].Name != "www.deep.example.com." {
		t.Fatalf("qtype/original disturbed: %v / %q", got.Question[0].Qtype, req.Question[0].Name)
	}
}
